"""Universal file analyzer: hashes, type confirmation and entropy.

Runs against every artifact, whatever it is, because these are the facts a forensic report needs
about any file regardless of format. It also performs the checks that only make sense when the
whole artifact is read: entropy shape, trailing-data detection, and confirming that the type
identified at ingestion from the first few kilobytes still holds.

Nothing here interprets. High entropy in a ZIP archive is reported as a measurement and
explicitly not as a finding, because the file type already explains it - flagging it anyway is how
a platform trains its users to ignore findings.
"""

from __future__ import annotations

from app.analysis.base import (
    AnalyzerOutput,
    ArtifactHandle,
    BaseAnalyzer,
    ExtractedEntity,
    ExtractedFinding,
)
from app.analysis.registry import register
from app.forensics import entropy as entropy_module
from app.forensics import filetype
from app.forensics.hashing import MultiHasher
from app.models.enums import EntityType, Severity

# Signatures that legitimately appear at the *end* of a file, so data after the logical end is
# expected rather than suspicious.
_TRAILING_TOLERANT = ("application/zip", "application/vnd.openxmlformats", "image/jpeg")


class FileMetadataAnalyzer(BaseAnalyzer):
    name = "file_metadata"
    version = "1"
    description = "Hashes, content type confirmation, entropy profile and structural checks"
    universal = True
    # Runs before every format-specific analyzer: it establishes the artifact's confirmed type and
    # hashes, which is the ground the narrower analyzers build on.
    priority = 0

    def analyze(self, artifact: ArtifactHandle) -> AnalyzerOutput:
        output = AnalyzerOutput()

        hasher = MultiHasher()
        scanner = entropy_module.EntropyScanner()
        tail = bytearray()

        for chunk in artifact.iter_chunks():
            hasher.update(chunk)
            scanner.update(chunk)
            # Keep a rolling tail so end-of-file structure can be checked without a second pass.
            tail.extend(chunk)
            if len(tail) > 4096:
                del tail[: len(tail) - 4096]

        hashes = hasher.result()
        profile = scanner.result()
        output.bytes_examined = hashes.size_bytes

        # Re-identify from the head now that the artifact has been read in full. The ingestion-time
        # identification used the same bytes, so a disagreement here would indicate the stored
        # object differs from what was uploaded - worth surfacing rather than assuming.
        identification = filetype.identify(artifact.head, filename=artifact.filename)

        output.metadata = {
            "hashes": {
                "sha256": hashes.sha256,
                "sha1": hashes.sha1,
                "md5": hashes.md5,
            },
            "size_bytes": hashes.size_bytes,
            "entropy": profile.as_metadata(),
            "type": identification.as_metadata(),
            "expected_high_entropy": entropy_module.is_expected_high_entropy(
                artifact.mime_type
            ),
        }

        # The artifact's own SHA-256 is recorded as an entity so that a hash appearing inside
        # another artifact - quoted in a log, listed in a manifest - correlates with the file
        # itself rather than staying an unconnected string.
        output.add_entity(
            ExtractedEntity(
                type=EntityType.file_hash,
                value=hashes.sha256,
                locator={"scope": "whole_file"},
                context="artifact_sha256",
                excerpt=None,
            )
        )
        output.add_entity(
            ExtractedEntity(
                type=EntityType.file_name,
                value=artifact.filename,
                locator={"scope": "filename"},
                context="original_filename",
            )
        )

        self._check_entropy(output, artifact, profile)
        self._check_type(output, artifact, identification)
        self._check_trailing_data(output, artifact, bytes(tail))

        return output

    def _check_entropy(
        self,
        output: AnalyzerOutput,
        artifact: ArtifactHandle,
        profile: entropy_module.EntropyProfile,
    ) -> None:
        interpretation = entropy_module.interpret(profile, artifact.mime_type)
        if interpretation is None:
            return

        localised = (
            profile.window_count >= 4
            and profile.max_window >= entropy_module.HIGH_ENTROPY_THRESHOLD
            and profile.mean_window < entropy_module.MODERATE_ENTROPY_THRESHOLD
        )
        output.add_finding(
            ExtractedFinding(
                code="file.entropy_anomaly",
                title=(
                    "Localised high-entropy region"
                    if localised
                    else "Unexpected entropy for this file type"
                ),
                description=interpretation,
                severity=Severity.low if localised else Severity.informational,
                locator=(
                    {"byte_offset": profile.peak_offsets[0]}
                    if profile.peak_offsets
                    else {"scope": "whole_file"}
                ),
                attributes={
                    "overall": round(profile.overall, 4),
                    "max_window": round(profile.max_window, 4),
                    "mean_window": round(profile.mean_window, 4),
                    "window_bytes": entropy_module.WINDOW_BYTES,
                    "high_entropy_window_ratio": round(
                        profile.high_entropy_window_ratio, 4
                    ),
                    "method": "Shannon entropy over 8 KiB windows",
                    "threshold": entropy_module.HIGH_ENTROPY_THRESHOLD,
                },
            )
        )

    def _check_type(
        self,
        output: AnalyzerOutput,
        artifact: ArtifactHandle,
        identification: filetype.TypeIdentification,
    ) -> None:
        if identification.extension_mismatch and identification.mismatch_detail:
            executable = identification.evidence_type.value == "executable"
            output.add_finding(
                ExtractedFinding(
                    code="file.mime_extension_mismatch",
                    title="File extension does not match content",
                    description=(
                        f"{identification.mismatch_detail} Detected using "
                        f"{identification.detector}"
                        + (
                            f" ({identification.magic_description})."
                            if identification.magic_description
                            else "."
                        )
                        + (
                            " Executable content presented under a document or image extension "
                            "is a standard delivery technique and should be treated as hostile "
                            "until shown otherwise."
                            if executable
                            else ""
                        )
                    ),
                    # Executable content behind a benign extension is materially more serious
                    # than a spreadsheet saved with the wrong suffix.
                    severity=Severity.high if executable else Severity.medium,
                    locator={"byte_offset": 0},
                    excerpt=artifact.head[:64].hex(),
                    attributes={
                        "declared_extension": identification.declared_extension,
                        "detected_mime": identification.detected_mime,
                        "magic_description": identification.magic_description,
                        "detector": identification.detector,
                    },
                )
            )

        if identification.detected_mime != artifact.mime_type:
            output.add_finding(
                ExtractedFinding(
                    code="file.type_changed_since_ingest",
                    title="Detected type differs from the type recorded at ingestion",
                    description=(
                        f"This artifact was recorded as {artifact.mime_type} when registered, "
                        f"but re-examining the stored content identifies it as "
                        f"{identification.detected_mime}. Investigate whether the stored object "
                        "was altered."
                    ),
                    severity=Severity.high,
                    locator={"byte_offset": 0},
                    attributes={
                        "recorded_mime": artifact.mime_type,
                        "detected_mime": identification.detected_mime,
                    },
                )
            )

    def _check_trailing_data(
        self, output: AnalyzerOutput, artifact: ArtifactHandle, tail: bytes
    ) -> None:
        """Look for content appended after a format's logical end.

        Appending a payload after the end-of-image marker is a long-standing way to smuggle data
        through filters that only inspect a file's header, and the file still renders normally.
        """
        if artifact.mime_type.startswith(_TRAILING_TOLERANT):
            return

        if artifact.mime_type == "image/png":
            # PNG ends with the IEND chunk plus its 4-byte CRC.
            marker = b"IEND"
            index = tail.rfind(marker)
            if index != -1 and len(tail) - (index + len(marker) + 4) > 0:
                extra = len(tail) - (index + len(marker) + 4)
                output.add_finding(
                    ExtractedFinding(
                        code="file.trailing_data",
                        title="Data present after the end of the image",
                        description=(
                            f"{extra} byte(s) follow the PNG IEND chunk. Image viewers ignore "
                            "trailing content, so this is a recognised way to conceal a payload "
                            "inside a file that still displays correctly."
                        ),
                        severity=Severity.medium,
                        locator={"byte_offset": artifact.size_bytes - extra},
                        excerpt=tail[-min(extra, 64) :].hex(),
                        attributes={"trailing_bytes": extra, "container": "PNG"},
                    )
                )

        if artifact.mime_type == "application/pdf":
            if b"%%EOF" not in tail:
                output.add_finding(
                    ExtractedFinding(
                        code="file.truncated_container",
                        title="PDF is missing its end-of-file marker",
                        description=(
                            "The PDF does not end with %%EOF, which indicates it is truncated or "
                            "has been modified. Content recovered from it may be incomplete."
                        ),
                        severity=Severity.low,
                        locator={"byte_offset": max(0, artifact.size_bytes - len(tail))},
                        attributes={"container": "PDF"},
                    )
                )


register(FileMetadataAnalyzer())
