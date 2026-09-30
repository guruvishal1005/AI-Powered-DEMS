"""Archive analyzer: inventory without extraction.

Archives are listed, never unpacked. That is a deliberate boundary: extracting attacker-supplied
archives inside the application process is how a zip bomb exhausts disk, how a path-traversal entry
writes outside its target directory, and how a symlink entry reads arbitrary files. Everything
useful for triage - what is inside, how large it claims to be, whether entries are encrypted, and
whether any entry is hostile by construction - is available from the central directory alone.

The compression ratio check is the one that earns its place. A zip bomb declares a modest
compressed size and an enormous uncompressed one, and because the ratio comes from metadata rather
than from decompressing anything, the check is free and cannot itself be exploited.
"""

from __future__ import annotations

import tarfile
import zipfile
from datetime import UTC, datetime
from typing import Any

from app.analysis.base import (
    AnalyzerOutput,
    ArtifactHandle,
    BaseAnalyzer,
    ExtractedEntity,
    ExtractedFinding,
    ExtractedObservation,
)
from app.analysis.registry import register
from app.models.enums import (
    Confidence,
    EntityType,
    EvidenceType,
    ObservationKind,
    Severity,
)

MAX_ARCHIVE_BYTES = 512 * 1024 * 1024
MAX_ENTRIES_LISTED = 2000
# Above this expansion factor, an archive is disproportionate to its compressed size. Text
# compresses roughly 3-5x and highly repetitive data far more, so the bar is set well clear of
# anything a normal archive produces.
SUSPICIOUS_RATIO = 200.0

_DANGEROUS_EXTENSIONS = frozenset(
    {
        "exe", "scr", "pif", "com", "bat", "cmd", "vbs", "js", "jse", "wsf", "ps1", "msi",
        "hta", "cpl", "jar", "lnk", "dll", "sys", "docm", "xlsm", "pptm", "iso", "img",
    }
)


class ArchiveAnalyzer(BaseAnalyzer):
    name = "archive_inventory"
    version = "1"
    description = "Archive contents listing, compression analysis and unsafe entry detection"
    mime_prefixes = (
        "application/zip",
        "application/x-tar",
        "application/gzip",
        "application/x-gzip",
    )
    evidence_types = (EvidenceType.archive,)
    max_size_bytes = MAX_ARCHIVE_BYTES

    def analyze(self, artifact: ArtifactHandle) -> AnalyzerOutput:
        output = AnalyzerOutput()
        output.bytes_examined = artifact.size_bytes

        with artifact.open_temp_file() as handle:
            if zipfile.is_zipfile(handle):
                handle.seek(0)
                entries, container, error = self._read_zip(handle)
            else:
                handle.seek(0)
                entries, container, error = self._read_tar(handle)

        if error is not None:
            output.skip_reason = error
            output.add_finding(
                ExtractedFinding(
                    code="archive.unreadable",
                    title="Archive could not be read",
                    description=(
                        f"The archive structure could not be parsed ({error}). This may indicate "
                        "corruption, an unsupported format such as RAR or 7z, or deliberate "
                        "malformation to frustrate automated inspection."
                    ),
                    severity=Severity.low,
                    confidence=0.7,
                    locator={"scope": "container"},
                )
            )
            return output

        declared = sum(entry["size_bytes"] for entry in entries)
        compressed = sum(entry["compressed_bytes"] for entry in entries) or artifact.size_bytes
        ratio = declared / compressed if compressed else 0.0

        output.metadata = {
            "container": container,
            "entry_count": len(entries),
            "entries": entries[:MAX_ENTRIES_LISTED],
            "declared_uncompressed_bytes": declared,
            "compressed_bytes": compressed,
            "compression_ratio": round(ratio, 2),
            "encrypted_entry_count": sum(1 for entry in entries if entry.get("encrypted")),
            "note": "Entries are listed from archive metadata; nothing was extracted.",
        }

        self._record_entries(output, entries)
        self._check_ratio(output, entries, declared, compressed, ratio)
        self._check_unsafe_paths(output, entries)
        self._check_encryption(output, entries)
        self._check_dangerous_content(output, entries)
        return output

    def _read_zip(
        self, handle: Any
    ) -> tuple[list[dict[str, Any]], str, str | None]:
        entries: list[dict[str, Any]] = []
        try:
            with zipfile.ZipFile(handle) as archive:
                for info in archive.infolist()[:MAX_ENTRIES_LISTED]:
                    when: datetime | None = None
                    try:
                        # ZIP stores local time with no zone, and a zeroed date is common in
                        # generated archives.
                        if info.date_time[0] >= 1980:
                            when = datetime(*info.date_time, tzinfo=UTC)
                    except (ValueError, TypeError):
                        when = None
                    entries.append(
                        {
                            "name": info.filename,
                            "size_bytes": info.file_size,
                            "compressed_bytes": info.compress_size,
                            "is_directory": info.is_dir(),
                            # Bit 0 of the general purpose flags marks an encrypted entry.
                            "encrypted": bool(info.flag_bits & 0x1),
                            "modified_at": when.isoformat() if when else None,
                            "crc32": f"{info.CRC:08x}",
                            "compression": info.compress_type,
                        }
                    )
        except (zipfile.BadZipFile, OSError, RuntimeError, ValueError) as exc:
            return [], "zip", f"{type(exc).__name__}: {exc}"
        return entries, "zip", None

    def _read_tar(
        self, handle: Any
    ) -> tuple[list[dict[str, Any]], str, str | None]:
        entries: list[dict[str, Any]] = []
        try:
            with tarfile.open(fileobj=handle, mode="r:*") as archive:
                for index, member in enumerate(archive):
                    if index >= MAX_ENTRIES_LISTED:
                        break
                    entries.append(
                        {
                            "name": member.name,
                            "size_bytes": member.size,
                            "compressed_bytes": member.size,
                            "is_directory": member.isdir(),
                            "encrypted": False,
                            "modified_at": datetime.fromtimestamp(
                                member.mtime, tz=UTC
                            ).isoformat()
                            if member.mtime
                            else None,
                            "mode": oct(member.mode),
                            "uid": member.uid,
                            "gid": member.gid,
                            "is_symlink": member.issym() or member.islnk(),
                            "link_target": member.linkname or None,
                        }
                    )
        except (tarfile.TarError, OSError, ValueError, EOFError) as exc:
            return [], "tar", f"{type(exc).__name__}: {exc}"
        return entries, "tar", None

    def _record_entries(self, output: AnalyzerOutput, entries: list[dict[str, Any]]) -> None:
        for entry in entries[:500]:
            if entry["is_directory"]:
                continue
            name = str(entry["name"])
            output.add_entity(
                ExtractedEntity(
                    type=EntityType.file_name,
                    value=name.rsplit("/", 1)[-1][:500],
                    locator={"archive_entry": name},
                    context="archive_member",
                    excerpt=f"{name} ({entry['size_bytes']} bytes)",
                )
            )
            if "/" in name:
                output.add_entity(
                    ExtractedEntity(
                        type=EntityType.file_path,
                        value=name[:500],
                        locator={"archive_entry": name},
                        context="archive_member_path",
                    )
                )

            if entry.get("modified_at"):
                output.add_observation(
                    ExtractedObservation(
                        kind=ObservationKind.file_modified,
                        occurred_at=datetime.fromisoformat(str(entry["modified_at"])),
                        summary=f"Archived file last modified: {name}",
                        locator={"archive_entry": name},
                        target_value=name[:500],
                        # Archive member timestamps are whatever the creating tool wrote, with no
                        # timezone recorded for ZIP at all.
                        time_confidence=Confidence.low,
                        timezone_assumed=True,
                        attributes={
                            "size_bytes": entry["size_bytes"],
                            "source": "archive member metadata",
                        },
                    )
                )

    def _check_ratio(
        self,
        output: AnalyzerOutput,
        entries: list[dict[str, Any]],
        declared: int,
        compressed: int,
        ratio: float,
    ) -> None:
        if ratio < SUSPICIOUS_RATIO or declared < 50 * 1024 * 1024:
            return
        worst = max(
            (entry for entry in entries if entry["compressed_bytes"]),
            key=lambda entry: entry["size_bytes"] / max(entry["compressed_bytes"], 1),
            default=None,
        )
        output.add_finding(
            ExtractedFinding(
                code="archive.decompression_bomb",
                title="Archive expands to a disproportionate size",
                description=(
                    f"The archive declares {declared / 1_048_576:.1f} MiB of content compressed "
                    f"into {compressed / 1_048_576:.2f} MiB, a ratio of {ratio:.0f}:1. Ratios "
                    "this high are characteristic of a decompression bomb designed to exhaust "
                    "disk or memory on any system that extracts it. Sizes are read from the "
                    "archive's own metadata; nothing was extracted to determine this."
                ),
                severity=Severity.high,
                confidence=0.85,
                locator={"archive_entry": str(worst["name"]) if worst else None},
                attributes={
                    "declared_bytes": declared,
                    "compressed_bytes": compressed,
                    "ratio": round(ratio, 1),
                    "threshold": SUSPICIOUS_RATIO,
                    "largest_entry": str(worst["name"]) if worst else None,
                    "method": "declared uncompressed size versus compressed size",
                },
            )
        )

    def _check_unsafe_paths(self, output: AnalyzerOutput, entries: list[dict[str, Any]]) -> None:
        traversal = [
            entry
            for entry in entries
            if str(entry["name"]).startswith(("/", "\\"))
            or ".." in str(entry["name"]).replace("\\", "/").split("/")
        ]
        if traversal:
            output.add_finding(
                ExtractedFinding(
                    code="archive.path_traversal",
                    title="Archive contains entries with unsafe paths",
                    description=(
                        f"{len(traversal)} entry name(s) use absolute paths or parent-directory "
                        f"references, such as {traversal[0]['name']!r}. On extraction these write "
                        "outside the intended directory, which allows an archive to overwrite "
                        "system files. No archive produced by normal tooling contains these."
                    ),
                    severity=Severity.high,
                    confidence=0.9,
                    locator={"archive_entry": str(traversal[0]["name"])},
                    attributes={
                        "unsafe_entries": [str(entry["name"]) for entry in traversal[:20]],
                        "count": len(traversal),
                    },
                )
            )

        symlinks = [entry for entry in entries if entry.get("is_symlink")]
        if symlinks:
            output.add_finding(
                ExtractedFinding(
                    code="archive.symlink_entries",
                    title="Archive contains symbolic links",
                    description=(
                        f"{len(symlinks)} entry(ies) are symbolic links, for example "
                        f"{symlinks[0]['name']!r} pointing to "
                        f"{symlinks[0].get('link_target')!r}. Extracting a symlink that targets a "
                        "path outside the extraction directory, followed by an entry that writes "
                        "through it, is a recognised way to place files anywhere on the "
                        "filesystem."
                    ),
                    severity=Severity.medium,
                    confidence=0.8,
                    locator={"archive_entry": str(symlinks[0]["name"])},
                    attributes={
                        "links": [
                            {"name": entry["name"], "target": entry.get("link_target")}
                            for entry in symlinks[:20]
                        ]
                    },
                )
            )

    def _check_encryption(self, output: AnalyzerOutput, entries: list[dict[str, Any]]) -> None:
        encrypted = [entry for entry in entries if entry.get("encrypted")]
        if not encrypted:
            return
        output.add_finding(
            ExtractedFinding(
                code="archive.encrypted_entries",
                title=f"Archive contains {len(encrypted)} password-protected entry(ies)",
                description=(
                    "Entries are encrypted, so their contents cannot be listed or examined "
                    "without the password. Password-protected archives are routinely used to "
                    "carry payloads past mail gateway scanning, with the password supplied "
                    "separately in the message body. Entry names remain visible because ZIP does "
                    "not encrypt its central directory."
                ),
                severity=Severity.medium,
                confidence=0.9,
                locator={"archive_entry": str(encrypted[0]["name"])},
                attributes={
                    "encrypted_names": [str(entry["name"]) for entry in encrypted[:20]],
                    "count": len(encrypted),
                },
            )
        )

    def _check_dangerous_content(
        self, output: AnalyzerOutput, entries: list[dict[str, Any]]
    ) -> None:
        risky = [
            entry
            for entry in entries
            if not entry["is_directory"]
            and str(entry["name"]).rsplit(".", 1)[-1].lower() in _DANGEROUS_EXTENSIONS
            and "." in str(entry["name"])
        ]
        if not risky:
            return
        output.add_finding(
            ExtractedFinding(
                code="archive.executable_content",
                title=f"Archive contains {len(risky)} executable or macro-enabled file(s)",
                description=(
                    "The archive contains files that can execute code: "
                    + ", ".join(str(entry["name"]) for entry in risky[:10])
                    + ". Wrapping an executable in an archive is a standard way to get it past "
                    "content filtering that does not inspect archive members."
                ),
                severity=Severity.high,
                confidence=0.85,
                locator={"archive_entry": str(risky[0]["name"])},
                attributes={
                    "names": [str(entry["name"]) for entry in risky[:20]],
                    "count": len(risky),
                },
            )
        )


register(ArchiveAnalyzer())
