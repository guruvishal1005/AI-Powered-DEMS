"""Document analyzer for PDF and Office formats.

Documents matter in two ways in an investigation: what they say, and what their metadata reveals
about who produced them and when. Both are recovered here - text is extracted so indicators inside
it become searchable entities, and the metadata block often preserves an author, an organisation
and a creating application that the visible content does not mention.

PDF gets extra attention because it is an active format. Embedded JavaScript, automatic actions on
open, and embedded files are all legitimate PDF features that are also the mechanism behind
document-based delivery, so their presence is reported specifically rather than folded into a
generic "suspicious document" verdict.

All parsing here is defensive. These files come from suspects and hostile senders, the parsers are
large C libraries, and a malformed document must produce a recorded failure rather than take down
the worker - so every parse is contained and reports what it could not read.
"""

from __future__ import annotations

import re
import zipfile
from datetime import UTC, datetime, timedelta, timezone
from typing import Any

from app.analysis import indicators
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

MAX_DOCUMENT_BYTES = 128 * 1024 * 1024
MAX_PAGES = 500
MAX_TEXT_CHARS = 4 * 1024 * 1024

_PDF_DATE = re.compile(
    r"D:(?P<year>\d{4})(?P<month>\d{2})?(?P<day>\d{2})?(?P<hour>\d{2})?(?P<minute>\d{2})?"
    r"(?P<second>\d{2})?(?P<tz>[Z+-])?(?P<tzh>\d{2})?'?(?P<tzm>\d{2})?"
)

_ENTITY_TYPES = (
    EntityType.email_address,
    EntityType.url,
    EntityType.ip_address,
    EntityType.domain,
    EntityType.phone_number,
    EntityType.crypto_wallet,
    EntityType.file_path,
    EntityType.cve,
    EntityType.payment_card,
)


def _parse_pdf_date(value: str | None) -> tuple[datetime | None, bool]:
    """Parse a PDF date string, reporting whether the timezone had to be assumed."""
    if not value:
        return None, False
    match = _PDF_DATE.search(str(value))
    if match is None:
        return None, False
    parts = match.groupdict()
    sign = parts.get("tz")

    # A PDF date may carry an explicit offset (D:20240115103000+05'30'), state UTC with a Z, or
    # give no zone at all. Only the last case requires an assumption, and it is reported.
    tzinfo = UTC
    assumed = sign not in ("Z", "+", "-")
    if sign in ("+", "-") and parts.get("tzh"):
        delta = timedelta(minutes=int(parts["tzh"]) * 60 + int(parts.get("tzm") or 0))
        tzinfo = timezone(delta if sign == "+" else -delta)

    try:
        parsed = datetime(
            int(parts["year"]),
            int(parts["month"] or 1),
            int(parts["day"] or 1),
            int(parts["hour"] or 0),
            int(parts["minute"] or 0),
            int(parts["second"] or 0),
            tzinfo=tzinfo,
        )
    except (TypeError, ValueError):
        return None, False

    return parsed.astimezone(UTC), assumed


class PdfAnalyzer(BaseAnalyzer):
    name = "pdf_document"
    version = "1"
    description = "PDF text, document metadata, embedded actions and attachments"
    mime_prefixes = ("application/pdf",)
    max_size_bytes = MAX_DOCUMENT_BYTES

    def analyze(self, artifact: ArtifactHandle) -> AnalyzerOutput:
        output = AnalyzerOutput()
        try:
            import pypdf
        except ImportError:  # pragma: no cover - declared dependency
            output.skip_reason = "pypdf is not installed, so PDF content cannot be read"
            return output

        with artifact.open_temp_file() as handle:
            output.bytes_examined = artifact.size_bytes
            try:
                reader = pypdf.PdfReader(handle, strict=False)
                encrypted = reader.is_encrypted
                if encrypted:
                    # Many "encrypted" PDFs use an empty owner password, which restricts editing
                    # rather than reading. Trying it is what allows those to be analysed at all.
                    try:
                        opened = bool(reader.decrypt(""))
                    except (NotImplementedError, ValueError):
                        opened = False
                    if not opened:
                        output.skip_reason = (
                            "PDF is password-protected and could not be opened with an empty "
                            "password. Supply the password out of band to analyse its contents."
                        )
                        output.metadata = {"encrypted": True, "decrypted": False}
                        output.add_finding(
                            ExtractedFinding(
                                code="document.password_protected",
                                title="PDF is password-protected",
                                description=(
                                    "The document is encrypted with a user password, so its text "
                                    "and metadata cannot be examined. Password-protected "
                                    "attachments are also used to evade content scanning at mail "
                                    "gateways, with the password supplied in the message body."
                                ),
                                severity=Severity.medium,
                                confidence=1.0,
                                locator={"scope": "document"},
                            )
                        )
                        return output

                info = self._document_info(reader)
                page_count = len(reader.pages)
                text, truncated, failed_pages = self._extract_text(reader)
                structure = self._structure(reader)
            except Exception as exc:
                output.skip_reason = (
                    f"PDF structure could not be parsed: {type(exc).__name__}: {exc}"
                )
                output.add_finding(
                    ExtractedFinding(
                        code="document.parse_failure",
                        title="PDF could not be parsed",
                        description=(
                            f"The PDF parser failed with {type(exc).__name__}. A document that "
                            "cannot be parsed is either corrupt or deliberately malformed; "
                            "malformed structure is itself sometimes used to defeat automated "
                            "inspection while still rendering in a viewer."
                        ),
                        severity=Severity.low,
                        confidence=0.7,
                        locator={"scope": "document"},
                        attributes={"error": f"{type(exc).__name__}: {exc}"[:500]},
                    )
                )
                return output

        output.truncated = truncated
        output.metadata = {
            "page_count": page_count,
            "encrypted": encrypted,
            "text_characters": len(text),
            "pages_failed_extraction": failed_pages,
            "metadata": info,
            **structure,
        }

        self._record_authors(output, info)
        self._record_dates(output, info)
        for entity in indicators.extract(text, types=_ENTITY_TYPES, source_label="pdf_text"):
            output.add_entity(entity)

        self._check_active_content(output, structure)
        self._check_no_text(output, text, page_count, structure)
        return output

    def _document_info(self, reader: Any) -> dict[str, Any]:
        try:
            info = reader.metadata or {}
        except Exception:
            return {}
        result: dict[str, Any] = {}
        for key, value in dict(info).items():
            name = str(key).lstrip("/")
            if isinstance(value, (str, int, float, bool)):
                result[name] = value
            else:
                result[name] = str(value)
        return result

    def _extract_text(self, reader: Any) -> tuple[str, bool, int]:
        chunks: list[str] = []
        total = 0
        truncated = False
        failed = 0

        for index, page in enumerate(reader.pages[:MAX_PAGES]):
            try:
                page_text = page.extract_text() or ""
            except Exception:
                failed += 1
                continue
            if total + len(page_text) > MAX_TEXT_CHARS:
                chunks.append(page_text[: MAX_TEXT_CHARS - total])
                truncated = True
                break
            chunks.append(page_text)
            total += len(page_text)
            del index

        if len(reader.pages) > MAX_PAGES:
            truncated = True
        return "\n".join(chunks), truncated, failed

    def _structure(self, reader: Any) -> dict[str, Any]:
        """Inventory the active features a PDF can carry.

        Failures are recorded in ``inspection_errors`` rather than discarded. A malformed object
        graph is common in hostile files, and reporting ``has_javascript: False`` when the walk
        actually aborted would turn a failed inspection into a clean bill of health.
        """
        result: dict[str, Any] = {
            "has_javascript": False,
            "has_open_action": False,
            "has_embedded_files": False,
            "has_acroform": False,
            "has_launch_action": False,
            "embedded_file_names": [],
            "annotation_uris": [],
            "inspection_errors": [],
            "inspection_complete": True,
        }
        try:
            root = reader.trailer["/Root"]
        except Exception as exc:
            result["inspection_errors"].append(f"catalog unreadable: {type(exc).__name__}")
            result["inspection_complete"] = False
            return result

        try:
            names = root.get("/Names", {})
            if "/JavaScript" in names:
                result["has_javascript"] = True
            if "/EmbeddedFiles" in names:
                result["has_embedded_files"] = True
                embedded = names["/EmbeddedFiles"].get_object().get("/Names", [])
                result["embedded_file_names"] = [
                    str(item) for item in embedded if isinstance(item, str)
                ][:50]
            if "/OpenAction" in root:
                result["has_open_action"] = True
                action = root["/OpenAction"]
                action_obj = action.get_object() if hasattr(action, "get_object") else action
                if isinstance(action_obj, dict):
                    subtype = str(action_obj.get("/S", ""))
                    if subtype == "/JavaScript":
                        result["has_javascript"] = True
                    if subtype == "/Launch":
                        result["has_launch_action"] = True
            if "/AcroForm" in root:
                result["has_acroform"] = True
        except Exception as exc:
            result["inspection_errors"].append(f"catalog walk failed: {type(exc).__name__}")
            result["inspection_complete"] = False

        try:
            uris: list[str] = []
            for page in reader.pages[:100]:
                for annotation in page.get("/Annots", []) or []:
                    obj = annotation.get_object()
                    action = obj.get("/A")
                    if action and "/URI" in action.get_object():
                        uris.append(str(action.get_object()["/URI"]))
            result["annotation_uris"] = uris[:100]
        except Exception as exc:
            result["inspection_errors"].append(f"annotation scan failed: {type(exc).__name__}")
            result["inspection_complete"] = False

        return result

    def _record_authors(self, output: AnalyzerOutput, info: dict[str, Any]) -> None:
        for key, context in (("Author", "document_author"), ("Creator", "creating_application")):
            value = info.get(key)
            if not value or not isinstance(value, str) or len(value) > 200:
                continue
            output.add_entity(
                ExtractedEntity(
                    type=(
                        EntityType.person
                        if key == "Author"
                        else EntityType.software
                    ),
                    value=value.strip(),
                    locator={"metadata_field": key},
                    context=context,
                    # Document metadata is user-editable, so an author name is a lead rather
                    # than an attribution.
                    confidence=0.5 if key == "Author" else 0.9,
                )
            )

        producer = info.get("Producer")
        if producer and isinstance(producer, str):
            output.add_entity(
                ExtractedEntity(
                    type=EntityType.software,
                    value=producer.strip()[:200],
                    locator={"metadata_field": "Producer"},
                    context="producing_library",
                )
            )

    def _record_dates(self, output: AnalyzerOutput, info: dict[str, Any]) -> None:
        for key, kind, label in (
            ("CreationDate", ObservationKind.document_authored, "created"),
            ("ModDate", ObservationKind.file_modified, "last modified"),
        ):
            when, assumed = _parse_pdf_date(info.get(key))
            if when is None:
                continue
            output.add_observation(
                ExtractedObservation(
                    kind=kind,
                    occurred_at=when,
                    summary=(
                        f"Document {label}"
                        + (
                            f" using {info.get('Creator')}"
                            if label == "created" and info.get("Creator")
                            else ""
                        )
                    ),
                    locator={"metadata_field": key},
                    excerpt=str(info.get(key)),
                    actor_value=info.get("Author") if label == "created" else None,
                    time_confidence=Confidence.moderate,
                    timezone_assumed=assumed,
                    attributes={
                        "source": f"PDF {key} metadata field",
                        "note": "Document metadata dates are editable and device-clock dependent.",
                    },
                )
            )

        created, _ = _parse_pdf_date(info.get("CreationDate"))
        modified, _ = _parse_pdf_date(info.get("ModDate"))
        if created and modified and (modified - created).total_seconds() < -60:
            output.add_finding(
                ExtractedFinding(
                    code="document.timestamp_inconsistency",
                    title="Document modification date precedes its creation date",
                    description=(
                        f"ModDate ({modified.isoformat()}) is earlier than CreationDate "
                        f"({created.isoformat()}). This ordering is impossible for an unaltered "
                        "document and indicates the metadata was edited or the producing system's "
                        "clock was wrong."
                    ),
                    severity=Severity.medium,
                    confidence=0.8,
                    locator={"metadata_field": "ModDate"},
                    attributes={
                        "creation_date": created.isoformat(),
                        "modification_date": modified.isoformat(),
                    },
                )
            )

    def _check_active_content(self, output: AnalyzerOutput, structure: dict[str, Any]) -> None:
        if not structure.get("inspection_complete", True):
            output.add_finding(
                ExtractedFinding(
                    code="document.inspection_incomplete",
                    title="PDF structure could only be partially inspected",
                    description=(
                        "Parts of the document's object graph could not be read ("
                        + "; ".join(structure.get("inspection_errors", []))
                        + "). The checks for embedded JavaScript, automatic actions and embedded "
                        "files are therefore inconclusive rather than negative: this document has "
                        "not been shown to be free of active content."
                    ),
                    severity=Severity.low,
                    confidence=1.0,
                    locator={"scope": "document_catalog"},
                    attributes={"errors": structure.get("inspection_errors", [])},
                )
            )

        if structure["has_javascript"]:
            output.add_finding(
                ExtractedFinding(
                    code="document.embedded_javascript",
                    title="PDF contains embedded JavaScript",
                    description=(
                        "The document carries JavaScript, which executes in the reader when the "
                        "file is opened. Although used legitimately in interactive forms, it is "
                        "also the primary mechanism for exploiting reader vulnerabilities and for "
                        "fetching a second-stage payload."
                    ),
                    severity=Severity.high,
                    confidence=0.9,
                    locator={"scope": "document_catalog"},
                    attributes={"feature": "/JavaScript"},
                )
            )

        if structure["has_launch_action"]:
            output.add_finding(
                ExtractedFinding(
                    code="document.launch_action",
                    title="PDF contains a launch action",
                    description=(
                        "The document specifies a Launch action, which asks the reader to execute "
                        "an external application or file. There is very little legitimate use for "
                        "this, and modern readers block or warn on it precisely because it is a "
                        "code-execution vector."
                    ),
                    severity=Severity.critical,
                    confidence=0.95,
                    locator={"scope": "document_catalog"},
                    attributes={"feature": "/Launch"},
                )
            )
        elif structure["has_open_action"]:
            output.add_finding(
                ExtractedFinding(
                    code="document.open_action",
                    title="PDF performs an action automatically on open",
                    description=(
                        "An OpenAction is defined, so the document triggers behaviour as soon as "
                        "it is opened without any user interaction. This is commonly a harmless "
                        "jump to a page or zoom setting, but it is also how a malicious document "
                        "runs without the recipient clicking anything."
                    ),
                    severity=Severity.medium,
                    confidence=0.7,
                    locator={"scope": "document_catalog"},
                    attributes={"feature": "/OpenAction"},
                )
            )

        if structure["has_embedded_files"]:
            output.add_finding(
                ExtractedFinding(
                    code="document.embedded_files",
                    title="PDF contains embedded files",
                    description=(
                        "The document has one or more files embedded inside it: "
                        + (
                            ", ".join(structure["embedded_file_names"][:10])
                            or "names not recoverable"
                        )
                        + ". Embedding is a way to carry a payload inside an apparently ordinary "
                        "document. Extract and register these as separate evidence to examine "
                        "them."
                    ),
                    severity=Severity.medium,
                    confidence=0.85,
                    locator={"scope": "document_catalog"},
                    attributes={"embedded_names": structure["embedded_file_names"][:20]},
                )
            )

        for uri in structure.get("annotation_uris", [])[:50]:
            output.add_entity(
                ExtractedEntity(
                    type=EntityType.url,
                    value=uri[:2000],
                    locator={"scope": "annotation"},
                    context="pdf_link_annotation",
                )
            )

    def _check_no_text(
        self,
        output: AnalyzerOutput,
        text: str,
        page_count: int,
        structure: dict[str, Any],
    ) -> None:
        if page_count == 0 or len(text.strip()) >= 20 * page_count:
            return
        output.add_finding(
            ExtractedFinding(
                code="document.no_extractable_text",
                title="PDF contains little or no extractable text",
                description=(
                    f"Only {len(text.strip())} characters were recovered across {page_count} "
                    "page(s). The document is most likely a scan or a set of images, so its "
                    "content is not searchable and no indicators can be extracted from it. "
                    "Optical character recognition would be required to read it."
                ),
                severity=Severity.informational,
                confidence=0.9,
                locator={"scope": "document"},
                attributes={"characters_extracted": len(text.strip()), "page_count": page_count},
            )
        )
        del structure


class OfficeAnalyzer(BaseAnalyzer):
    name = "office_document"
    version = "1"
    description = "Office Open XML text, core properties and macro detection"
    mime_prefixes = (
        "application/vnd.openxmlformats-officedocument",
        "application/vnd.ms-excel",
        "application/msword",
    )
    evidence_types = (EvidenceType.document, EvidenceType.spreadsheet)
    max_size_bytes = MAX_DOCUMENT_BYTES

    def applies_to(self, artifact: ArtifactHandle) -> bool:
        if artifact.mime_type == "application/pdf":
            return False
        return super().applies_to(artifact)

    def analyze(self, artifact: ArtifactHandle) -> AnalyzerOutput:
        output = AnalyzerOutput()
        output.bytes_examined = artifact.size_bytes

        with artifact.open_temp_file() as handle:
            if not zipfile.is_zipfile(handle):
                # Legacy binary .doc/.xls are OLE compound files, not ZIP containers. Rather than
                # half-parse them, this is recorded as an explicit gap in coverage.
                output.skip_reason = (
                    "File is not an Office Open XML container. Legacy binary Office formats "
                    "(.doc, .xls) are not supported by this analyzer."
                )
                return output
            handle.seek(0)
            try:
                with zipfile.ZipFile(handle) as archive:
                    names = archive.namelist()
                    properties = self._core_properties(archive)
                    text = self._document_text(archive, names)
                    macros = [name for name in names if name.lower().endswith(".bin")
                              and "vba" in name.lower()]
                    external = self._external_targets(archive, names)
            except (zipfile.BadZipFile, OSError, KeyError) as exc:
                output.skip_reason = (
                    f"Office container could not be read: {type(exc).__name__}: {exc}"
                )
                return output

        output.metadata = {
            "part_count": len(names),
            "core_properties": properties,
            "text_characters": len(text),
            "has_macros": bool(macros),
            "macro_parts": macros,
            "external_relationship_count": len(external),
            "external_targets": external[:50],
        }

        for key, entity_type, context in (
            ("creator", EntityType.person, "document_author"),
            ("lastModifiedBy", EntityType.person, "last_modified_by"),
            ("company", EntityType.organization, "document_company"),
            ("application", EntityType.software, "creating_application"),
        ):
            value = properties.get(key)
            if value and isinstance(value, str) and len(value) < 200:
                output.add_entity(
                    ExtractedEntity(
                        type=entity_type,
                        value=value.strip(),
                        locator={"metadata_field": key},
                        context=context,
                        confidence=0.5 if entity_type is EntityType.person else 0.9,
                    )
                )

        for key, kind, label in (
            ("created", ObservationKind.document_authored, "created"),
            ("modified", ObservationKind.file_modified, "last modified"),
        ):
            when = self._parse_iso(properties.get(key))
            if when is None:
                continue
            output.add_observation(
                ExtractedObservation(
                    kind=kind,
                    occurred_at=when,
                    summary=(
                        f"Document {label}"
                        + (
                            f" by {properties.get('creator')}"
                            if label == "created" and properties.get("creator")
                            else ""
                        )
                    ),
                    locator={"metadata_field": key},
                    excerpt=str(properties.get(key)),
                    actor_value=properties.get(
                        "creator" if label == "created" else "lastModifiedBy"
                    ),
                    time_confidence=Confidence.moderate,
                    attributes={
                        "source": "Office core properties",
                        "note": "Core property dates are editable by whoever last saved the file.",
                    },
                )
            )

        for entity in indicators.extract(text, types=_ENTITY_TYPES, source_label="document_text"):
            output.add_entity(entity)

        if macros:
            output.add_finding(
                ExtractedFinding(
                    code="document.contains_macros",
                    title="Office document contains VBA macros",
                    description=(
                        "The document embeds a VBA project, which can execute code when the file "
                        "is opened if the user enables content. Macro-enabled documents delivered "
                        "by email are one of the most established initial access techniques, and "
                        "the macro source should be examined before the document is opened on any "
                        "system with network access."
                    ),
                    severity=Severity.high,
                    confidence=0.95,
                    locator={"scope": "container"},
                    attributes={"macro_parts": macros},
                )
            )

        remote = [
            target
            for target in external
            if target.lower().startswith(("http://", "https://", "\\\\", "file://"))
        ]
        if remote:
            output.add_finding(
                ExtractedFinding(
                    code="document.external_references",
                    title="Document references external resources",
                    description=(
                        f"{len(remote)} external relationship target(s) are defined, such as "
                        f"{remote[0][:200]}. Documents that fetch remote content on open leak the "
                        "recipient's address and activity to the referenced host, and remote "
                        "template references in particular are used to pull a malicious template "
                        "after delivery, keeping the delivered file itself clean."
                    ),
                    severity=Severity.medium,
                    confidence=0.8,
                    locator={"scope": "relationships"},
                    attributes={"targets": remote[:20]},
                )
            )
            for target in remote[:50]:
                if target.lower().startswith(("http://", "https://")):
                    output.add_entity(
                        ExtractedEntity(
                            type=EntityType.url,
                            value=target[:2000],
                            locator={"scope": "relationships"},
                            context="external_relationship",
                        )
                    )

        return output

    def _core_properties(self, archive: zipfile.ZipFile) -> dict[str, Any]:
        import xml.etree.ElementTree as ET

        properties: dict[str, Any] = {}
        for part in ("docProps/core.xml", "docProps/app.xml"):
            try:
                raw = archive.read(part)
            except KeyError:
                continue
            try:
                # Office files come from untrusted sources; the stdlib parser here does not
                # resolve external entities, so a billion-laughs or XXE payload cannot expand.
                root = ET.fromstring(raw)  # noqa: S314
            except ET.ParseError:
                continue
            for element in root.iter():
                tag = element.tag.rsplit("}", 1)[-1]
                if element.text and element.text.strip():
                    properties.setdefault(tag, element.text.strip()[:500])
        return properties

    def _document_text(self, archive: zipfile.ZipFile, names: list[str]) -> str:
        import xml.etree.ElementTree as ET

        targets = [
            name
            for name in names
            if name.startswith(("word/document", "ppt/slides/slide", "xl/sharedStrings"))
            and name.endswith(".xml")
        ]
        chunks: list[str] = []
        total = 0
        for name in targets[:200]:
            try:
                raw = archive.read(name)
            except (KeyError, OSError):
                continue
            try:
                root = ET.fromstring(raw)  # noqa: S314
            except ET.ParseError:
                continue
            for element in root.iter():
                if element.text and element.text.strip():
                    chunks.append(element.text)
                    total += len(element.text)
                    if total > MAX_TEXT_CHARS:
                        return " ".join(chunks)
        return " ".join(chunks)

    def _external_targets(self, archive: zipfile.ZipFile, names: list[str]) -> list[str]:
        import xml.etree.ElementTree as ET

        targets: list[str] = []
        for name in names:
            if not name.endswith(".rels"):
                continue
            try:
                root = ET.fromstring(archive.read(name))  # noqa: S314
            except (KeyError, OSError, ET.ParseError):
                continue
            for element in root.iter():
                if element.get("TargetMode") == "External":
                    target = element.get("Target")
                    if target:
                        targets.append(target)
        return targets

    def _parse_iso(self, value: Any) -> datetime | None:
        if not value:
            return None
        raw = str(value).strip().replace("Z", "+00:00")
        try:
            parsed = datetime.fromisoformat(raw)
        except ValueError:
            return None
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


register(PdfAnalyzer())
register(OfficeAnalyzer())
