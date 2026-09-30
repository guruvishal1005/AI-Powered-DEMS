"""Content-based file type identification.

The client-supplied filename and ``Content-Type`` are treated as claims by an untrusted party,
recorded for the record but never believed. Type is determined from the bytes themselves via
libmagic, and any disagreement between what a file is called and what it contains becomes a
recorded observation rather than a silent correction - a ``.jpg`` that is really a PE executable
is an investigative finding, and overwriting the declared name would destroy that signal.

libmagic is a soft dependency. Where it is unavailable the module falls back to signature
matching over a table of magic numbers, so ingestion still classifies common evidence types and
still detects mismatches, with reduced coverage recorded honestly in the result.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any

from app.core.logging import get_logger
from app.models.enums import EvidenceType

logger = get_logger(__name__)

_MAGIC: Any | None
_MAGIC_DESC: Any | None

try:  # pragma: no cover - depends on the host having libmagic installed
    import magic as _libmagic

    _MAGIC = _libmagic.Magic(mime=True)
    _MAGIC_DESC = _libmagic.Magic(mime=False)
    LIBMAGIC_AVAILABLE = True
except Exception as exc:  # pragma: no cover
    _MAGIC = None
    _MAGIC_DESC = None
    LIBMAGIC_AVAILABLE = False
    logger.warning("libmagic_unavailable", error=str(exc))


SNIFF_BYTES = 8192

# Ordered signature table used when libmagic is absent. Longer, more specific signatures are
# checked first so that container formats are not mistaken for their generic envelope.
_SIGNATURES: tuple[tuple[bytes, int, str], ...] = (
    (b"\x89PNG\r\n\x1a\n", 0, "image/png"),
    (b"\xff\xd8\xff", 0, "image/jpeg"),
    (b"GIF87a", 0, "image/gif"),
    (b"GIF89a", 0, "image/gif"),
    (b"BM", 0, "image/bmp"),
    (b"%PDF-", 0, "application/pdf"),
    (b"PK\x03\x04", 0, "application/zip"),
    (b"Rar!\x1a\x07", 0, "application/vnd.rar"),
    (b"\x1f\x8b", 0, "application/gzip"),
    (b"7z\xbc\xaf\x27\x1c", 0, "application/x-7z-compressed"),
    (b"\x7fELF", 0, "application/x-elf"),
    (b"MZ", 0, "application/vnd.microsoft.portable-executable"),
    (b"SQLite format 3\x00", 0, "application/vnd.sqlite3"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", 0, "application/x-ole-storage"),
    (b"OggS", 0, "audio/ogg"),
    (b"ID3", 0, "audio/mpeg"),
    (b"ftypmp4", 4, "video/mp4"),
    (b"ftypisom", 4, "video/mp4"),
    (b"\x1aE\xdf\xa3", 0, "video/x-matroska"),
    (b"EVF\x09\x0d\x0a\xff\x00", 0, "application/x-encase-image"),
    (b"AFF", 0, "application/x-aff-image"),
)

# Extensions inside a ZIP container that identify a more specific format. libmagic already
# distinguishes these; the table exists for the fallback path.
_ZIP_REFINEMENTS: dict[str, str] = {
    ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    ".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    ".odt": "application/vnd.oasis.opendocument.text",
    ".apk": "application/vnd.android.package-archive",
    ".jar": "application/java-archive",
}

# What each extension is expected to contain. Used only to flag disagreements.
_EXTENSION_EXPECTATIONS: dict[str, tuple[str, ...]] = {
    ".jpg": ("image/jpeg",),
    ".jpeg": ("image/jpeg",),
    ".png": ("image/png",),
    ".gif": ("image/gif",),
    ".bmp": ("image/bmp",),
    ".webp": ("image/webp",),
    ".tif": ("image/tiff",),
    ".tiff": ("image/tiff",),
    ".pdf": ("application/pdf",),
    ".zip": ("application/zip",),
    ".gz": ("application/gzip",),
    ".tgz": ("application/gzip",),
    ".rar": ("application/vnd.rar", "application/x-rar-compressed"),
    ".7z": ("application/x-7z-compressed",),
    ".tar": ("application/x-tar",),
    ".txt": ("text/plain",),
    ".log": ("text/plain",),
    ".csv": ("text/csv", "text/plain", "application/csv"),
    ".json": ("application/json", "text/plain"),
    ".xml": ("text/xml", "application/xml", "text/plain"),
    ".html": ("text/html", "text/plain"),
    ".eml": ("message/rfc822", "text/plain"),
    ".msg": ("application/vnd.ms-outlook", "application/x-ole-storage"),
    ".docx": (
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "application/zip",
    ),
    ".xlsx": (
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "application/zip",
    ),
    ".doc": ("application/msword", "application/x-ole-storage"),
    ".exe": ("application/vnd.microsoft.portable-executable", "application/x-dosexec"),
    ".dll": ("application/vnd.microsoft.portable-executable", "application/x-dosexec"),
    ".sqlite": ("application/vnd.sqlite3",),
    ".db": ("application/vnd.sqlite3", "application/octet-stream"),
    ".pcap": ("application/vnd.tcpdump.pcap",),
    ".pcapng": ("application/vnd.tcpdump.pcap", "application/octet-stream"),
    ".e01": ("application/x-encase-image",),
    ".mp4": ("video/mp4",),
    ".mp3": ("audio/mpeg",),
    ".wav": ("audio/x-wav", "audio/wav"),
}

# Which MIME families map to which evidence type. Prefix match, most specific first, so
# container formats are resolved before the generic envelope they are built on.
_TYPE_RULES: tuple[tuple[str, EvidenceType], ...] = (
    ("message/rfc822", EvidenceType.email_message),
    ("application/vnd.ms-outlook", EvidenceType.email_message),
    ("image/", EvidenceType.image),
    ("video/", EvidenceType.video),
    ("audio/", EvidenceType.audio),
    ("application/pdf", EvidenceType.document),
    ("application/vnd.openxmlformats-officedocument.spreadsheetml", EvidenceType.spreadsheet),
    ("application/vnd.ms-excel", EvidenceType.spreadsheet),
    ("application/vnd.oasis.opendocument.spreadsheet", EvidenceType.spreadsheet),
    ("text/csv", EvidenceType.spreadsheet),
    ("application/csv", EvidenceType.spreadsheet),
    ("application/vnd.openxmlformats", EvidenceType.document),
    ("application/msword", EvidenceType.document),
    ("application/vnd.oasis.opendocument", EvidenceType.document),
    ("application/rtf", EvidenceType.document),
    ("application/vnd.tcpdump", EvidenceType.network_capture),
    ("application/vnd.sqlite3", EvidenceType.database_export),
    ("application/x-encase-image", EvidenceType.disk_image),
    ("application/x-aff-image", EvidenceType.disk_image),
    ("application/vnd.microsoft.portable-executable", EvidenceType.executable),
    ("application/x-dosexec", EvidenceType.executable),
    ("application/x-elf", EvidenceType.executable),
    ("application/x-mach-binary", EvidenceType.executable),
    ("application/vnd.android.package-archive", EvidenceType.archive),
    ("application/java-archive", EvidenceType.archive),
    ("application/zip", EvidenceType.archive),
    ("application/gzip", EvidenceType.archive),
    ("application/x-tar", EvidenceType.archive),
    ("application/vnd.rar", EvidenceType.archive),
    ("application/x-rar", EvidenceType.archive),
    ("application/x-7z", EvidenceType.archive),
    ("application/x-bzip", EvidenceType.archive),
    ("application/x-xz", EvidenceType.archive),
)

# Extensions that identify an evidence type the MIME type cannot: a memory dump and a raw disk
# image are both undifferentiated binary, and a log is indistinguishable from any other text.
_EXTENSION_TYPES: dict[str, EvidenceType] = {
    ".log": EvidenceType.system_log,
    ".syslog": EvidenceType.system_log,
    ".evtx": EvidenceType.system_log,
    ".journal": EvidenceType.system_log,
    ".mem": EvidenceType.memory_dump,
    ".dmp": EvidenceType.memory_dump,
    ".vmem": EvidenceType.memory_dump,
    ".lime": EvidenceType.memory_dump,
    ".e01": EvidenceType.disk_image,
    ".ex01": EvidenceType.disk_image,
    ".aff": EvidenceType.disk_image,
    ".aff4": EvidenceType.disk_image,
    ".dd": EvidenceType.disk_image,
    ".img": EvidenceType.disk_image,
    ".raw": EvidenceType.disk_image,
    ".pcap": EvidenceType.network_capture,
    ".pcapng": EvidenceType.network_capture,
    ".ufdr": EvidenceType.mobile_extraction,
    ".xry": EvidenceType.mobile_extraction,
    ".eml": EvidenceType.email_message,
    ".msg": EvidenceType.email_message,
    ".mbox": EvidenceType.email_message,
}


@dataclass(frozen=True, slots=True)
class TypeIdentification:
    """The result of inspecting an artifact's leading bytes."""

    detected_mime: str
    declared_mime: str | None
    declared_extension: str
    evidence_type: EvidenceType
    magic_description: str | None
    extension_mismatch: bool
    mismatch_detail: str | None
    detector: str

    def as_metadata(self) -> dict[str, object]:
        """Flatten to a JSON-safe dict for storage on the evidence record."""
        return {
            "detected_mime": self.detected_mime,
            "declared_mime": self.declared_mime,
            "declared_extension": self.declared_extension,
            "magic_description": self.magic_description,
            "extension_mismatch": self.extension_mismatch,
            "mismatch_detail": self.mismatch_detail,
            "detector": self.detector,
        }


def _sniff_signature(head: bytes) -> str | None:
    for signature, offset, mime in _SIGNATURES:
        if head[offset : offset + len(signature)] == signature:
            return mime
    return None


def _looks_textual(head: bytes) -> bool:
    """Heuristic text test: decodable as UTF-8 and free of control bytes."""
    if not head:
        return False
    if b"\x00" in head:
        return False
    try:
        text = head.decode("utf-8")
    except UnicodeDecodeError:
        return False
    printable = sum(1 for ch in text if ch.isprintable() or ch in "\r\n\t")
    return printable / len(text) > 0.9


def _refine_text(head: bytes, extension: str) -> str:
    """Narrow ``text/plain`` using structure that is cheap to recognise."""
    sample = head.lstrip()[:512]
    if sample.startswith((b"{", b"[")) or extension == ".json":
        return "application/json"
    if sample.startswith(b"<?xml"):
        return "text/xml"
    if sample.lower().startswith(b"<!doctype html") or sample.lower().startswith(b"<html"):
        return "text/html"
    # RFC 5322 messages open with headers; Received/From/Message-ID are the reliable markers.
    lowered = bytes(sample.lower())
    if any(
        lowered.startswith(header)
        for header in (b"received:", b"from:", b"return-path:", b"message-id:", b"delivered-to:")
    ):
        return "message/rfc822"
    if extension == ".csv":
        return "text/csv"
    return "text/plain"


def detect_mime(head: bytes, filename: str = "") -> tuple[str, str | None, str]:
    """Return ``(mime, magic_description, detector)`` for the leading bytes of an artifact."""
    extension = PurePosixPath(filename).suffix.lower()

    if _MAGIC is not None:
        try:
            mime = _MAGIC.from_buffer(head) or "application/octet-stream"
            description = _MAGIC_DESC.from_buffer(head) if _MAGIC_DESC else None
            if mime in {"text/plain", "application/octet-stream"} or mime.startswith("text/"):
                # libmagic is conservative with text; structure gives a more useful answer.
                refined = _refine_text(head, extension)
                if refined != "text/plain" and mime.startswith("text/"):
                    mime = refined
            return mime, description, "libmagic"
        except Exception as exc:  # pragma: no cover - libmagic internal failure
            logger.warning("libmagic_failed", error=str(exc))

    detected = _sniff_signature(head)
    if detected == "application/zip" and extension in _ZIP_REFINEMENTS:
        detected = _ZIP_REFINEMENTS[extension]
    if detected is None:
        detected = (
            _refine_text(head, extension) if _looks_textual(head) else "application/octet-stream"
        )
    return detected, None, "signature-table"


def classify(mime: str, extension: str = "") -> EvidenceType:
    """Map detected content onto the evidence taxonomy.

    Content takes precedence, since that is what was actually observed. The extension is only
    consulted for the categories bytes cannot distinguish - a memory dump, a raw disk image and
    a log file all look like undifferentiated binary or plain text.
    """
    for prefix, evidence_type in _TYPE_RULES:
        if mime.startswith(prefix):
            return evidence_type

    by_extension = _EXTENSION_TYPES.get(extension)
    if by_extension is not None:
        return by_extension

    if mime.startswith("text/") or mime in {"application/json", "application/xml"}:
        return EvidenceType.document
    return EvidenceType.other


def identify(
    head: bytes,
    filename: str = "",
    declared_mime: str | None = None,
) -> TypeIdentification:
    """Identify an artifact from its leading bytes and flag any mismatch with its name.

    A mismatch is reported, never corrected. Both the claim and the observation are preserved
    so an analyst can see that a file was presented as one thing and contains another.
    """
    extension = PurePosixPath(filename).suffix.lower()
    detected, description, detector = detect_mime(head, filename)

    mismatch = False
    detail: str | None = None

    expected = _EXTENSION_EXPECTATIONS.get(extension)
    if expected and not any(detected.startswith(candidate) for candidate in expected):
        mismatch = True
        detail = (
            f"File is named '{extension}', which implies {expected[0]}, "
            f"but its content is {detected}."
        )
    elif declared_mime and declared_mime != "application/octet-stream":
        declared_family = declared_mime.split("/", 1)[0]
        detected_family = detected.split("/", 1)[0]
        if declared_family != detected_family and detected != "application/octet-stream":
            mismatch = True
            detail = f"Upload declared its type as {declared_mime}, but its content is {detected}."

    return TypeIdentification(
        detected_mime=detected,
        declared_mime=declared_mime,
        declared_extension=extension,
        evidence_type=classify(detected, extension),
        magic_description=description,
        extension_mismatch=mismatch,
        mismatch_detail=detail,
        detector=detector,
    )
