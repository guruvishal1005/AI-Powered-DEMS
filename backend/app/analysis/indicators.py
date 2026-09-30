"""Indicator extraction from text.

This is where most of the platform's entity data originates, so the patterns are written to be
*specific* rather than generous. An extractor that matches too much is worse than one that matches
too little: every false positive becomes a node in the relationship graph and a term in a
correlation score, and a graph full of version numbers mistaken for IP addresses is unusable.

Concrete decisions that follow from that:

* IP candidates are validated with :mod:`ipaddress`, so ``1.2.3.4.5`` and ``999.1.1.1`` are
  rejected rather than recorded.
* Domains must end in a known-plausible TLD shape and are rejected when they look like a filename,
  which is what stops ``report.pdf`` and ``schema.xsd`` from becoming domains.
* Private, loopback and documentation addresses are extracted but tagged, because "internal host"
  and "external infrastructure" mean very different things in an investigation.
* Every match carries its byte offset, line number and surrounding text, so any extracted value
  can be pointed back at the exact place it was seen.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterator
from dataclasses import dataclass

from app.analysis.base import ExtractedEntity
from app.models.enums import EntityType

EXCERPT_RADIUS = 60
# Guard against a single pathological artifact producing hundreds of thousands of occurrences.
MAX_OCCURRENCES_PER_TYPE = 500

# Kept deliberately conservative. A domain-shaped string ending in something that is not a
# plausible TLD is far more often a filename, a version string or a Java package.
_KNOWN_TLD_PATTERN = r"(?:[a-z]{2,24})"

_PATTERNS: dict[EntityType, re.Pattern[str]] = {
    EntityType.ip_address: re.compile(
        # The lookarounds reject a dotted quad embedded in a longer dotted-numeric string, so
        # version "1.2.3.4.5" does not yield the address "1.2.3.4".
        r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])"
        # IPv6: at least two groups and a double colon, or a full eight-group form.
        r"|\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b"
        r"|\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b"
    ),
    EntityType.email_address: re.compile(
        r"\b[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,255}\.[A-Za-z]{2,24}\b"
    ),
    EntityType.url: re.compile(r"\bhttps?://[^\s\"'<>()\[\]{}]{3,2000}", re.IGNORECASE),
    EntityType.domain: re.compile(
        rf"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{{0,61}}[a-zA-Z0-9])?\.)+{_KNOWN_TLD_PATTERN}\b"
    ),
    EntityType.mac_address: re.compile(
        r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b"
    ),
    # MD5, SHA-1 and SHA-256 lengths only. Other lengths of hex are far more often identifiers.
    EntityType.file_hash: re.compile(
        r"\b[0-9a-fA-F]{32}\b|\b[0-9a-fA-F]{40}\b|\b[0-9a-fA-F]{64}\b"
    ),
    EntityType.cve: re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE),
    EntityType.crypto_wallet: re.compile(
        # Bitcoin legacy and P2SH, bech32, and Ethereum.
        r"\b(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{25,62}|0x[a-fA-F0-9]{40})\b"
    ),
    EntityType.phone_number: re.compile(
        r"(?<![\w.])\+?\d{1,3}[\s\-.]?\(?\d{2,4}\)?[\s\-.]?\d{3,4}[\s\-.]?\d{3,4}(?![\w.])"
    ),
    EntityType.registry_key: re.compile(
        r"\b(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKLM|HKCU)\\[\w\\\-. ]{3,240}"
    ),
    EntityType.file_path: re.compile(
        r"(?:[A-Za-z]:\\[\w\\\-. ()]{3,240}"
        r"|(?:/(?:etc|var|usr|home|opt|tmp|root|bin|sbin)/[\w/\-. ]{2,240})"
        r"|\\\\[\w.\-]+\\[\w\\\-. $]{2,240})"
    ),
    EntityType.user_agent: re.compile(
        r"Mozilla/\d\.\d \([^)]{3,200}\)(?:[^\"\s][^\"]{0,200})?"
    ),
}

# Extensions that make a domain-shaped token almost certainly a filename.
_FILENAME_TLDS = frozenset(
    {
        "exe", "dll", "sys", "bat", "cmd", "ps1", "sh", "py", "js", "ts", "jsx", "tsx",
        "java", "class", "jar", "c", "h", "cpp", "cs", "go", "rs", "rb", "php", "pl",
        "txt", "log", "csv", "json", "xml", "yml", "yaml", "toml", "ini", "cfg", "conf",
        "md", "rst", "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "odt", "rtf",
        "zip", "gz", "tar", "rar", "7z", "bz2", "xz", "iso", "img", "dd", "e01",
        "png", "jpg", "jpeg", "gif", "bmp", "svg", "webp", "tiff", "ico",
        "mp3", "mp4", "avi", "mov", "wav", "mkv", "webm",
        "html", "htm", "css", "scss", "vue", "sql", "db", "sqlite", "bak", "tmp", "swp",
        "xsd", "xsl", "xslt", "dtd", "wsdl", "properties", "gradle", "cmake", "mk", "in",
        "dat", "bin", "so", "dylib", "o", "a", "lib", "pdb", "map", "lock", "pem", "key",
        "crt", "cer", "pfx", "eml", "msg", "pst", "ost", "evtx", "pcap", "pcapng",
    }
)

# Reserved and infrastructure domains that carry no investigative signal on their own.
_NOISE_DOMAINS = frozenset(
    {
        "example.com", "example.org", "example.net", "localhost.localdomain",
        "w3.org", "schemas.microsoft.com", "www.w3.org", "purl.org", "xml.org",
        "iana.org", "ietf.org", "rfc-editor.org",
    }
)


@dataclass(frozen=True, slots=True)
class Match:
    """One raw pattern hit, with everything needed to locate it again."""

    type: EntityType
    value: str
    byte_offset: int
    line: int
    excerpt: str


# Documentation and test ranges (RFC 5737, RFC 3849). Python's ``is_private`` reports these as
# private because IANA lists them as special-purpose, but for an investigation they behave as
# external addresses - they are not hosts on the subject's own network. Checking them before
# ``is_private`` is what keeps them from being mislabelled as internal.
_DOCUMENTATION_NETWORKS = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("2001:db8::/32"),
)

# Scopes that represent infrastructure outside the subject's own network.
EXTERNAL_SCOPES = frozenset({"public", "documentation"})


def _classify_address(value: str) -> tuple[bool, str]:
    """Return ``(keep, scope)`` for an IP candidate.

    Rejects strings that merely look like addresses, and labels the ones it keeps. The label
    matters downstream: an anomaly detector that treats a loopback address as suspicious external
    infrastructure, or an internal address as attacker infrastructure, produces nonsense.
    """
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False, ""

    if address.is_unspecified:
        return False, ""
    if address.is_loopback:
        return True, "loopback"
    if address.is_link_local:
        return True, "link_local"
    if address.is_multicast:
        return True, "multicast"
    if any(address in network for network in _DOCUMENTATION_NETWORKS):
        return True, "documentation"
    if address.is_private:
        return True, "private"
    if address.is_reserved:
        return True, "reserved"
    return True, "public"


def address_scope(value: str) -> str | None:
    """The network scope of an address, or ``None`` if it is not a valid address."""
    keep, scope = _classify_address(value)
    return scope if keep else None


def is_external_address(value: str) -> bool:
    """Whether an address represents infrastructure outside the subject's own network."""
    return address_scope(value) in EXTERNAL_SCOPES


def _plausible_phone(value: str) -> bool:
    """Reject dotted-numeric strings that merely have a phone-like shape.

    Version numbers, invalid dotted quads and build identifiers all match the digit-group pattern.
    Requiring a real phone-number length, and refusing candidates whose only separator is a dot,
    removes the bulk of them without losing conventionally written numbers.
    """
    digits = re.sub(r"\D", "", value)
    if not 7 <= len(digits) <= 15:
        return False
    return not (value.count(".") >= 2 and not any(char in value for char in " -()+"))


def plausible_domain(value: str) -> bool:
    """Whether a domain-shaped string is worth recording as a domain.

    Public because analyzers that pull hostnames out of structured fields - mail relay names in a
    ``Received`` header, for instance - need the same filtering that free-text extraction applies.
    """
    lowered = value.lower().rstrip(".")
    if lowered in _NOISE_DOMAINS:
        return False
    tld = lowered.rsplit(".", 1)[-1]
    if tld in _FILENAME_TLDS:
        return False
    if len(tld) < 2 or tld.isdigit():
        return False
    # A single label plus TLD is fine (example.com); more than six labels is almost always a
    # Java package or a hostname fragment from a stack trace.
    return 2 <= len(lowered.split(".")) <= 6


def _line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _excerpt(text: str, start: int, end: int) -> str:
    left = max(0, start - EXCERPT_RADIUS)
    right = min(len(text), end + EXCERPT_RADIUS)
    return text[left:right].replace("\n", " ").strip()


def iter_matches(text: str, types: tuple[EntityType, ...] | None = None) -> Iterator[Match]:
    """Yield validated indicator matches from text.

    Offsets are character offsets into the decoded text. They are recorded as ``char_offset``
    rather than ``byte_offset`` in locators, because after a lenient decode the two only coincide
    for ASCII, and claiming a byte offset that is wrong would be worse than admitting it is a
    character offset.
    """
    wanted = types or tuple(_PATTERNS)
    counts: dict[EntityType, int] = {}

    for entity_type in wanted:
        pattern = _PATTERNS.get(entity_type)
        if pattern is None:
            continue
        for match in pattern.finditer(text):
            if counts.get(entity_type, 0) >= MAX_OCCURRENCES_PER_TYPE:
                break
            raw = match.group(0).strip().rstrip(".,;:)]}\"'")
            if not raw:
                continue

            if entity_type is EntityType.ip_address:
                keep, _scope = _classify_address(raw)
                if not keep:
                    continue
            elif entity_type is EntityType.domain and not plausible_domain(raw):
                continue
            elif entity_type is EntityType.file_hash and len(raw) not in (32, 40, 64):
                continue
            elif entity_type is EntityType.phone_number and not _plausible_phone(raw):
                continue

            counts[entity_type] = counts.get(entity_type, 0) + 1
            yield Match(
                type=entity_type,
                value=raw,
                byte_offset=match.start(),
                line=_line_number(text, match.start()),
                excerpt=_excerpt(text, match.start(), match.end()),
            )


def extract(
    text: str,
    *,
    types: tuple[EntityType, ...] | None = None,
    source_label: str | None = None,
) -> list[ExtractedEntity]:
    """Extract indicators, collapsing repeats of the same value into one occurrence.

    Repeats are counted rather than stored individually: a log containing one address ten thousand
    times should produce one occurrence with a count of ten thousand, not ten thousand rows. The
    first sighting's location is kept, since that is the one an investigator will want to look at.
    """
    first_seen: dict[tuple[EntityType, str], ExtractedEntity] = {}
    repeats: dict[tuple[EntityType, str], int] = {}

    for match in iter_matches(text, types):
        key = (match.type, match.value.lower())
        if key in first_seen:
            repeats[key] = repeats.get(key, 1) + 1
            continue

        context = source_label
        if match.type is EntityType.ip_address:
            _keep, scope = _classify_address(match.value)
            context = f"{source_label}:{scope}" if source_label else scope

        first_seen[key] = ExtractedEntity(
            type=match.type,
            value=match.value,
            locator={"char_offset": match.byte_offset, "line": match.line},
            excerpt=match.excerpt,
            context=context,
        )

    return [
        ExtractedEntity(
            type=entity.type,
            value=entity.value,
            locator=entity.locator,
            excerpt=entity.excerpt,
            context=entity.context,
            confidence=entity.confidence,
            occurrence_count=repeats.get((entity.type, entity.value.lower()), 1),
        )
        for entity in first_seen.values()
    ]
