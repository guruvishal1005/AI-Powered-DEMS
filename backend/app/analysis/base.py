"""The analyzer contract.

An analyzer reads one artifact and returns what it *observed*. It does not touch the database,
does not decide what anything means, and cannot raise an alert. That restriction is the entire
point of this boundary: everything an analyzer produces is a fact with a location inside a
specific artifact, and interpretation happens later, in a separate layer, over facts that were
already recorded. It is what makes "observed versus interpretation" a structural property of the
system rather than a labelling convention in the interface.

Three consequences worth stating explicitly:

**Provenance is mandatory, not optional.** Every extracted item carries a ``locator`` - a byte
offset, line number, header name or page - and an ``excerpt``. An analyzer that cannot say where
it saw something has no way to record it, so an unsupported claim cannot enter the system.

**Timestamps found inside artifacts are untrusted.** A log line's clock belongs to whoever wrote
the log. Observations therefore carry ``time_confidence`` and ``timezone_assumed``, because a
timeline that silently invents an offset is worse than one that admits the ambiguity.

**Analyzers are versioned.** A finding produced by version 1 is never presented as though the
current version produced it, so improving an analyzer does not retroactively rewrite history.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import datetime
from typing import IO, Any, Protocol, runtime_checkable

from app.models.enums import Confidence, EntityType, EvidenceType, ObservationKind, Severity

# How much of an artifact a text-oriented analyzer will read. Beyond this, extraction is
# truncated and says so, rather than reading a 4 GB log into memory.
MAX_TEXT_BYTES = 8 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class ExtractedEntity:
    """An indicator or actor observed at a specific place in an artifact."""

    type: EntityType
    value: str
    locator: dict[str, Any] = field(default_factory=dict)
    excerpt: str | None = None
    # What role the value played where it was found: "sender", "source_ip", "gps".
    context: str | None = None
    confidence: float = 1.0
    occurrence_count: int = 1


@dataclass(frozen=True, slots=True)
class ExtractedObservation:
    """A timestamped event recovered from an artifact's content."""

    kind: ObservationKind
    occurred_at: datetime
    summary: str
    locator: dict[str, Any] = field(default_factory=dict)
    excerpt: str | None = None
    actor_value: str | None = None
    source_value: str | None = None
    target_value: str | None = None
    outcome: str | None = None
    time_confidence: Confidence = Confidence.high
    # True when the artifact gave no UTC offset and one had to be assumed.
    timezone_assumed: bool = False
    attributes: dict[str, Any] = field(default_factory=dict)
    # Entity values this event involves, matched back to entities after persistence.
    entity_values: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ExtractedFinding:
    """A technical finding an analyzer can support from the artifact alone."""

    code: str
    title: str
    description: str
    severity: Severity = Severity.informational
    confidence: float = 1.0
    locator: dict[str, Any] = field(default_factory=dict)
    excerpt: str | None = None
    attributes: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class AnalyzerOutput:
    """Everything one analyzer produced from one artifact."""

    metadata: dict[str, Any] = field(default_factory=dict)
    entities: list[ExtractedEntity] = field(default_factory=list)
    observations: list[ExtractedObservation] = field(default_factory=list)
    findings: list[ExtractedFinding] = field(default_factory=list)
    bytes_examined: int = 0
    # Set when the analyzer declined to run; recorded so a gap in analysis is visible rather
    # than looking like an artifact that simply contained nothing.
    skip_reason: str | None = None
    truncated: bool = False

    def add_entity(self, entity: ExtractedEntity) -> None:
        self.entities.append(entity)

    def add_observation(self, observation: ExtractedObservation) -> None:
        self.observations.append(observation)

    def add_finding(self, finding: ExtractedFinding) -> None:
        self.findings.append(finding)


@dataclass(frozen=True, slots=True)
class ArtifactHandle:
    """Read-only access to one artifact plus the facts already known about it.

    Analyzers receive this instead of an evidence row, so they cannot reach the database, and
    so the same analyzer can be run against a test fixture with no platform state at all.
    """

    evidence_id: Any
    case_id: Any
    filename: str
    mime_type: str
    evidence_type: EvidenceType
    size_bytes: int
    sha256: str
    # Streams decrypted plaintext. Called at most once per analyzer, and lazily, so declining to
    # run costs nothing.
    open_stream: Any
    head: bytes
    # When the evidence was acquired, used to anchor timestamps in formats that omit the year
    # (syslog being the common case). Anchoring to acquisition rather than to "now" keeps a log
    # collected two years ago from being placed in the present.
    acquired_at: datetime | None = None

    def read_text(self, max_bytes: int = MAX_TEXT_BYTES) -> tuple[str, bool]:
        """Decode a bounded prefix as text, reporting whether it was truncated.

        Decoding is lenient. Evidence is frequently not valid UTF-8 - mixed encodings in a log,
        a truncated capture - and refusing to analyse it would discard recoverable information;
        replacement characters are acceptable here because every extracted value is also stored
        with its exact byte locator.
        """
        chunks: list[bytes] = []
        total = 0
        truncated = False
        for chunk in self.open_stream():
            remaining = max_bytes - total
            if remaining <= 0:
                truncated = True
                break
            if len(chunk) > remaining:
                chunks.append(chunk[:remaining])
                total += remaining
                truncated = True
                break
            chunks.append(chunk)
            total += len(chunk)
        return b"".join(chunks).decode("utf-8", errors="replace"), truncated

    def read_bytes(self, max_bytes: int = MAX_TEXT_BYTES) -> tuple[bytes, bool]:
        chunks: list[bytes] = []
        total = 0
        truncated = False
        for chunk in self.open_stream():
            remaining = max_bytes - total
            if remaining <= 0:
                truncated = True
                break
            if len(chunk) > remaining:
                chunks.append(chunk[:remaining])
                truncated = True
                break
            chunks.append(chunk)
            total += len(chunk)
        return b"".join(chunks), truncated

    def iter_chunks(self) -> Iterator[bytes]:
        """Stream the whole artifact, for analyzers that must not buffer it."""
        return self.open_stream()

    def open_temp_file(self) -> IO[bytes]:
        """Materialise the artifact as a seekable temporary file.

        Some libraries genuinely require random access - PDF and ZIP parsers among them - and
        cannot work from a forward-only stream. The file is created with restrictive permissions
        and deleted when closed, so decrypted content never persists on disk.
        """
        import tempfile

        handle = tempfile.NamedTemporaryFile(suffix=".plain")
        for chunk in self.open_stream():
            handle.write(chunk)
        handle.flush()
        handle.seek(0)
        return handle


@runtime_checkable
class Analyzer(Protocol):
    """What every analyzer must provide."""

    name: str
    version: str
    description: str
    # Lower runs earlier. Used instead of import order so that sorting imports cannot change the
    # sequence in which analysis happens.
    priority: int

    def applies_to(self, artifact: ArtifactHandle) -> bool:
        """Whether this analyzer can say anything useful about the artifact."""
        ...

    def analyze(self, artifact: ArtifactHandle) -> AnalyzerOutput:
        """Examine the artifact and return what was observed."""
        ...


class BaseAnalyzer:
    """Convenience base supplying the common applicability patterns."""

    name: str = "base"
    version: str = "1"
    description: str = ""
    priority: int = 100
    # MIME prefixes this analyzer handles. Empty means "consult evidence_types instead".
    mime_prefixes: tuple[str, ...] = ()
    evidence_types: tuple[EvidenceType, ...] = ()
    # Analyzers that must run regardless of type (metadata, hashing).
    universal: bool = False
    max_size_bytes: int | None = None

    def applies_to(self, artifact: ArtifactHandle) -> bool:
        if self.max_size_bytes is not None and artifact.size_bytes > self.max_size_bytes:
            return False
        if self.universal:
            return True
        if self.mime_prefixes and artifact.mime_type.startswith(self.mime_prefixes):
            return True
        return artifact.evidence_type in self.evidence_types

    def analyze(self, artifact: ArtifactHandle) -> AnalyzerOutput:  # pragma: no cover
        raise NotImplementedError
