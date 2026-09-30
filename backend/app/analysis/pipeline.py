"""Analysis orchestration.

The pipeline decides which analyzers apply to an artifact, runs them, and persists what they
observed. Three properties matter more than the mechanics:

**One analyzer's failure is not the pipeline's failure.** A malformed PDF that crashes a parser
must not prevent the email analyzer from having run. Each analyzer is isolated, and its failure is
recorded as a failed :class:`~app.models.analysis.AnalysisRun` with the error attached, so a gap in
analysis is *visible* rather than looking like an artifact that contained nothing of interest.

**Re-analysis replaces, never appends.** Running analysis twice over the same artifact must not
double its entity counts, so a re-run clears the previous output for each analyzer before writing
new results.

**Nothing here interprets.** The pipeline writes entities, observations and technical findings.
Correlation, anomaly detection, risk and insight generation all read those rows afterwards. An
analyzer cannot reach across that line even by accident, because it never receives a session.
"""

from __future__ import annotations

import time
import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.analysis import registry
from app.analysis.base import AnalyzerOutput, ArtifactHandle
from app.analysis.entities import clear_occurrences, record_occurrence, refresh_counters
from app.audit.writer import append_custody
from app.core.clock import utcnow
from app.core.context import RequestContext
from app.core.errors import NotFound
from app.core.logging import get_logger
from app.models.analysis import (
    AnalysisFinding,
    AnalysisRun,
    Entity,
    Observation,
    observation_entities,
)
from app.models.enums import (
    AnalysisStatus,
    CustodyAction,
    EvidenceStatus,
    Severity,
)
from app.models.evidence import Evidence, EvidenceVersion, StoredObject
from app.storage.local import get_storage

logger = get_logger(__name__)


def build_handle(db: Session, evidence: Evidence) -> ArtifactHandle:
    """Wrap an evidence item as the read-only handle analyzers receive."""
    version = evidence.current_version
    if version is None:
        raise NotFound("Evidence version", evidence.reference)
    stored = db.get(StoredObject, version.stored_object_id)
    if stored is None:
        raise NotFound("Stored object", str(version.stored_object_id))

    from app.forensics.integrity import ref_for

    ref = ref_for(stored)
    storage = get_storage()

    return ArtifactHandle(
        evidence_id=evidence.id,
        case_id=evidence.case_id,
        filename=evidence.original_filename,
        mime_type=evidence.mime_type,
        evidence_type=evidence.evidence_type,
        size_bytes=version.size_bytes,
        sha256=version.sha256,
        # A callable rather than an open stream: an analyzer that declines to run should not pay
        # the cost of decrypting anything.
        open_stream=lambda: storage.open_stream(ref),
        head=storage.read_prefix(ref, 8192),
        acquired_at=evidence.acquired_at,
    )


def analyze_evidence(
    db: Session,
    ctx: RequestContext,
    evidence: Evidence,
    *,
    only: str | None = None,
    record_custody: bool = True,
) -> dict[str, Any]:
    """Run every applicable analyzer over an item and persist the results."""
    registry.load_analyzers()

    version = evidence.current_version
    if version is None:
        raise NotFound("Evidence version", evidence.reference)

    handle = build_handle(db, evidence)
    analyzers = (
        (registry.get(only),) if only else registry.applicable(handle)
    )

    evidence.status = EvidenceStatus.processing
    db.flush()

    summary: dict[str, Any] = {
        "evidence": evidence.reference,
        "analyzers_run": [],
        "analyzers_failed": [],
        "entities": 0,
        "observations": 0,
        "findings": 0,
    }
    aggregate_metadata: dict[str, Any] = dict(evidence.extracted_metadata or {})
    touched_entities: set[uuid.UUID] = set()

    for analyzer in analyzers:
        # Flushed before the savepoint below, so the record that this analyzer was attempted
        # survives even when its own work is rolled back.
        run = _new_run(evidence, version, analyzer.name, analyzer.version, ctx)
        db.add(run)
        db.flush()
        run_id = run.id

        started = time.perf_counter()
        try:
            # A SAVEPOINT per analyzer. An analyzer parses adversarial input, so any exception
            # type is possible, and a half-written result set must be discarded without taking
            # the preceding analyzers' work with it.
            with db.begin_nested():
                output = analyzer.analyze(handle)
                if output.skip_reason:
                    counts = None
                else:
                    cleared = clear_occurrences(db, evidence.id, analyzer.name)
                    counts = _persist(
                        db, evidence, run, analyzer.name, analyzer.version, output
                    )
                    counts["entity_ids"] |= cleared
        except Exception as exc:
            _mark_failed(db, run_id, exc, started)
            summary["analyzers_failed"].append(analyzer.name)
            logger.warning(
                "analyzer_failed",
                analyzer=analyzer.name,
                evidence=evidence.reference,
                error=f"{type(exc).__name__}: {exc}",
            )
            continue

        # The savepoint release expired the instance, so re-fetch before mutating it.
        completed_run = db.get(AnalysisRun, run_id)
        if completed_run is None:  # pragma: no cover - defensive
            continue
        completed_run.completed_at = utcnow()
        completed_run.duration_ms = int((time.perf_counter() - started) * 1000)
        completed_run.bytes_examined = output.bytes_examined

        if counts is None:
            completed_run.status = AnalysisStatus.skipped
            completed_run.skip_reason = (output.skip_reason or "")[:240]
            continue

        touched_entities |= counts["entity_ids"]
        completed_run.status = AnalysisStatus.completed
        completed_run.entity_count = counts["entities"]
        completed_run.observation_count = counts["observations"]
        completed_run.finding_count = counts["findings"]
        completed_run.summary = {**output.metadata, "truncated": output.truncated}

        if output.metadata:
            aggregate_metadata[analyzer.name] = output.metadata

        summary["analyzers_run"].append(analyzer.name)
        summary["entities"] += counts["entities"]
        summary["observations"] += counts["observations"]
        summary["findings"] += counts["findings"]

    refresh_counters(db, touched_entities)

    evidence.extracted_metadata = aggregate_metadata
    evidence.analysis_completed_at = utcnow()
    # An item that failed verification stays flagged for attention; analysis completing does not
    # clear an integrity problem.
    if evidence.status is EvidenceStatus.processing:
        evidence.status = EvidenceStatus.analyzed

    _apply_derived_fields(evidence, aggregate_metadata)

    if record_custody:
        append_custody(
            db,
            ctx,
            evidence,
            CustodyAction.analyzed,
            new_state={"status": evidence.status.value},
            details={
                "analyzers_run": summary["analyzers_run"],
                "analyzers_failed": summary["analyzers_failed"],
                "entities_recorded": summary["entities"],
                "observations_recorded": summary["observations"],
                "findings_recorded": summary["findings"],
                # Recorded so the custody chain shows exactly which code examined the artifact.
                "analyzer_versions": {a.name: a.version for a in analyzers},
            },
        )

    logger.info(
        "analysis_completed",
        evidence=evidence.reference,
        analyzers=len(summary["analyzers_run"]),
        failed=len(summary["analyzers_failed"]),
        entities=summary["entities"],
        observations=summary["observations"],
    )
    return summary


def _trim(value: str | None, limit: int = 255) -> str | None:
    """Fit an analyzer-supplied value into its column without raising.

    Analyzers pull these out of evidence, so their length is set by whatever an attacker or a
    logging system happened to write. Truncating is right here: the full text is always still
    available in the observation's excerpt and locator.
    """
    if value is None:
        return None
    cleaned = value.strip()
    return cleaned[:limit] or None


def _new_run(
    evidence: Evidence,
    version: EvidenceVersion,
    analyzer: str,
    analyzer_version: str,
    ctx: RequestContext,
) -> AnalysisRun:
    now = utcnow()
    return AnalysisRun(
        evidence_id=evidence.id,
        case_id=evidence.case_id,
        evidence_version_id=version.id,
        analyzer=analyzer,
        analyzer_version=analyzer_version,
        status=AnalysisStatus.running,
        started_at=now,
        created_at=now,
        requested_by_id=ctx.actor_id,
        summary={},
    )


def _mark_failed(db: Session, run_id: uuid.UUID, exc: Exception, started: float) -> None:
    """Record why an analyzer failed, on the run row that survived the savepoint rollback."""
    run = db.get(AnalysisRun, run_id)
    if run is None:  # pragma: no cover - defensive
        return
    run.status = AnalysisStatus.failed
    run.completed_at = utcnow()
    run.duration_ms = int((time.perf_counter() - started) * 1000)
    run.error = f"{type(exc).__name__}: {exc}"[:4000]
    db.flush()


def _persist(
    db: Session,
    evidence: Evidence,
    run: AnalysisRun,
    analyzer: str,
    analyzer_version: str,
    output: AnalyzerOutput,
) -> dict[str, Any]:
    """Write one analyzer's output, wiring observations to the entities they involve."""
    entity_ids: set[uuid.UUID] = set()
    # Canonical value to entity id, so an observation can reference an entity the same analyzer
    # extracted without a second lookup.
    by_value: dict[str, uuid.UUID] = {}

    for extracted in output.entities:
        occurrence = record_occurrence(
            db,
            extracted=extracted,
            evidence_id=evidence.id,
            case_id=evidence.case_id,
            analysis_run_id=run.id,
            analyzer=analyzer,
            analyzer_version=analyzer_version,
        )
        if occurrence is None:
            continue
        entity_ids.add(occurrence.entity_id)
        by_value[extracted.value.strip().lower()] = occurrence.entity_id

    db.flush()

    # Previous observations and findings from this analyzer are replaced for the same reason
    # occurrences are: a re-run must not duplicate the timeline.
    _delete_previous(db, evidence.id, analyzer)

    observation_count = 0
    for extracted_observation in output.observations:
        observation = Observation(
            evidence_id=evidence.id,
            case_id=evidence.case_id,
            analysis_run_id=run.id,
            kind=extracted_observation.kind,
            occurred_at=extracted_observation.occurred_at,
            time_confidence=extracted_observation.time_confidence,
            timezone_assumed=extracted_observation.timezone_assumed,
            summary=extracted_observation.summary[:400],
            actor_value=_trim(extracted_observation.actor_value),
            source_value=_trim(extracted_observation.source_value),
            target_value=_trim(extracted_observation.target_value),
            outcome=_trim(extracted_observation.outcome, 48),
            analyzer=analyzer,
            analyzer_version=analyzer_version,
            locator=extracted_observation.locator,
            excerpt=(extracted_observation.excerpt or "")[:2000] or None,
            attributes=extracted_observation.attributes,
        )
        db.add(observation)
        db.flush()
        observation_count += 1

        linked = {
            by_value[value.strip().lower()]
            for value in extracted_observation.entity_values
            if value.strip().lower() in by_value
        }
        for entity_id in linked:
            db.execute(
                observation_entities.insert().values(
                    observation_id=observation.id, entity_id=entity_id
                )
            )

    finding_count = 0
    for extracted_finding in output.findings:
        db.add(
            AnalysisFinding(
                evidence_id=evidence.id,
                case_id=evidence.case_id,
                analysis_run_id=run.id,
                code=extracted_finding.code[:96],
                title=extracted_finding.title[:240],
                description=extracted_finding.description,
                severity=extracted_finding.severity,
                confidence=extracted_finding.confidence,
                analyzer=analyzer,
                analyzer_version=analyzer_version,
                locator=extracted_finding.locator,
                excerpt=(extracted_finding.excerpt or "")[:2000] or None,
                attributes=extracted_finding.attributes,
            )
        )
        finding_count += 1

    db.flush()
    return {
        "entities": len(entity_ids),
        "observations": observation_count,
        "findings": finding_count,
        "entity_ids": entity_ids,
    }


def _delete_previous(db: Session, evidence_id: uuid.UUID, analyzer: str) -> None:
    for observation in (
        db.execute(
            select(Observation)
            .where(Observation.evidence_id == evidence_id)
            .where(Observation.analyzer == analyzer)
        )
        .scalars()
        .all()
    ):
        db.delete(observation)
    for finding in (
        db.execute(
            select(AnalysisFinding)
            .where(AnalysisFinding.evidence_id == evidence_id)
            .where(AnalysisFinding.analyzer == analyzer)
        )
        .scalars()
        .all()
    ):
        db.delete(finding)
    db.flush()


def _apply_derived_fields(evidence: Evidence, metadata: dict[str, Any]) -> None:
    """Copy a few analyzer results onto the evidence row.

    Denormalised only where a value is needed for listing, filtering or sorting - entropy and the
    high-entropy flag - because a repository view cannot join into JSONB for every row.
    """
    file_metadata = metadata.get("file_metadata")
    if isinstance(file_metadata, dict):
        entropy = file_metadata.get("entropy", {})
        if isinstance(entropy, dict):
            overall = entropy.get("overall_bits_per_byte")
            if isinstance(overall, int | float):
                evidence.entropy = float(overall)


def analyze_by_id(
    db: Session,
    ctx: RequestContext,
    evidence_id: uuid.UUID,
    *,
    only: str | None = None,
) -> dict[str, Any]:
    evidence = db.get(Evidence, evidence_id)
    if evidence is None:
        raise NotFound("Evidence", str(evidence_id))
    return analyze_evidence(db, ctx, evidence, only=only)


def entity_summary(db: Session, evidence_id: uuid.UUID) -> list[dict[str, Any]]:
    """Entities found in one artifact, with their global rarity.

    ``document_frequency`` is returned alongside each value so the interface can show how common
    it is; an indicator present in one other artifact means something quite different from one
    present in four hundred.
    """
    from app.models.analysis import EntityOccurrence

    rows = db.execute(
        select(Entity, EntityOccurrence)
        .join(EntityOccurrence, EntityOccurrence.entity_id == Entity.id)
        .where(EntityOccurrence.evidence_id == evidence_id)
        .order_by(Entity.type, Entity.canonical_value)
    ).all()

    grouped: dict[uuid.UUID, dict[str, Any]] = {}
    for entity, occurrence in rows:
        record = grouped.setdefault(
            entity.id,
            {
                "entity_id": entity.id,
                "type": entity.type.value,
                "value": entity.display_value,
                "canonical_value": entity.canonical_value,
                "document_frequency": entity.document_frequency,
                "case_count": entity.case_count,
                "intel_severity": (
                    entity.intel_severity.value if entity.intel_severity else None
                ),
                "occurrences": [],
            },
        )
        record["occurrences"].append(
            {
                "locator": occurrence.locator,
                "excerpt": occurrence.excerpt,
                "context": occurrence.context,
                "analyzer": occurrence.analyzer,
                "analyzer_version": occurrence.analyzer_version,
                "confidence": occurrence.confidence,
            }
        )
    return list(grouped.values())


SEVERITY_ORDER = {
    Severity.critical: 0,
    Severity.high: 1,
    Severity.medium: 2,
    Severity.low: 3,
    Severity.informational: 4,
}
