"""Evidence analysis tasks.

The queue's entry point into the analysis pipeline. These tasks are deliberately thin: they resolve
the subject, call the pipeline, and let the worker own the transaction. Business logic lives in
:mod:`app.analysis.pipeline` so that it is testable without a queue.

Deduplication keys matter here more than elsewhere. Analysis is expensive and idempotent-by-replace,
so two concurrent runs over the same item would waste work and race each other's deletes. The
dedupe template collapses them to one pending job per evidence item.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.analysis.pipeline import analyze_evidence
from app.core.context import RequestContext
from app.core.errors import NotFound
from app.core.logging import get_logger
from app.jobs.queue import enqueue, enqueue_if_available
from app.jobs.registry import task
from app.models.analysis import AnalysisRun
from app.models.enums import AnalysisStatus, EvidenceStatus
from app.models.evidence import Evidence

logger = get_logger(__name__)

# Analysis of a single item should not be retried indefinitely: a parser that fails on a malformed
# artifact will fail identically on every attempt, and the failure is already recorded per analyzer.
MAX_ANALYSIS_ATTEMPTS = 2

# Items in these states are out of the active working set: archived material is deliberately at
# rest, and disposed material no longer has content to read.
_TERMINAL_STATUSES = (EvidenceStatus.archived, EvidenceStatus.disposed)


def analysis_dedupe_key(evidence: Evidence, version_number: int | None = None) -> str:
    """The dedupe key for analysing an item at a given version.

    Version-aware on purpose. A second job for the *same* version is redundant work, but adding a
    new version genuinely requires re-analysis, and a key that ignored the version number would
    suppress it. Every producer of these jobs - ingestion, versioning and the periodic sweeps -
    must build the key the same way or deduplication silently stops working.

    ``version_number`` should be passed explicitly by callers that have just created a version,
    because the ``current_version`` relationship can still hold the previous row until the session
    refreshes it - and reading a stale number there would suppress the new version's analysis.
    """
    if version_number is None:
        version = evidence.current_version
        version_number = version.version_number if version is not None else 0
    return f"analyze:{evidence.id}:{version_number}"


def _load_evidence(db: Session, payload: dict[str, Any]) -> Evidence:
    raw = payload.get("evidence_id")
    if not raw:
        raise ValueError("evidence.analyze requires an evidence_id")
    evidence = db.get(Evidence, uuid.UUID(str(raw)))
    if evidence is None:
        raise NotFound("Evidence", str(raw))
    return evidence


@task(
    "evidence.analyze",
    max_attempts=MAX_ANALYSIS_ATTEMPTS,
    priority=50,
    description="Run all applicable analyzers over one evidence item",
)
def analyze(db: Session, ctx: RequestContext, payload: dict[str, Any]) -> dict[str, Any]:
    """Analyse one evidence item with every analyzer that applies to it."""
    evidence = _load_evidence(db, payload)
    result = analyze_evidence(
        db,
        ctx,
        evidence,
        only=payload.get("analyzer"),
        record_custody=bool(payload.get("record_custody", True)),
    )

    # Correlation is a separate concern that reads what analysis wrote, so it is queued rather than
    # called: it must not be able to fail this job or extend its transaction.
    if result.get("entities"):
        enqueue_if_available(
            db,
            "intelligence.correlate_evidence",
            payload={"evidence_id": str(evidence.id)},
            case_id=evidence.case_id,
            requested_by_id=ctx.actor_id,
        )

    return result


@task(
    "evidence.reanalyze_case",
    max_attempts=1,
    priority=140,
    description="Queue analysis for every item in a case",
    dedupe_template="evidence.reanalyze_case:{case_id}",
)
def reanalyze_case(db: Session, ctx: RequestContext, payload: dict[str, Any]) -> dict[str, Any]:
    """Re-run analysis across a case, one queued job per item.

    Fanning out rather than looping inline keeps each item's analysis in its own transaction, so a
    single unparseable artifact cannot roll back the work already done for its siblings.
    """
    raw = payload.get("case_id")
    if not raw:
        raise ValueError("evidence.reanalyze_case requires a case_id")
    case_id = uuid.UUID(str(raw))

    items = db.scalars(
        select(Evidence).where(
            Evidence.case_id == case_id,
            Evidence.status.notin_(_TERMINAL_STATUSES),
        )
    ).all()

    queued = 0
    for evidence in items:
        job = enqueue(
            db,
            "evidence.analyze",
            payload={"evidence_id": str(evidence.id), "analyzer": payload.get("analyzer")},
            case_id=case_id,
            evidence_id=evidence.id,
            requested_by_id=ctx.actor_id,
            dedupe_key=analysis_dedupe_key(evidence),
        )
        if job is not None:
            queued += 1

    return {"case_id": str(case_id), "items": len(items), "queued": queued}


@task(
    "evidence.retry_failed_analysis",
    max_attempts=1,
    priority=170,
    description="Re-queue analysis for items whose analyzers failed",
)
def retry_failed_analysis(
    db: Session, ctx: RequestContext, payload: dict[str, Any]
) -> dict[str, Any]:
    """Re-queue items that have at least one failed analyzer run.

    Runs periodically. Analyzer failures are frequently environmental - a parser that ran out of
    memory alongside a large job - and those clear on a retry, while genuinely malformed artifacts
    simply fail again and stay visible as failed runs.
    """
    limit = int(payload.get("limit", 50))

    failed = db.scalars(
        select(AnalysisRun.evidence_id)
        .where(AnalysisRun.status == AnalysisStatus.failed)
        .group_by(AnalysisRun.evidence_id)
        .limit(limit)
    ).all()

    queued = 0
    for evidence_id in failed:
        evidence = db.get(Evidence, evidence_id)
        if evidence is None or evidence.status in _TERMINAL_STATUSES:
            continue
        job = enqueue(
            db,
            "evidence.analyze",
            payload={"evidence_id": str(evidence_id)},
            case_id=evidence.case_id,
            evidence_id=evidence_id,
            requested_by_id=ctx.actor_id,
            dedupe_key=analysis_dedupe_key(evidence),
        )
        if job is not None:
            queued += 1

    logger.info("analysis_retry_swept", candidates=len(failed), queued=queued)
    return {"candidates": len(failed), "queued": queued}


@task(
    "evidence.analyze_pending",
    max_attempts=1,
    priority=160,
    description="Queue analysis for items that were never analysed",
)
def analyze_pending(db: Session, ctx: RequestContext, payload: dict[str, Any]) -> dict[str, Any]:
    """Catch items that never got analysed.

    A job can be lost - the process was killed between ingestion committing and the queue insert
    landing, or a job was purged - and without this sweep such an item would sit unanalysed
    indefinitely with nothing indicating it had been missed.
    """
    limit = int(payload.get("limit", 100))

    pending = db.scalars(
        select(Evidence)
        .where(
            Evidence.analysis_completed_at.is_(None),
            Evidence.status.notin_(_TERMINAL_STATUSES),
        )
        .order_by(Evidence.created_at)
        .limit(limit)
    ).all()

    queued = 0
    for evidence in pending:
        job = enqueue(
            db,
            "evidence.analyze",
            payload={"evidence_id": str(evidence.id)},
            case_id=evidence.case_id,
            evidence_id=evidence.id,
            requested_by_id=ctx.actor_id,
            dedupe_key=analysis_dedupe_key(evidence),
        )
        if job is not None:
            queued += 1

    if queued:
        logger.info("pending_analysis_swept", candidates=len(pending), queued=queued)
    return {"candidates": len(pending), "queued": queued}
