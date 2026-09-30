"""Correlation, anomaly, intelligence and insight tasks.

These run after analysis because they read what analysis wrote. The chain is
``analyze -> correlate_evidence -> refresh_case``, each link a separate job so that a slow or
failing stage cannot roll back the stage before it or hold a transaction open across the whole lot.

Correlation is per-item because it is triggered by ingesting one; anomaly detection, intelligence
lookup, insight generation and risk scoring are per-case because they are properties of the case as
a whole. Both are coalesced by dedupe key: importing forty artifacts should not produce forty
identical case refreshes, and a short delay lets a burst of ingestion settle into a single pass.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.context import RequestContext
from app.core.errors import NotFound
from app.core.logging import get_logger
from app.intelligence import anomalies, correlation, insights, risk, threatintel
from app.jobs.queue import enqueue
from app.jobs.registry import task
from app.models.case import Case
from app.models.enums import CaseStatus, EvidenceStatus
from app.models.evidence import Evidence

logger = get_logger(__name__)

# Long enough that ingesting a folder of evidence collapses into one refresh, short enough that an
# investigator uploading a single item sees the case update while still looking at it.
CASE_REFRESH_DELAY_SECONDS = 20

# Cases in these states are not being worked. Recomputing intelligence for them wastes the queue and
# would rewrite the risk score of a closed case, which is a record someone may need to defend.
_INACTIVE_CASE_STATUSES = (CaseStatus.closed, CaseStatus.archived)


def _load_case(db: Session, payload: dict[str, Any]) -> Case:
    raw = payload.get("case_id")
    if not raw:
        raise ValueError("a case_id is required")
    case = db.get(Case, uuid.UUID(str(raw)))
    if case is None:
        raise NotFound("Case", str(raw))
    return case


@task(
    "intelligence.correlate_evidence",
    max_attempts=3,
    priority=70,
    description="Score correlations between one item and the rest of the corpus",
    dedupe_template="correlate:{evidence_id}",
)
def correlate_evidence(
    db: Session, ctx: RequestContext, payload: dict[str, Any]
) -> dict[str, Any]:
    """Correlate one artifact against everything that shares an indicator with it."""
    raw = payload.get("evidence_id")
    if not raw:
        raise ValueError("intelligence.correlate_evidence requires an evidence_id")
    evidence = db.get(Evidence, uuid.UUID(str(raw)))
    if evidence is None:
        raise NotFound("Evidence", str(raw))

    result = correlation.correlate_evidence(db, evidence)

    # A delayed, deduplicated case refresh. Case-level intelligence depends on every item's
    # correlations, so it is pointless to run it once per artifact during a bulk import.
    enqueue(
        db,
        "intelligence.refresh_case",
        payload={"case_id": str(evidence.case_id)},
        case_id=evidence.case_id,
        requested_by_id=ctx.actor_id,
        delay_seconds=CASE_REFRESH_DELAY_SECONDS,
    )
    return result


@task(
    "intelligence.refresh_case",
    max_attempts=3,
    priority=90,
    description="Recompute anomalies, intelligence matches, insights and risk for a case",
    dedupe_template="refresh_case:{case_id}",
)
def refresh_case(db: Session, ctx: RequestContext, payload: dict[str, Any]) -> dict[str, Any]:
    """Recompute every case-level intelligence product, in dependency order.

    Order is not arbitrary: intelligence matches and anomalies are inputs to insights and to the
    risk score, so running them first means one pass produces a consistent picture instead of a
    score derived from the previous pass's anomalies.
    """
    case = _load_case(db, payload)

    intel_result = threatintel.check_case(db, case.id)
    anomaly_result = anomalies.detect_for_case(db, case.id)
    insight_result = insights.generate_for_case(db, case)
    assessment = risk.score_case(db, case)

    logger.info(
        "case_intelligence_refreshed",
        case=case.reference,
        anomalies=anomaly_result["created"],
        insights=insight_result["created"],
        risk=assessment.score,
    )
    return {
        "case": case.reference,
        "intel": intel_result,
        "anomalies": anomaly_result,
        "insights": insight_result,
        "risk": {"score": assessment.score, "band": assessment.band},
    }


@task(
    "intelligence.rebuild_correlations",
    max_attempts=1,
    priority=200,
    description="Recompute correlation scores across the whole corpus",
)
def rebuild_correlations(
    db: Session, ctx: RequestContext, payload: dict[str, Any]
) -> dict[str, Any]:
    """Recompute every correlation edge.

    Rarity is a global property: each new artifact changes the corpus size and the document
    frequency of everything it contains, so scores computed earlier slowly drift. Running this
    periodically brings every edge back into agreement with a single view of the corpus.
    """
    limit = payload.get("limit")
    return correlation.rebuild_all(db, limit=int(limit) if limit else None)


@task(
    "intelligence.refresh_active_cases",
    max_attempts=1,
    priority=210,
    description="Queue an intelligence refresh for every open case",
)
def refresh_active_cases(
    db: Session, ctx: RequestContext, payload: dict[str, Any]
) -> dict[str, Any]:
    """Fan out a refresh to each open case.

    Needed because case intelligence is comparative: a cross-case link appears in *both* cases, and
    the older one gets no ingestion event to trigger its own recomputation.
    """
    cases = db.scalars(
        select(Case).where(Case.status.notin_(_INACTIVE_CASE_STATUSES))
    ).all()

    queued = 0
    for case in cases:
        if (
            enqueue(
                db,
                "intelligence.refresh_case",
                payload={"case_id": str(case.id)},
                case_id=case.id,
                requested_by_id=ctx.actor_id,
            )
            is not None
        ):
            queued += 1

    return {"cases": len(cases), "queued": queued}


@task(
    "intelligence.correlate_pending",
    max_attempts=1,
    priority=205,
    description="Queue correlation for analysed items that have no edges yet",
)
def correlate_pending(
    db: Session, ctx: RequestContext, payload: dict[str, Any]
) -> dict[str, Any]:
    """Catch analysed items whose correlation job never ran.

    The chain from analysis to correlation is a queued handoff, and a handoff can be lost - a purged
    job, a process killed between the two. Without this sweep such an item stays permanently
    uncorrelated, and nothing anywhere indicates that it should have been.
    """
    limit = int(payload.get("limit", 100))

    items = db.scalars(
        select(Evidence)
        .where(
            Evidence.analysis_completed_at.is_not(None),
            Evidence.status.notin_((EvidenceStatus.archived, EvidenceStatus.disposed)),
        )
        .order_by(Evidence.analysis_completed_at.desc())
        .limit(limit)
    ).all()

    queued = 0
    for evidence in items:
        if (
            enqueue(
                db,
                "intelligence.correlate_evidence",
                payload={"evidence_id": str(evidence.id)},
                case_id=evidence.case_id,
                evidence_id=evidence.id,
                requested_by_id=ctx.actor_id,
            )
            is not None
        ):
            queued += 1

    return {"candidates": len(items), "queued": queued}
