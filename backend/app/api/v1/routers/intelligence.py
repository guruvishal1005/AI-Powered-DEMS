"""Intelligence endpoints: insights, anomalies, correlations, entities and risk.

Reads are gated on ``analysis:read`` and scoped to the caller's cases in SQL. Recomputation is
queued rather than performed inline: a full case refresh runs correlation, intelligence lookup,
anomaly detection, insight generation and risk scoring, which is far too much work to hold an HTTP
request open for, and doing it in the request would also make it trivially easy to exhaust the
database by refreshing repeatedly.

There is no endpoint that writes an insight, an anomaly or a correlation edge. Those are produced
only by deterministic code reading persisted evidence, and an API that let a client post one would
make the provenance labelling meaningless.
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.core.context import RequestContext
from app.core.pagination import Page, PageParams, page_params
from app.db.session import get_db
from app.jobs.queue import enqueue
from app.models.enums import (
    AnomalyKind,
    EntityType,
    IndicatorSeverity,
    InsightKind,
    Permission,
    Severity,
)
from app.schemas.common import EvidenceRef
from app.schemas.intelligence import (
    AnomalyOut,
    CaseRiskOut,
    CorrelationEdgeOut,
    CrossCaseLinkOut,
    DismissRequest,
    EntityDetailOut,
    EntityOccurrenceOut,
    EntitySummaryOut,
    InsightOut,
    IntelligenceSummaryOut,
    PinRequest,
    RefreshQueuedOut,
    ThreatIndicatorOut,
)
from app.security.deps import require
from app.services import case_service, intelligence_service

router = APIRouter(prefix="/intelligence", tags=["intelligence"])

DbSession = Annotated[Session, Depends(get_db)]


def _entity_summary(view: intelligence_service.EntityView) -> EntitySummaryOut:
    entity = view.entity
    return EntitySummaryOut(
        id=entity.id,
        type=entity.type,
        canonical_value=entity.canonical_value,
        display_value=entity.display_value,
        label=entity.label,
        first_seen_at=entity.first_seen_at,
        last_seen_at=entity.last_seen_at,
        evidence_count=view.evidence_count,
        occurrence_count=view.occurrence_count,
        document_frequency=entity.document_frequency,
        case_count=entity.case_count,
        intel_severity=entity.intel_severity,
        intel_tags=list(entity.intel_tags or []),
        intel_checked_at=entity.intel_checked_at,
        intel_match_count=view.intel_matches,
    )


@router.get("/insights", response_model=Page[InsightOut], summary="List insights")
def list_insights(
    db: DbSession,
    ctx: Annotated[RequestContext, Depends(require(Permission.analysis_read))],
    params: Annotated[PageParams, Depends(page_params)],
    case_id: uuid.UUID | None = None,
    kind: Annotated[list[InsightKind] | None, Query()] = None,
    severity: Annotated[list[Severity] | None, Query()] = None,
    include_dismissed: bool = False,
    pinned_only: bool = False,
) -> Page[InsightOut]:
    insights, total = intelligence_service.list_insights(
        db,
        ctx,
        params,
        case_id=case_id,
        kinds=kind,
        severities=severity,
        include_dismissed=include_dismissed,
        pinned_only=pinned_only,
    )
    return Page.build([InsightOut.model_validate(insight) for insight in insights], total, params)


@router.get("/insights/{insight_id}", response_model=InsightOut, summary="Retrieve one insight")
def get_insight(
    db: DbSession,
    ctx: Annotated[RequestContext, Depends(require(Permission.analysis_read))],
    insight_id: uuid.UUID,
) -> InsightOut:
    return InsightOut.model_validate(intelligence_service.get_insight(db, ctx, insight_id))


@router.post(
    "/insights/{insight_id}/dismiss",
    response_model=InsightOut,
    summary="Dismiss an insight",
)
def dismiss_insight(
    db: DbSession,
    ctx: Annotated[RequestContext, Depends(require(Permission.analysis_read))],
    insight_id: uuid.UUID,
    body: DismissRequest,
) -> InsightOut:
    return InsightOut.model_validate(
        intelligence_service.dismiss_insight(db, ctx, insight_id, body.reason)
    )


@router.post(
    "/insights/{insight_id}/restore",
    response_model=InsightOut,
    summary="Restore a dismissed insight",
)
def restore_insight(
    db: DbSession,
    ctx: Annotated[RequestContext, Depends(require(Permission.analysis_read))],
    insight_id: uuid.UUID,
) -> InsightOut:
    return InsightOut.model_validate(intelligence_service.restore_insight(db, ctx, insight_id))


@router.post("/insights/{insight_id}/pin", response_model=InsightOut, summary="Pin an insight")
def pin_insight(
    db: DbSession,
    ctx: Annotated[RequestContext, Depends(require(Permission.analysis_read))],
    insight_id: uuid.UUID,
    body: PinRequest,
) -> InsightOut:
    return InsightOut.model_validate(
        intelligence_service.set_insight_pinned(db, ctx, insight_id, body.pinned)
    )


@router.get("/anomalies", response_model=Page[AnomalyOut], summary="List anomalies")
def list_anomalies(
    db: DbSession,
    ctx: Annotated[RequestContext, Depends(require(Permission.analysis_read))],
    params: Annotated[PageParams, Depends(page_params)],
    case_id: uuid.UUID | None = None,
    evidence_id: uuid.UUID | None = None,
    kind: Annotated[list[AnomalyKind] | None, Query()] = None,
    severity: Annotated[list[Severity] | None, Query()] = None,
    include_dismissed: bool = False,
) -> Page[AnomalyOut]:
    anomalies, total = intelligence_service.list_anomalies(
        db,
        ctx,
        params,
        case_id=case_id,
        evidence_id=evidence_id,
        kinds=kind,
        severities=severity,
        include_dismissed=include_dismissed,
    )
    return Page.build([AnomalyOut.model_validate(anomaly) for anomaly in anomalies], total, params)


@router.post(
    "/anomalies/{anomaly_id}/dismiss",
    response_model=AnomalyOut,
    summary="Dismiss an anomaly",
)
def dismiss_anomaly(
    db: DbSession,
    ctx: Annotated[RequestContext, Depends(require(Permission.analysis_read))],
    anomaly_id: uuid.UUID,
    body: DismissRequest,
) -> AnomalyOut:
    return AnomalyOut.model_validate(
        intelligence_service.dismiss_anomaly(db, ctx, anomaly_id, body.reason)
    )


@router.get(
    "/correlations",
    response_model=Page[CorrelationEdgeOut],
    summary="List correlation edges",
)
def list_correlations(
    db: DbSession,
    ctx: Annotated[RequestContext, Depends(require(Permission.analysis_read))],
    params: Annotated[PageParams, Depends(page_params)],
    case_id: uuid.UUID | None = None,
    evidence_id: uuid.UUID | None = None,
    cross_case_only: bool = False,
    min_score: Annotated[float, Query(ge=0.0, le=1.0)] = 0.0,
) -> Page[CorrelationEdgeOut]:
    views, total = intelligence_service.list_correlations(
        db,
        ctx,
        params,
        case_id=case_id,
        evidence_id=evidence_id,
        cross_case_only=cross_case_only,
        min_score=min_score,
    )
    return Page.build(
        [
            CorrelationEdgeOut(
                id=view.edge.id,
                kind=view.edge.kind,
                score=view.edge.score,
                shared_entity_count=view.edge.shared_entity_count,
                explanation=view.edge.explanation,
                basis=view.edge.basis,
                is_cross_case=view.edge.is_cross_case,
                computed_at=view.edge.computed_at,
                source=EvidenceRef.model_validate(view.source),
                target=EvidenceRef.model_validate(view.target),
                source_case_id=view.edge.source_case_id,
                target_case_id=view.edge.target_case_id,
                restricted=view.restricted,
            )
            for view in views
        ],
        total,
        params,
    )


@router.get(
    "/cases/{case_id}/cross-case-links",
    response_model=list[CrossCaseLinkOut],
    summary="Cases linked to this one",
)
def cross_case_links(
    db: DbSession,
    ctx: Annotated[RequestContext, Depends(require(Permission.analysis_read))],
    case_id: uuid.UUID,
) -> list[CrossCaseLinkOut]:
    return [
        CrossCaseLinkOut.model_validate(entry)
        for entry in intelligence_service.cross_case_summary(db, ctx, case_id)
    ]


@router.get("/entities", response_model=Page[EntitySummaryOut], summary="List entities")
def list_entities(
    db: DbSession,
    ctx: Annotated[RequestContext, Depends(require(Permission.analysis_read))],
    params: Annotated[PageParams, Depends(page_params)],
    case_id: uuid.UUID | None = None,
    type: Annotated[list[EntityType] | None, Query()] = None,
    search: Annotated[str | None, Query(max_length=200)] = None,
    intel_severity: Annotated[list[IndicatorSeverity] | None, Query()] = None,
    min_evidence_count: Annotated[int, Query(ge=1, le=100)] = 1,
) -> Page[EntitySummaryOut]:
    views, total = intelligence_service.list_entities(
        db,
        ctx,
        params,
        case_id=case_id,
        types=type,
        search=search,
        intel_severity=intel_severity,
        min_evidence_count=min_evidence_count,
    )
    return Page.build([_entity_summary(view) for view in views], total, params)


@router.get(
    "/entities/{entity_id}",
    response_model=EntityDetailOut,
    summary="Entity detail with occurrences",
)
def get_entity(
    db: DbSession,
    ctx: Annotated[RequestContext, Depends(require(Permission.analysis_read))],
    entity_id: uuid.UUID,
    case_id: uuid.UUID | None = None,
) -> EntityDetailOut:
    detail = intelligence_service.get_entity(db, ctx, entity_id, case_id=case_id)
    view = intelligence_service.EntityView(
        entity=detail.entity,
        evidence_count=len(detail.evidence),
        occurrence_count=sum(occurrence.occurrence_count for occurrence in detail.occurrences),
        intel_matches=len(detail.indicators),
    )
    return EntityDetailOut(
        entity=_entity_summary(view),
        occurrences=[
            EntityOccurrenceOut.model_validate(occurrence) for occurrence in detail.occurrences
        ],
        evidence=[EvidenceRef.model_validate(item) for item in detail.evidence.values()],
        indicators=[
            ThreatIndicatorOut.model_validate(indicator) for indicator in detail.indicators
        ],
        case_ids=detail.case_ids,
    )


@router.get("/cases/{case_id}/risk", response_model=CaseRiskOut, summary="Case risk breakdown")
def case_risk(
    db: DbSession,
    ctx: Annotated[RequestContext, Depends(require(Permission.analysis_read))],
    case_id: uuid.UUID,
) -> CaseRiskOut:
    return CaseRiskOut.model_validate(intelligence_service.case_risk(db, ctx, case_id))


@router.get(
    "/cases/{case_id}/summary",
    response_model=IntelligenceSummaryOut,
    summary="Intelligence counts for a case",
)
def case_summary(
    db: DbSession,
    ctx: Annotated[RequestContext, Depends(require(Permission.analysis_read))],
    case_id: uuid.UUID,
) -> IntelligenceSummaryOut:
    return IntelligenceSummaryOut.model_validate(
        intelligence_service.intelligence_summary(db, ctx, case_id)
    )


@router.post(
    "/cases/{case_id}/refresh",
    response_model=RefreshQueuedOut,
    summary="Recompute case intelligence",
)
def refresh_case(
    db: DbSession,
    ctx: Annotated[RequestContext, Depends(require(Permission.analysis_run))],
    case_id: uuid.UUID,
) -> RefreshQueuedOut:
    """Queue a full recomputation of this case's intelligence.

    Returns immediately. The dedupe key means a refresh already pending is reported as such rather
    than queued twice, so an impatient click does not multiply the work.
    """
    case = case_service.require_case_access(db, ctx, case_id)
    job = enqueue(
        db,
        "intelligence.refresh_case",
        payload={"case_id": str(case.id)},
        case_id=case.id,
        requested_by_id=ctx.actor_id,
    )
    if job is None:
        return RefreshQueuedOut(
            queued=False,
            job_id=None,
            detail=(
                "A refresh for this case is already queued or running; its results will appear "
                "when it completes."
            ),
        )
    return RefreshQueuedOut(
        queued=True,
        job_id=job.id,
        detail=(
            "Recomputing correlations, anomalies, intelligence matches, insights and risk for "
            f"{case.reference}."
        ),
    )
