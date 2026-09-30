"""Reads and analyst actions over the intelligence layer.

Every query here starts from a case the actor is allowed to see. Insights, anomalies, correlation
edges and entity occurrences all carry a ``case_id``, and each one is filtered through the same
SQL scoping used everywhere else - because intelligence output *summarises* evidence, and an insight
that quotes an out-of-scope artifact's reference and shared indicators would disclose exactly what
case scoping exists to protect.

Cross-case links need particular care. Their whole purpose is to point at another investigation, so
the endpoint reports the *existence* of a link and the shared indicators that justify it, while
withholding the other case's identity from an actor with no access to it. An investigator learning
"three of your indicators also appear in a case you cannot see" can escalate to someone who can look
at both; being handed that case's contents would defeat the access model entirely.

Analyst actions are limited to dismissing and pinning. Nothing here can edit an insight's facts:
those are written by the deterministic generators and must stay reproducible from the evidence.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any

from sqlalchemy import Select, func, or_, select
from sqlalchemy.orm import Session

from app.core.clock import utcnow
from app.core.context import RequestContext
from app.core.errors import NotFound, ValidationFailed
from app.core.logging import get_logger
from app.core.pagination import PageParams, paginate
from app.intelligence import risk
from app.models.analysis import (
    Anomaly,
    CaseRiskSnapshot,
    CorrelationEdge,
    Entity,
    EntityOccurrence,
    Insight,
)
from app.models.case import Case
from app.models.enums import (
    AnomalyKind,
    EntityType,
    IndicatorSeverity,
    InsightKind,
    Severity,
)
from app.models.evidence import Evidence
from app.models.intel import IndicatorMatch, ThreatIndicator
from app.security.scoping import accessible_case_ids, has_global_case_access, scope_case_ids
from app.services import case_service

logger = get_logger(__name__)


def list_insights(
    db: Session,
    ctx: RequestContext,
    params: PageParams,
    *,
    case_id: uuid.UUID | None = None,
    kinds: list[InsightKind] | None = None,
    severities: list[Severity] | None = None,
    include_dismissed: bool = False,
    pinned_only: bool = False,
) -> tuple[list[Insight], int]:
    """Insights the actor may see, highest-ranked first."""
    stmt = scope_case_ids(select(Insight), ctx, Insight.case_id)

    if case_id is not None:
        case_service.require_case_access(db, ctx, case_id)
        stmt = stmt.where(Insight.case_id == case_id)
    if kinds:
        stmt = stmt.where(Insight.kind.in_(kinds))
    if severities:
        stmt = stmt.where(Insight.severity.in_(severities))
    if not include_dismissed:
        stmt = stmt.where(Insight.dismissed_at.is_(None))
    if pinned_only:
        stmt = stmt.where(Insight.is_pinned.is_(True))

    # Pinned first, then by rank: a pin is an investigator saying "this one matters", which must
    # outrank the engine's own ordering.
    stmt = stmt.order_by(
        Insight.is_pinned.desc(), Insight.rank_score.desc(), Insight.created_at.desc()
    )
    return paginate(db, stmt, params)


def get_insight(db: Session, ctx: RequestContext, insight_id: uuid.UUID) -> Insight:
    stmt = scope_case_ids(select(Insight).where(Insight.id == insight_id), ctx, Insight.case_id)
    insight = db.execute(stmt).scalar_one_or_none()
    if insight is None:
        raise NotFound("Insight", str(insight_id))
    return insight


def dismiss_insight(
    db: Session, ctx: RequestContext, insight_id: uuid.UUID, reason: str
) -> Insight:
    """Dismiss an insight, recording who dismissed it and why.

    A reason is mandatory. Dismissal is a judgement that survives regeneration and suppresses the
    item from every subsequent view, so the next person to look needs to know on what basis - an
    unexplained dismissal is indistinguishable from something being missed.
    """
    if not reason.strip():
        raise ValidationFailed("A reason is required when dismissing an insight.")

    insight = get_insight(db, ctx, insight_id)
    insight.dismissed_at = utcnow()
    insight.dismissed_by_id = ctx.actor_id
    insight.dismissed_reason = reason.strip()
    insight.is_pinned = False
    db.flush()

    logger.info(
        "insight_dismissed",
        insight_id=str(insight.id),
        kind=insight.kind.value,
        actor_id=str(ctx.actor_id),
    )
    return insight


def restore_insight(db: Session, ctx: RequestContext, insight_id: uuid.UUID) -> Insight:
    insight = get_insight(db, ctx, insight_id)
    insight.dismissed_at = None
    insight.dismissed_by_id = None
    insight.dismissed_reason = None
    db.flush()
    return insight


def set_insight_pinned(
    db: Session, ctx: RequestContext, insight_id: uuid.UUID, pinned: bool
) -> Insight:
    """Pin or unpin an insight.

    A pinned insight also survives regeneration even when its supporting facts stop reproducing,
    which is deliberate: if an investigator marked it as significant, its disappearance should be
    something they notice and decide about, not something the engine does quietly.
    """
    insight = get_insight(db, ctx, insight_id)
    insight.is_pinned = pinned
    db.flush()
    return insight


def list_anomalies(
    db: Session,
    ctx: RequestContext,
    params: PageParams,
    *,
    case_id: uuid.UUID | None = None,
    kinds: list[AnomalyKind] | None = None,
    severities: list[Severity] | None = None,
    evidence_id: uuid.UUID | None = None,
    include_dismissed: bool = False,
) -> tuple[list[Anomaly], int]:
    stmt = scope_case_ids(select(Anomaly), ctx, Anomaly.case_id)

    if case_id is not None:
        case_service.require_case_access(db, ctx, case_id)
        stmt = stmt.where(Anomaly.case_id == case_id)
    if evidence_id is not None:
        stmt = stmt.where(Anomaly.evidence_id == evidence_id)
    if kinds:
        stmt = stmt.where(Anomaly.kind.in_(kinds))
    if severities:
        stmt = stmt.where(Anomaly.severity.in_(severities))
    if not include_dismissed:
        stmt = stmt.where(Anomaly.dismissed_at.is_(None))

    stmt = stmt.order_by(Anomaly.severity.desc(), Anomaly.created_at.desc())
    return paginate(db, stmt, params)


def dismiss_anomaly(
    db: Session, ctx: RequestContext, anomaly_id: uuid.UUID, reason: str
) -> Anomaly:
    """Dismiss an anomaly as explained or not relevant."""
    if not reason.strip():
        raise ValidationFailed("A reason is required when dismissing an anomaly.")

    stmt = scope_case_ids(select(Anomaly).where(Anomaly.id == anomaly_id), ctx, Anomaly.case_id)
    anomaly = db.execute(stmt).scalar_one_or_none()
    if anomaly is None:
        raise NotFound("Anomaly", str(anomaly_id))

    anomaly.dismissed_at = utcnow()
    anomaly.dismissed_by_id = ctx.actor_id
    anomaly.dismissed_reason = reason.strip()
    db.flush()

    logger.info("anomaly_dismissed", anomaly_id=str(anomaly.id), actor_id=str(ctx.actor_id))
    return anomaly


@dataclass(frozen=True, slots=True)
class CorrelationView:
    """A correlation edge with both endpoints resolved for display."""

    edge: CorrelationEdge
    source: Evidence
    target: Evidence
    #: Set when the other side of the edge is in a case the actor cannot see. The link is still
    #: reported, because knowing a connection exists is what lets an investigator escalate, but the
    #: other case's details are withheld.
    restricted: bool


def list_correlations(
    db: Session,
    ctx: RequestContext,
    params: PageParams,
    *,
    case_id: uuid.UUID | None = None,
    evidence_id: uuid.UUID | None = None,
    cross_case_only: bool = False,
    min_score: float = 0.0,
) -> tuple[list[CorrelationView], int]:
    """Correlation edges with at least one endpoint the actor may see."""
    stmt = select(CorrelationEdge)

    if not has_global_case_access(ctx):
        visible = accessible_case_ids(ctx)
        stmt = stmt.where(
            or_(
                CorrelationEdge.source_case_id.in_(visible),
                CorrelationEdge.target_case_id.in_(visible),
            )
        )

    if case_id is not None:
        case_service.require_case_access(db, ctx, case_id)
        stmt = stmt.where(
            or_(
                CorrelationEdge.source_case_id == case_id,
                CorrelationEdge.target_case_id == case_id,
            )
        )
    if evidence_id is not None:
        stmt = stmt.where(
            or_(
                CorrelationEdge.source_evidence_id == evidence_id,
                CorrelationEdge.target_evidence_id == evidence_id,
            )
        )
    if cross_case_only:
        stmt = stmt.where(CorrelationEdge.is_cross_case.is_(True))
    if min_score > 0:
        stmt = stmt.where(CorrelationEdge.score >= min_score)

    stmt = stmt.order_by(CorrelationEdge.score.desc())
    edges, total = paginate(db, stmt, params)

    visible_cases = _visible_case_ids(db, ctx, edges)
    views: list[CorrelationView] = []
    for edge in edges:
        source = db.get(Evidence, edge.source_evidence_id)
        target = db.get(Evidence, edge.target_evidence_id)
        if source is None or target is None:  # pragma: no cover - FK cascade
            continue
        views.append(
            CorrelationView(
                edge=edge,
                source=source,
                target=target,
                restricted=not (
                    edge.source_case_id in visible_cases and edge.target_case_id in visible_cases
                ),
            )
        )
    return views, total


def _visible_case_ids(
    db: Session, ctx: RequestContext, edges: list[CorrelationEdge]
) -> set[uuid.UUID]:
    """Which of these edges' cases the actor may actually see."""
    if has_global_case_access(ctx):
        return {case_id for edge in edges for case_id in (edge.source_case_id, edge.target_case_id)}
    referenced = {
        case_id for edge in edges for case_id in (edge.source_case_id, edge.target_case_id)
    }
    if not referenced:
        return set()
    return set(
        db.scalars(
            select(Case.id).where(Case.id.in_(referenced), Case.id.in_(accessible_case_ids(ctx)))
        ).all()
    )


def cross_case_summary(
    db: Session, ctx: RequestContext, case_id: uuid.UUID
) -> list[dict[str, Any]]:
    """Cases linked to this one, with the other case's identity withheld where necessary."""
    case_service.require_case_access(db, ctx, case_id)

    edges = db.scalars(
        select(CorrelationEdge)
        .where(
            CorrelationEdge.is_cross_case.is_(True),
            or_(
                CorrelationEdge.source_case_id == case_id,
                CorrelationEdge.target_case_id == case_id,
            ),
        )
        .order_by(CorrelationEdge.score.desc())
    ).all()
    if not edges:
        return []

    grouped: dict[uuid.UUID, list[CorrelationEdge]] = {}
    for edge in edges:
        other_id = edge.target_case_id if edge.source_case_id == case_id else edge.source_case_id
        grouped.setdefault(other_id, []).append(edge)

    accessible = (
        set(grouped)
        if has_global_case_access(ctx)
        else set(
            db.scalars(
                select(Case.id).where(
                    Case.id.in_(grouped.keys()), Case.id.in_(accessible_case_ids(ctx))
                )
            ).all()
        )
    )

    summaries: list[dict[str, Any]] = []
    for other_case_id, case_edges in grouped.items():
        shared = {
            str(term.get("value"))
            for edge in case_edges
            for term in edge.basis.get("shared_terms", [])
        }
        entry: dict[str, Any] = {
            "edge_count": len(case_edges),
            "max_score": max(edge.score for edge in case_edges),
            "shared_indicator_count": len(shared),
            "shared_indicators": sorted(shared)[:20],
            "accessible": other_case_id in accessible,
        }
        if other_case_id in accessible:
            linked_case = db.get(Case, other_case_id)
            if linked_case is not None:
                entry |= {
                    "case_id": str(linked_case.id),
                    "reference": linked_case.reference,
                    "title": linked_case.title,
                    "status": linked_case.status.value,
                    "severity": linked_case.severity.value,
                    "incident_type": linked_case.incident_type.value,
                }
        else:
            # Deliberately withheld: the actor learns a link exists and on what indicators, and
            # can escalate to someone with access to both cases.
            entry |= {
                "case_id": None,
                "reference": None,
                "title": None,
                "detail": (
                    "This case shares indicators with an investigation you do not have access "
                    "to. Contact a supervisor or an auditor to have the connection reviewed."
                ),
            }
        summaries.append(entry)

    return sorted(summaries, key=lambda item: item["max_score"], reverse=True)


@dataclass(frozen=True, slots=True)
class EntityView:
    """An entity as it appears within a case, with its case-local footprint."""

    entity: Entity
    evidence_count: int
    occurrence_count: int
    intel_matches: int


def list_entities(
    db: Session,
    ctx: RequestContext,
    params: PageParams,
    *,
    case_id: uuid.UUID | None = None,
    types: list[EntityType] | None = None,
    search: str | None = None,
    intel_severity: list[IndicatorSeverity] | None = None,
    min_evidence_count: int = 1,
) -> tuple[list[EntityView], int]:
    """Entities extracted from evidence the actor may see.

    Counts are computed over scoped occurrences rather than read from the denormalised counters on
    ``entities``, which are corpus-wide. Showing a corpus-wide count on a case page would both
    mislead and leak: "this address appears in 14 items" tells an investigator about 13 artifacts
    they may have no access to.
    """
    occurrence_scope = scope_case_ids(
        select(EntityOccurrence.entity_id), ctx, EntityOccurrence.case_id
    )
    if case_id is not None:
        case_service.require_case_access(db, ctx, case_id)
        occurrence_scope = occurrence_scope.where(EntityOccurrence.case_id == case_id)

    counts = (
        occurrence_scope.add_columns(
            func.count(func.distinct(EntityOccurrence.evidence_id)).label("evidence_count"),
            func.sum(EntityOccurrence.occurrence_count).label("occurrence_count"),
        )
        .group_by(EntityOccurrence.entity_id)
        .subquery()
    )

    stmt: Select[Any] = (
        select(
            Entity,
            counts.c.evidence_count,
            counts.c.occurrence_count,
        )
        .join(counts, counts.c.entity_id == Entity.id)
        .where(counts.c.evidence_count >= min_evidence_count)
    )

    if types:
        stmt = stmt.where(Entity.type.in_(types))
    if intel_severity:
        stmt = stmt.where(Entity.intel_severity.in_(intel_severity))
    if search:
        stmt = stmt.where(Entity.canonical_value.ilike(f"%{search.strip().lower()}%"))

    stmt = stmt.order_by(counts.c.evidence_count.desc(), Entity.canonical_value)

    count_stmt = select(func.count()).select_from(stmt.order_by(None).subquery())
    total = int(db.execute(count_stmt).scalar_one())
    rows = db.execute(stmt.limit(params.size).offset(params.offset)).all()

    entity_ids = [row[0].id for row in rows]
    match_counts = _intel_match_counts(db, ctx, entity_ids, case_id=case_id)

    return [
        EntityView(
            entity=row[0],
            evidence_count=int(row[1] or 0),
            occurrence_count=int(row[2] or 0),
            intel_matches=match_counts.get(row[0].id, 0),
        )
        for row in rows
    ], total


def _intel_match_counts(
    db: Session,
    ctx: RequestContext,
    entity_ids: list[uuid.UUID],
    *,
    case_id: uuid.UUID | None,
) -> dict[uuid.UUID, int]:
    if not entity_ids:
        return {}
    stmt = scope_case_ids(
        select(IndicatorMatch.entity_id, func.count(func.distinct(IndicatorMatch.indicator_id)))
        .where(IndicatorMatch.entity_id.in_(entity_ids))
        .group_by(IndicatorMatch.entity_id),
        ctx,
        IndicatorMatch.case_id,
    )
    if case_id is not None:
        stmt = stmt.where(IndicatorMatch.case_id == case_id)
    return {entity_id: int(count) for entity_id, count in db.execute(stmt).all()}


@dataclass(frozen=True, slots=True)
class EntityDetail:
    """An entity with the artifacts it was found in and any intelligence on it."""

    entity: Entity
    occurrences: list[EntityOccurrence]
    evidence: dict[uuid.UUID, Evidence]
    indicators: list[ThreatIndicator]
    case_ids: list[uuid.UUID]


def get_entity(
    db: Session,
    ctx: RequestContext,
    entity_id: uuid.UUID,
    *,
    case_id: uuid.UUID | None = None,
) -> EntityDetail:
    """One entity, with every scoped occurrence and its intelligence record.

    Reported as not found when the actor can see no occurrence of it. Distinguishing "no such
    entity" from "an entity you may not see" would turn this endpoint into an oracle for probing
    whether a given address or wallet appears anywhere in the platform.
    """
    entity = db.get(Entity, entity_id)
    if entity is None:
        raise NotFound("Entity", str(entity_id))

    stmt = scope_case_ids(
        select(EntityOccurrence).where(EntityOccurrence.entity_id == entity_id),
        ctx,
        EntityOccurrence.case_id,
    )
    if case_id is not None:
        case_service.require_case_access(db, ctx, case_id)
        stmt = stmt.where(EntityOccurrence.case_id == case_id)

    occurrences = list(db.scalars(stmt.order_by(EntityOccurrence.created_at)).all())
    if not occurrences:
        raise NotFound("Entity", str(entity_id))

    evidence_ids = {occurrence.evidence_id for occurrence in occurrences}
    evidence = {
        item.id: item
        for item in db.scalars(select(Evidence).where(Evidence.id.in_(evidence_ids))).all()
    }

    indicators = list(
        db.scalars(
            select(ThreatIndicator)
            .join(IndicatorMatch, IndicatorMatch.indicator_id == ThreatIndicator.id)
            .where(IndicatorMatch.entity_id == entity_id)
            .distinct()
        ).all()
    )

    return EntityDetail(
        entity=entity,
        occurrences=occurrences,
        evidence=evidence,
        indicators=indicators,
        case_ids=sorted({occurrence.case_id for occurrence in occurrences}, key=str),
    )


def case_risk(db: Session, ctx: RequestContext, case_id: uuid.UUID) -> dict[str, Any]:
    """The case's current risk score, its breakdown and its history.

    Recomputed live rather than read from the cached column, so the breakdown always matches the
    evidence as it stands. Snapshots supply the history, which is what makes a score quoted in an
    earlier report explicable later.
    """
    case = case_service.require_case_access(db, ctx, case_id)
    assessment = risk.assess_case(db, case)

    history = db.scalars(
        select(CaseRiskSnapshot)
        .where(CaseRiskSnapshot.case_id == case_id)
        .order_by(CaseRiskSnapshot.created_at.desc())
        .limit(30)
    ).all()

    return {
        "case_id": str(case.id),
        "case_reference": case.reference,
        "score": assessment.score,
        "band": assessment.band,
        "breakdown": assessment.as_breakdown(),
        "cached_score": float(case.risk_score) if case.risk_score is not None else None,
        "cached_at": case.risk_computed_at,
        "history": [
            {
                "score": float(snapshot.score),
                "recorded_at": snapshot.created_at,
                "model_version": snapshot.model_version,
                "band": snapshot.breakdown.get("band"),
            }
            for snapshot in history
        ],
    }


def intelligence_summary(db: Session, ctx: RequestContext, case_id: uuid.UUID) -> dict[str, Any]:
    """Counts for the case workspace header: what the intelligence layer currently holds."""
    case = case_service.require_case_access(db, ctx, case_id)

    insight_rows = db.execute(
        select(Insight.severity, func.count())
        .where(Insight.case_id == case_id, Insight.dismissed_at.is_(None))
        .group_by(Insight.severity)
    ).all()
    anomaly_rows = db.execute(
        select(Anomaly.severity, func.count())
        .where(Anomaly.case_id == case_id, Anomaly.dismissed_at.is_(None))
        .group_by(Anomaly.severity)
    ).all()

    cross_case = int(
        db.scalar(
            select(func.count())
            .select_from(CorrelationEdge)
            .where(
                CorrelationEdge.is_cross_case.is_(True),
                or_(
                    CorrelationEdge.source_case_id == case_id,
                    CorrelationEdge.target_case_id == case_id,
                ),
            )
        )
        or 0
    )
    malicious = int(
        db.scalar(
            select(func.count(func.distinct(IndicatorMatch.entity_id)))
            .join(ThreatIndicator, ThreatIndicator.id == IndicatorMatch.indicator_id)
            .where(
                IndicatorMatch.case_id == case_id,
                ThreatIndicator.severity == IndicatorSeverity.malicious,
            )
        )
        or 0
    )
    entities = int(
        db.scalar(
            select(func.count(func.distinct(EntityOccurrence.entity_id))).where(
                EntityOccurrence.case_id == case_id
            )
        )
        or 0
    )

    return {
        "case_id": str(case.id),
        "insights": {severity.value: count for severity, count in insight_rows},
        "insight_total": sum(count for _severity, count in insight_rows),
        "anomalies": {severity.value: count for severity, count in anomaly_rows},
        "anomaly_total": sum(count for _severity, count in anomaly_rows),
        "cross_case_edges": cross_case,
        "malicious_indicators": malicious,
        "distinct_entities": entities,
        "risk_score": float(case.risk_score) if case.risk_score is not None else None,
        "risk_computed_at": case.risk_computed_at,
    }
