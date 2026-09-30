"""Response shapes for the intelligence layer.

Two conventions run through this module and are load-bearing rather than stylistic.

**The observed/interpretation split is visible in the wire format.** ``observed`` and
``interpretation`` are separate fields on :class:`InsightOut`, and ``llm_narrative`` is a third.
A client cannot accidentally render an inference as a fact, because it never receives them joined.

**Every derived number carries its arithmetic.** Anomalies expose ``method``, ``threshold``,
``observed_value``, ``baseline_value`` and ``sample_size``; correlation edges expose their full
``basis``; risk exposes per-component points. The interface is therefore able to show *why*, which
is what separates a forensic tool from a black box that emits numbers.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from app.models.enums import (
    AnomalyKind,
    CorrelationKind,
    EntityType,
    IndicatorSeverity,
    IndicatorType,
    InsightKind,
    InsightProvenance,
    Severity,
)
from app.schemas.common import ActorRef, EvidenceRef, ORMModel


class InsightOut(ORMModel):
    """An insight, with fact and inference kept in separate fields."""

    id: uuid.UUID
    case_id: uuid.UUID | None
    kind: InsightKind
    provenance: InsightProvenance
    severity: Severity
    confidence: float

    title: str
    observed: str
    interpretation: str | None
    llm_narrative: str | None
    llm_model: str | None

    evidence_refs: list[dict[str, Any]]
    entity_refs: list[dict[str, Any]]
    case_refs: list[dict[str, Any]]
    basis: dict[str, Any]

    rank_score: float
    generator: str
    generator_version: str

    is_pinned: bool
    dismissed_at: datetime | None
    dismissed_reason: str | None
    dismissed_by: ActorRef | None = None
    created_at: datetime
    updated_at: datetime


class DismissRequest(BaseModel):
    """A dismissal, which is a recorded judgement and therefore needs a reason."""

    reason: str = Field(min_length=3, max_length=2000)


class PinRequest(BaseModel):
    pinned: bool = True


class AnomalyOut(ORMModel):
    """An anomaly, published with the measurement that produced it."""

    id: uuid.UUID
    case_id: uuid.UUID | None
    evidence_id: uuid.UUID | None
    kind: AnomalyKind
    severity: Severity

    title: str
    description: str

    method: str
    threshold: float | None
    observed_value: float | None
    baseline_value: float | None
    deviation: float | None
    sample_size: int | None

    window_start: datetime | None
    window_end: datetime | None

    detector: str
    detector_version: str
    attributes: dict[str, Any]

    dismissed_at: datetime | None
    dismissed_reason: str | None
    created_at: datetime


class CorrelationEdgeOut(BaseModel):
    """A scored link between two artifacts, with both endpoints resolved."""

    id: uuid.UUID
    kind: CorrelationKind
    score: float
    shared_entity_count: int
    explanation: str
    basis: dict[str, Any]
    is_cross_case: bool
    computed_at: datetime

    source: EvidenceRef
    target: EvidenceRef
    source_case_id: uuid.UUID
    target_case_id: uuid.UUID
    #: True when one endpoint sits in a case the caller cannot access. The link is reported so it
    #: can be escalated; the inaccessible case's contents are not.
    restricted: bool


class CrossCaseLinkOut(BaseModel):
    """Another investigation connected to this one by shared indicators."""

    case_id: uuid.UUID | None
    reference: str | None
    title: str | None
    status: str | None = None
    severity: str | None = None
    incident_type: str | None = None
    accessible: bool
    edge_count: int
    max_score: float
    shared_indicator_count: int
    shared_indicators: list[str]
    detail: str | None = None


class EntitySummaryOut(BaseModel):
    """An entity with its footprint inside the requested scope."""

    id: uuid.UUID
    type: EntityType
    canonical_value: str
    display_value: str
    label: str | None

    first_seen_at: datetime | None
    last_seen_at: datetime | None

    #: Counts within the caller's visible scope, not corpus-wide.
    evidence_count: int
    occurrence_count: int

    #: Corpus-wide rarity, which is what makes a value significant. Safe to publish because it is
    #: an aggregate that names no case.
    document_frequency: int
    case_count: int

    intel_severity: IndicatorSeverity | None
    intel_tags: list[Any]
    intel_checked_at: datetime | None
    intel_match_count: int


class EntityOccurrenceOut(ORMModel):
    """Where in an artifact an entity was found."""

    id: uuid.UUID
    evidence_id: uuid.UUID
    case_id: uuid.UUID
    analyzer: str
    analyzer_version: str
    #: Structured pointer into the artifact - line number, EXIF tag, header name - so the interface
    #: can take a reader to the exact place the value came from.
    locator: dict[str, Any]
    excerpt: str | None
    context: str | None
    confidence: float
    occurrence_count: int
    created_at: datetime


class ThreatIndicatorOut(ORMModel):
    """An intelligence record about a value, attributed to its source."""

    id: uuid.UUID
    type: IndicatorType
    canonical_value: str
    severity: IndicatorSeverity
    confidence: float
    source: str
    source_reference: str | None
    description: str
    tags: list[Any]
    threat_actor: str | None
    malware_family: str | None
    first_seen_at: datetime | None
    last_seen_at: datetime | None
    expires_at: datetime | None
    is_active: bool


class EntityDetailOut(BaseModel):
    entity: EntitySummaryOut
    occurrences: list[EntityOccurrenceOut]
    evidence: list[EvidenceRef]
    indicators: list[ThreatIndicatorOut]
    case_ids: list[uuid.UUID]


class RiskComponentOut(BaseModel):
    key: str
    label: str
    points: float
    cap: float
    rationale: str
    inputs: dict[str, Any]


class RiskSnapshotOut(BaseModel):
    score: float
    recorded_at: datetime
    model_version: str
    band: str | None


class CaseRiskOut(BaseModel):
    """A risk score, published only alongside the components that produced it."""

    case_id: uuid.UUID
    case_reference: str
    score: float
    band: str
    breakdown: dict[str, Any]
    cached_score: float | None
    cached_at: datetime | None
    history: list[RiskSnapshotOut]


class IntelligenceSummaryOut(BaseModel):
    """Header counts for a case workspace."""

    case_id: uuid.UUID
    insights: dict[str, int]
    insight_total: int
    anomalies: dict[str, int]
    anomaly_total: int
    cross_case_edges: int
    malicious_indicators: int
    distinct_entities: int
    risk_score: float | None
    risk_computed_at: datetime | None


class RefreshQueuedOut(BaseModel):
    """Acknowledgement that recomputation was queued rather than performed inline."""

    queued: bool
    job_id: uuid.UUID | None
    detail: str
