"""Analysis, correlation and intelligence models.

The central design decision is that **every extracted fact carries its provenance**. An
:class:`EntityOccurrence` or :class:`Observation` always records which analyzer produced it,
at which analyzer version, where inside the artifact it was found (``locator``) and the
surrounding text (``excerpt``). That is what allows the interface to answer "how do you know
this?" by pointing at a byte offset in a specific artifact, and it is what makes the
separation between observed fact and interpretation meaningful rather than cosmetic.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    Numeric,
    String,
    Table,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, CreatedAtMixin, TimestampMixin, UUIDPrimaryKey
from app.models.enums import (
    AnalysisStatus,
    AnomalyKind,
    Confidence,
    CorrelationKind,
    EntityType,
    IndicatorSeverity,
    InsightKind,
    InsightProvenance,
    ObservationKind,
    Severity,
    enum_type,
)

if TYPE_CHECKING:
    from app.models.case import Case
    from app.models.evidence import Evidence
    from app.models.user import User

observation_entities = Table(
    "observation_entities",
    Base.metadata,
    Column("observation_id", ForeignKey("observations.id", ondelete="CASCADE"), primary_key=True),
    Column("entity_id", ForeignKey("entities.id", ondelete="CASCADE"), primary_key=True),
    Column("role", String(32), nullable=False, server_default="involved"),
)


class AnalysisRun(UUIDPrimaryKey, Base):
    """One analyzer execution against one evidence version.

    ``analyzer_version`` is recorded so results remain interpretable after an analyzer is
    improved: a finding produced by v1 is not silently presented as though v2 produced it.
    """

    __tablename__ = "analysis_runs"
    __table_args__ = (Index("ix_analysis_runs_evidence_analyzer", "evidence_id", "analyzer"),)

    evidence_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("evidence.id", ondelete="CASCADE"), nullable=False, index=True
    )
    case_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True
    )
    evidence_version_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("evidence_versions.id", ondelete="SET NULL")
    )

    analyzer: Mapped[str] = mapped_column(String(64), nullable=False)
    analyzer_version: Mapped[str] = mapped_column(String(16), nullable=False)
    status: Mapped[AnalysisStatus] = mapped_column(
        enum_type(AnalysisStatus), nullable=False, default=AnalysisStatus.pending
    )

    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    duration_ms: Mapped[int | None] = mapped_column(Integer)
    bytes_examined: Mapped[int | None] = mapped_column(BigInteger)

    entity_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    observation_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    finding_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    error: Mapped[str | None] = mapped_column(Text)
    skip_reason: Mapped[str | None] = mapped_column(String(240))
    summary: Mapped[dict[str, Any]] = mapped_column(nullable=False, default=dict)

    requested_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    evidence: Mapped[Evidence] = relationship(back_populates="analysis_runs")


class Entity(UUIDPrimaryKey, TimestampMixin, Base):
    """A globally unique indicator or actor observed across the corpus.

    Uniqueness on ``(type, canonical_value)`` is what makes correlation possible: the same
    address seen in a log and in an email resolves to one row, so "which artifacts share
    this?" is a join rather than a text search.

    ``document_frequency`` (how many evidence items contain this entity) is maintained so
    correlation can weight by rarity - a value present in almost every artifact carries
    almost no investigative signal, and must not be scored as though it did.
    """

    __tablename__ = "entities"
    __table_args__ = (
        UniqueConstraint("type", "canonical_value", name="uq_entities_type_canonical_value"),
        Index(
            "ix_entities_value_trgm",
            "canonical_value",
            postgresql_using="gin",
            postgresql_ops={"canonical_value": "gin_trgm_ops"},
        ),
    )

    type: Mapped[EntityType] = mapped_column(enum_type(EntityType), nullable=False, index=True)
    # Normalised for comparison: lowercased, trimmed, IDN/IPv6 canonicalised.
    canonical_value: Mapped[str] = mapped_column(String(512), nullable=False)
    # As it appeared, for display and for quoting in reports.
    display_value: Mapped[str] = mapped_column(String(512), nullable=False)
    label: Mapped[str | None] = mapped_column(String(240))

    first_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    occurrence_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    document_frequency: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    case_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # Threat-intelligence annotation, populated by the intel providers.
    intel_severity: Mapped[IndicatorSeverity | None] = mapped_column(enum_type(IndicatorSeverity))
    intel_tags: Mapped[list[Any]] = mapped_column(nullable=False, default=list)
    intel_checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    attributes: Mapped[dict[str, Any]] = mapped_column(nullable=False, default=dict)

    occurrences: Mapped[list[EntityOccurrence]] = relationship(
        back_populates="entity", cascade="all, delete-orphan"
    )


class EntityOccurrence(UUIDPrimaryKey, CreatedAtMixin, Base):
    """One sighting of an entity inside one evidence item, with its exact location."""

    __tablename__ = "entity_occurrences"
    __table_args__ = (
        Index("ix_entity_occurrences_entity_evidence", "entity_id", "evidence_id"),
        Index("ix_entity_occurrences_case", "case_id"),
    )

    entity_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("entities.id", ondelete="CASCADE"), nullable=False, index=True
    )
    evidence_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("evidence.id", ondelete="CASCADE"), nullable=False, index=True
    )
    case_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("cases.id", ondelete="CASCADE"), nullable=False
    )
    analysis_run_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("analysis_runs.id", ondelete="SET NULL")
    )

    analyzer: Mapped[str] = mapped_column(String(64), nullable=False)
    analyzer_version: Mapped[str] = mapped_column(String(16), nullable=False)

    # Where exactly: {"byte_offset": 4096, "line": 82, "field": "Received[2]", "page": 3}
    locator: Mapped[dict[str, Any]] = mapped_column(nullable=False, default=dict)
    # Surrounding text proving the sighting. Redacted from logs (see app.core.logging).
    excerpt: Mapped[str | None] = mapped_column(Text)
    context: Mapped[str | None] = mapped_column(String(160))
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    occurrence_count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    entity: Mapped[Entity] = relationship(back_populates="occurrences")
    evidence: Mapped[Evidence] = relationship(back_populates="entity_occurrences")


class Observation(UUIDPrimaryKey, CreatedAtMixin, Base):
    """A timestamped event extracted from evidence content.

    Observations are the raw material of the reconstructed timeline. ``occurred_at`` comes
    from the artifact itself and is therefore untrusted: ``time_confidence`` and
    ``timezone_assumed`` record how much weight it can bear, because many log formats omit
    the offset entirely and a timeline that silently guesses is worse than one that admits it.
    """

    __tablename__ = "observations"
    __table_args__ = (
        Index("ix_observations_case_occurred", "case_id", "occurred_at"),
        Index("ix_observations_evidence_occurred", "evidence_id", "occurred_at"),
        Index("ix_observations_kind", "kind"),
    )

    evidence_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("evidence.id", ondelete="CASCADE"), nullable=False
    )
    case_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("cases.id", ondelete="CASCADE"), nullable=False
    )
    analysis_run_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("analysis_runs.id", ondelete="SET NULL")
    )

    kind: Mapped[ObservationKind] = mapped_column(enum_type(ObservationKind), nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    time_confidence: Mapped[Confidence] = mapped_column(
        enum_type(Confidence), nullable=False, default=Confidence.high
    )
    timezone_assumed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    summary: Mapped[str] = mapped_column(String(400), nullable=False)
    actor_value: Mapped[str | None] = mapped_column(String(255))
    source_value: Mapped[str | None] = mapped_column(String(255))
    target_value: Mapped[str | None] = mapped_column(String(255))
    outcome: Mapped[str | None] = mapped_column(String(48))

    analyzer: Mapped[str] = mapped_column(String(64), nullable=False)
    analyzer_version: Mapped[str] = mapped_column(String(16), nullable=False)
    locator: Mapped[dict[str, Any]] = mapped_column(nullable=False, default=dict)
    excerpt: Mapped[str | None] = mapped_column(Text)
    attributes: Mapped[dict[str, Any]] = mapped_column(nullable=False, default=dict)

    evidence: Mapped[Evidence] = relationship(back_populates="observations")
    entities: Mapped[list[Entity]] = relationship(secondary=observation_entities)


class AnalysisFinding(UUIDPrimaryKey, CreatedAtMixin, Base):
    """A technical finding produced by an analyzer.

    Distinct from :class:`~app.models.case.Finding`, which a human authors. Keeping them in
    separate tables means a report can never blur what the tool detected with what the
    investigator concluded.
    """

    __tablename__ = "analysis_findings"
    __table_args__ = (Index("ix_analysis_findings_case_code", "case_id", "code"),)

    evidence_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("evidence.id", ondelete="CASCADE"), nullable=False, index=True
    )
    case_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("cases.id", ondelete="CASCADE"), nullable=False
    )
    analysis_run_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("analysis_runs.id", ondelete="SET NULL")
    )

    # Stable machine code, e.g. "email.return_path_mismatch", "file.mime_mismatch".
    code: Mapped[str] = mapped_column(String(96), nullable=False)
    title: Mapped[str] = mapped_column(String(240), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[Severity] = mapped_column(
        enum_type(Severity), nullable=False, default=Severity.informational
    )
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)

    analyzer: Mapped[str] = mapped_column(String(64), nullable=False)
    analyzer_version: Mapped[str] = mapped_column(String(16), nullable=False)
    locator: Mapped[dict[str, Any]] = mapped_column(nullable=False, default=dict)
    excerpt: Mapped[str | None] = mapped_column(Text)
    attributes: Mapped[dict[str, Any]] = mapped_column(nullable=False, default=dict)

    evidence: Mapped[Evidence] = relationship()


class CorrelationEdge(UUIDPrimaryKey, Base):
    """A scored, explained relationship between two evidence items.

    ``basis`` records precisely why the edge exists - which entities were shared, their
    rarity weights, the time delta - so the interface can justify the link instead of
    asserting it. Evidence ids are stored in a canonical order (lower UUID first) so an
    undirected relationship cannot be recorded twice.
    """

    __tablename__ = "correlation_edges"
    __table_args__ = (
        UniqueConstraint(
            "source_evidence_id",
            "target_evidence_id",
            "kind",
            name="uq_correlation_edges_source_target_kind",
        ),
        Index("ix_correlation_edges_score", "score"),
        Index("ix_correlation_edges_cross_case", "is_cross_case"),
    )

    kind: Mapped[CorrelationKind] = mapped_column(enum_type(CorrelationKind), nullable=False)
    source_evidence_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("evidence.id", ondelete="CASCADE"), nullable=False, index=True
    )
    target_evidence_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("evidence.id", ondelete="CASCADE"), nullable=False, index=True
    )
    source_case_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True
    )
    target_case_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True
    )
    is_cross_case: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    shared_entity_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    basis: Mapped[dict[str, Any]] = mapped_column(nullable=False, default=dict)
    explanation: Mapped[str] = mapped_column(Text, nullable=False, default="")

    computed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    computer_version: Mapped[str] = mapped_column(String(16), nullable=False, default="1")

    source_evidence: Mapped[Evidence] = relationship(foreign_keys=[source_evidence_id])
    target_evidence: Mapped[Evidence] = relationship(foreign_keys=[target_evidence_id])


class Anomaly(UUIDPrimaryKey, CreatedAtMixin, Base):
    """A statistically or structurally unusual pattern.

    The detection maths is stored alongside the result - ``method``, ``threshold``,
    ``observed_value``, ``baseline_value``, ``sample_size`` - so an analyst can judge
    whether the signal is real, and so a defence expert can challenge it on the record.
    Nothing here is a black box.
    """

    __tablename__ = "anomalies"
    __table_args__ = (Index("ix_anomalies_case_kind", "case_id", "kind"),)

    case_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("cases.id", ondelete="CASCADE"), index=True
    )
    evidence_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("evidence.id", ondelete="CASCADE"), index=True
    )

    kind: Mapped[AnomalyKind] = mapped_column(enum_type(AnomalyKind), nullable=False)
    severity: Mapped[Severity] = mapped_column(
        enum_type(Severity), nullable=False, default=Severity.medium
    )
    title: Mapped[str] = mapped_column(String(240), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)

    method: Mapped[str] = mapped_column(String(120), nullable=False)
    threshold: Mapped[float | None] = mapped_column(Float)
    observed_value: Mapped[float | None] = mapped_column(Float)
    baseline_value: Mapped[float | None] = mapped_column(Float)
    deviation: Mapped[float | None] = mapped_column(Float)
    sample_size: Mapped[int | None] = mapped_column(Integer)

    window_start: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    window_end: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    detector: Mapped[str] = mapped_column(String(64), nullable=False)
    detector_version: Mapped[str] = mapped_column(String(16), nullable=False, default="1")
    attributes: Mapped[dict[str, Any]] = mapped_column(nullable=False, default=dict)

    dismissed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    dismissed_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    dismissed_reason: Mapped[str | None] = mapped_column(Text)

    case: Mapped[Case | None] = relationship()
    evidence: Mapped[Evidence | None] = relationship()


class Insight(UUIDPrimaryKey, TimestampMixin, Base):
    """An investigation-oriented observation produced by the intelligence layer.

    The observed/interpretation split is enforced by the schema, not by convention:

    ``observed``
        Facts, each traceable to a recorded artifact via ``evidence_refs``. Written only by
        deterministic code reading persisted rows.
    ``interpretation``
        What those facts may mean. Explicitly labelled as inference in the interface.
    ``llm_narrative``
        Optional phrasing assistance. Isolated in its own column and shown under its own
        label, because a language model is permitted to rephrase an interpretation but is
        never permitted to introduce a fact. It has no write path to ``entities``,
        ``observations`` or ``analysis_findings``.
    """

    __tablename__ = "insights"
    __table_args__ = (
        Index("ix_insights_case_kind", "case_id", "kind"),
        Index("ix_insights_rank", "rank_score"),
        UniqueConstraint("case_id", "dedupe_key", name="uq_insights_case_id_dedupe_key"),
    )

    case_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("cases.id", ondelete="CASCADE"), index=True
    )
    kind: Mapped[InsightKind] = mapped_column(enum_type(InsightKind), nullable=False)
    provenance: Mapped[InsightProvenance] = mapped_column(
        enum_type(InsightProvenance), nullable=False, default=InsightProvenance.derived
    )
    severity: Mapped[Severity] = mapped_column(
        enum_type(Severity), nullable=False, default=Severity.informational
    )
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)

    title: Mapped[str] = mapped_column(String(240), nullable=False)
    observed: Mapped[str] = mapped_column(Text, nullable=False)
    interpretation: Mapped[str | None] = mapped_column(Text)
    llm_narrative: Mapped[str | None] = mapped_column(Text)
    llm_model: Mapped[str | None] = mapped_column(String(64))

    evidence_refs: Mapped[list[Any]] = mapped_column(nullable=False, default=list)
    entity_refs: Mapped[list[Any]] = mapped_column(nullable=False, default=list)
    case_refs: Mapped[list[Any]] = mapped_column(nullable=False, default=list)
    basis: Mapped[dict[str, Any]] = mapped_column(nullable=False, default=dict)

    rank_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    generator: Mapped[str] = mapped_column(String(64), nullable=False)
    generator_version: Mapped[str] = mapped_column(String(16), nullable=False, default="1")
    # Stable identity for an insight so recomputation updates rather than duplicates.
    dedupe_key: Mapped[str] = mapped_column(String(128), nullable=False)

    dismissed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    dismissed_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    dismissed_reason: Mapped[str | None] = mapped_column(Text)
    is_pinned: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    case: Mapped[Case | None] = relationship()
    dismissed_by: Mapped[User | None] = relationship()


class EntityRelationship(UUIDPrimaryKey, Base):
    """A typed edge between two entities, backing the relationship graph.

    Derived rather than authored: produced by analyzers that see two entities in a
    structural relationship (an email's ``From`` and its originating address, a log line's
    user and host), always with the evidence that supports it.
    """

    __tablename__ = "entity_relationships"
    __table_args__ = (
        UniqueConstraint(
            "source_entity_id",
            "target_entity_id",
            "relation",
            name="uq_entity_relationships_source_target_relation",
        ),
    )

    source_entity_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("entities.id", ondelete="CASCADE"), nullable=False, index=True
    )
    target_entity_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("entities.id", ondelete="CASCADE"), nullable=False, index=True
    )
    relation: Mapped[str] = mapped_column(String(48), nullable=False)
    weight: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    observation_count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    supporting_evidence_ids: Mapped[list[Any]] = mapped_column(nullable=False, default=list)
    first_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    source_entity: Mapped[Entity] = relationship(foreign_keys=[source_entity_id])
    target_entity: Mapped[Entity] = relationship(foreign_keys=[target_entity_id])


class CaseRiskSnapshot(UUIDPrimaryKey, CreatedAtMixin, Base):
    """Historical record of computed case risk, so trend is real rather than implied."""

    __tablename__ = "case_risk_snapshots"

    case_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True
    )
    score: Mapped[float] = mapped_column(Numeric(5, 2), nullable=False)
    breakdown: Mapped[dict[str, Any]] = mapped_column(nullable=False, default=dict)
    model_version: Mapped[str] = mapped_column(String(16), nullable=False, default="1")
