"""External threat intelligence.

The MVP ships a curated offline feed rather than calling a live service, so the platform has
no outbound dependency and a demonstration is reproducible. The provider boundary in
:mod:`app.intel` is what allows MISP, VirusTotal or AbuseIPDB adapters to be added later
without touching the matching logic or the schema.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, CreatedAtMixin, TimestampMixin, UUIDPrimaryKey
from app.models.analysis import Entity
from app.models.enums import IndicatorSeverity, IndicatorType, enum_type


class ThreatIndicator(UUIDPrimaryKey, TimestampMixin, Base):
    """A known indicator of compromise from an intelligence source."""

    __tablename__ = "threat_indicators"
    __table_args__ = (
        UniqueConstraint(
            "type", "canonical_value", "source", name="uq_threat_indicators_type_value_source"
        ),
        Index("ix_threat_indicators_value", "canonical_value"),
    )

    type: Mapped[IndicatorType] = mapped_column(enum_type(IndicatorType), nullable=False)
    canonical_value: Mapped[str] = mapped_column(String(512), nullable=False)
    severity: Mapped[IndicatorSeverity] = mapped_column(
        enum_type(IndicatorSeverity), nullable=False, default=IndicatorSeverity.suspicious
    )
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.5)

    source: Mapped[str] = mapped_column(String(64), nullable=False)
    source_reference: Mapped[str | None] = mapped_column(String(512))
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    tags: Mapped[list[Any]] = mapped_column(nullable=False, default=list)
    # Attribution where the feed provides it, e.g. a named campaign or malware family.
    threat_actor: Mapped[str | None] = mapped_column(String(96))
    malware_family: Mapped[str | None] = mapped_column(String(96))

    first_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)


class IndicatorMatch(UUIDPrimaryKey, CreatedAtMixin, Base):
    """An extracted entity that matched a known indicator.

    Recorded as its own row rather than a flag on the entity so that the same value matching
    several feeds produces several attributable matches, each citing its source.
    """

    __tablename__ = "indicator_matches"
    __table_args__ = (
        UniqueConstraint(
            "indicator_id", "evidence_id", name="uq_indicator_matches_indicator_id_evidence_id"
        ),
        Index("ix_indicator_matches_case", "case_id"),
    )

    indicator_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("threat_indicators.id", ondelete="CASCADE"), nullable=False, index=True
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
    occurrence_count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    context: Mapped[str | None] = mapped_column(String(240))

    indicator: Mapped[ThreatIndicator] = relationship(lazy="joined")
    entity: Mapped[Entity] = relationship(lazy="joined")
