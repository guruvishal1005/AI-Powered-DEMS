"""Alerts and notifications."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, CreatedAtMixin, TimestampMixin, UUIDPrimaryKey
from app.models.enums import AlertSource, AlertStatus, AlertType, Severity, enum_type

if TYPE_CHECKING:
    from app.models.case import Case
    from app.models.evidence import Evidence
    from app.models.user import User


class Alert(UUIDPrimaryKey, TimestampMixin, Base):
    """An actionable signal requiring human attention.

    ``dedupe_key`` collapses repeats: a partial unique index enforces at most one *open*
    alert per key, so a failing nightly integrity sweep raises one alert with a rising
    ``occurrence_count`` rather than a new alert every night. Once resolved, a recurrence
    legitimately opens a fresh alert.
    """

    __tablename__ = "alerts"
    __table_args__ = (
        Index(
            "uq_alerts_open_dedupe_key",
            "dedupe_key",
            unique=True,
            postgresql_where=text("status = 'open'"),
        ),
        Index("ix_alerts_status_severity", "status", "severity"),
        Index("ix_alerts_type_created", "type", "created_at"),
    )

    reference: Mapped[str] = mapped_column(String(24), unique=True, nullable=False)
    type: Mapped[AlertType] = mapped_column(enum_type(AlertType), nullable=False)
    source: Mapped[AlertSource] = mapped_column(enum_type(AlertSource), nullable=False)
    severity: Mapped[Severity] = mapped_column(enum_type(Severity), nullable=False)
    status: Mapped[AlertStatus] = mapped_column(
        enum_type(AlertStatus), nullable=False, default=AlertStatus.open, index=True
    )

    title: Mapped[str] = mapped_column(String(240), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    recommended_action: Mapped[str | None] = mapped_column(Text)

    dedupe_key: Mapped[str] = mapped_column(String(160), nullable=False)
    occurrence_count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    case_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("cases.id", ondelete="CASCADE"), index=True
    )
    evidence_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("evidence.id", ondelete="CASCADE"), index=True
    )
    anomaly_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("anomalies.id", ondelete="SET NULL")
    )
    # The user an alert is *about* (e.g. repeated failed logins), not its assignee.
    subject_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )

    assigned_to_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), index=True
    )
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    acknowledged_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    resolved_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    resolution_note: Mapped[str | None] = mapped_column(Text)

    details: Mapped[dict[str, Any]] = mapped_column(nullable=False, default=dict)

    case: Mapped[Case | None] = relationship()
    evidence: Mapped[Evidence | None] = relationship()
    assigned_to: Mapped[User | None] = relationship(foreign_keys=[assigned_to_id])
    events: Mapped[list[AlertEvent]] = relationship(
        back_populates="alert", cascade="all, delete-orphan", order_by="AlertEvent.created_at"
    )


class AlertEvent(UUIDPrimaryKey, CreatedAtMixin, Base):
    """Triage history for an alert."""

    __tablename__ = "alert_events"

    alert_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("alerts.id", ondelete="CASCADE"), nullable=False, index=True
    )
    action: Mapped[str] = mapped_column(String(32), nullable=False)
    actor_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    actor_label: Mapped[str] = mapped_column(String(255), nullable=False)
    note: Mapped[str | None] = mapped_column(Text)
    from_status: Mapped[AlertStatus | None] = mapped_column(enum_type(AlertStatus))
    to_status: Mapped[AlertStatus | None] = mapped_column(enum_type(AlertStatus))

    alert: Mapped[Alert] = relationship(back_populates="events")


class Notification(UUIDPrimaryKey, CreatedAtMixin, Base):
    """Per-user in-app notification."""

    __tablename__ = "notifications"
    __table_args__ = (Index("ix_notifications_user_read", "user_id", "read_at"),)

    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    kind: Mapped[str] = mapped_column(String(48), nullable=False)
    title: Mapped[str] = mapped_column(String(240), nullable=False)
    body: Mapped[str | None] = mapped_column(Text)
    severity: Mapped[Severity] = mapped_column(
        enum_type(Severity), nullable=False, default=Severity.informational
    )
    # Deep link into the application, e.g. "/cases/CT-2026-0001/evidence/E-2026-00004".
    link: Mapped[str | None] = mapped_column(String(512))
    alert_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("alerts.id", ondelete="CASCADE"))
    read_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    is_dismissed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
