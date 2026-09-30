"""Operational models: job queue, scheduler, retention, backups and settings."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import (
    BigInteger,
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
from app.models.enums import (
    BackupStatus,
    DispositionAction,
    JobStatus,
    Severity,
    enum_type,
)

if TYPE_CHECKING:
    from app.models.user import User


class Job(UUIDPrimaryKey, Base):
    """A unit of background work.

    Claiming uses ``SELECT ... FOR UPDATE SKIP LOCKED``, which gives correct behaviour with
    several concurrent workers without a broker: each worker takes rows no one else holds.
    The lease (``locked_at`` plus ``lease_expires_at``) lets a reaper recover jobs whose
    worker died mid-flight instead of leaving them stuck in ``running`` forever.
    """

    __tablename__ = "jobs"
    __table_args__ = (
        # The claim query's covering index: pending work, ordered by priority then due time.
        Index("ix_jobs_claim", "status", "priority", "run_at"),
        Index("ix_jobs_task_status", "task", "status"),
        Index(
            "uq_jobs_active_dedupe_key",
            "dedupe_key",
            unique=True,
            postgresql_where=text("status in ('queued', 'running') and dedupe_key is not null"),
        ),
    )

    task: Mapped[str] = mapped_column(String(64), nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(nullable=False, default=dict)
    status: Mapped[JobStatus] = mapped_column(
        enum_type(JobStatus), nullable=False, default=JobStatus.queued, index=True
    )
    # Lower runs first.
    priority: Mapped[int] = mapped_column(Integer, nullable=False, default=100)

    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    max_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=3)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    # When the job becomes eligible; also used to implement retry backoff.
    run_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    duration_ms: Mapped[int | None] = mapped_column(Integer)

    locked_by: Mapped[str | None] = mapped_column(String(64))
    locked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    lease_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    last_error: Mapped[str | None] = mapped_column(Text)
    result: Mapped[dict[str, Any] | None] = mapped_column()

    # Prevents duplicate queueing of the same logical work while it is pending.
    dedupe_key: Mapped[str | None] = mapped_column(String(160))

    # Denormalised context so the admin queue view can filter without joins.
    case_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("cases.id", ondelete="SET NULL"), index=True
    )
    evidence_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("evidence.id", ondelete="SET NULL"), index=True
    )
    requested_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    parent_job_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("jobs.id", ondelete="SET NULL")
    )

    @property
    def can_retry(self) -> bool:
        return self.attempts < self.max_attempts


class PeriodicTask(UUIDPrimaryKey, TimestampMixin, Base):
    """Scheduled recurring work.

    Kept in the database rather than in cron so schedules are visible and adjustable in the
    admin interface, and so the schedule survives a restart with its next-run time intact.
    """

    __tablename__ = "periodic_tasks"

    name: Mapped[str] = mapped_column(String(96), unique=True, nullable=False)
    task: Mapped[str] = mapped_column(String(64), nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(nullable=False, default=dict)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")

    interval_seconds: Mapped[int] = mapped_column(Integer, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    next_run_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_status: Mapped[str | None] = mapped_column(String(24))
    last_error: Mapped[str | None] = mapped_column(Text)
    run_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


class RetentionPolicy(UUIDPrimaryKey, TimestampMixin, Base):
    """How long material is kept, and what happens at expiry.

    Disposition never deletes silently: ``requires_review`` forces a human decision, and any
    legal hold overrides the policy entirely.
    """

    __tablename__ = "retention_policies"

    name: Mapped[str] = mapped_column(String(96), unique=True, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    # Matching criteria, e.g. {"incident_type": ["ransomware"], "min_severity": "high"}.
    criteria: Mapped[dict[str, Any]] = mapped_column(nullable=False, default=dict)
    retention_days: Mapped[int] = mapped_column(Integer, nullable=False)
    disposition_action: Mapped[DispositionAction] = mapped_column(
        enum_type(DispositionAction), nullable=False, default=DispositionAction.review
    )
    requires_review: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    warn_days_before: Mapped[int] = mapped_column(Integer, nullable=False, default=30)
    is_default: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )


class LegalHold(UUIDPrimaryKey, CreatedAtMixin, Base):
    """An override that suspends retention disposal for a case or item."""

    __tablename__ = "legal_holds"

    reference: Mapped[str] = mapped_column(String(64), nullable=False)
    case_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("cases.id", ondelete="CASCADE"), index=True
    )
    evidence_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("evidence.id", ondelete="CASCADE"), index=True
    )
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    authority: Mapped[str | None] = mapped_column(String(160))
    applied_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    released_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    released_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    release_reason: Mapped[str | None] = mapped_column(Text)

    @property
    def is_active(self) -> bool:
        return self.released_at is None


class Backup(UUIDPrimaryKey, Base):
    """A backup run and its verification outcome.

    An unverified backup is an assumption, so the run records whether the custody and audit
    chains verified at capture time and whether the archive was read back successfully.
    """

    __tablename__ = "backups"

    kind: Mapped[str] = mapped_column(String(24), nullable=False, default="full")
    status: Mapped[BackupStatus] = mapped_column(
        enum_type(BackupStatus), nullable=False, default=BackupStatus.running
    )
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    duration_ms: Mapped[int | None] = mapped_column(Integer)

    storage_key: Mapped[str | None] = mapped_column(String(512))
    size_bytes: Mapped[int | None] = mapped_column(BigInteger)
    object_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    sha256: Mapped[str | None] = mapped_column(String(64))
    manifest: Mapped[dict[str, Any]] = mapped_column(nullable=False, default=dict)

    custody_chain_verified: Mapped[bool | None] = mapped_column()
    audit_chain_verified: Mapped[bool | None] = mapped_column()
    restore_verified: Mapped[bool | None] = mapped_column()
    verification_note: Mapped[str | None] = mapped_column(Text)

    error: Mapped[str | None] = mapped_column(Text)
    triggered_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )

    triggered_by: Mapped[User | None] = relationship()


class SystemSetting(UUIDPrimaryKey, Base):
    """Runtime-adjustable configuration.

    Only settings that are safe to change without a restart live here. Secrets and
    cryptographic material deliberately do not: those stay in the environment, outside the
    reach of anything an authenticated administrator can edit.
    """

    __tablename__ = "system_settings"

    key: Mapped[str] = mapped_column(String(96), unique=True, nullable=False)
    value: Mapped[dict[str, Any]] = mapped_column(nullable=False, default=dict)
    category: Mapped[str] = mapped_column(String(32), nullable=False, default="general")
    label: Mapped[str] = mapped_column(String(160), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    is_sensitive: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )


class SystemHealthSample(UUIDPrimaryKey, CreatedAtMixin, Base):
    """Periodic snapshot of platform health, so the admin dashboard shows trend not guesswork."""

    __tablename__ = "system_health_samples"

    queue_depth: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    jobs_running: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    jobs_failed_24h: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    evidence_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    storage_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    integrity_failures: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    open_alerts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    worst_alert_severity: Mapped[Severity | None] = mapped_column(enum_type(Severity))
    details: Mapped[dict[str, Any]] = mapped_column(nullable=False, default=dict)
