"""Forensic report models.

A report is an immutable artifact, not a live view. When one is generated the builder
captures a complete point-in-time ``snapshot`` of the case - evidence inventory with
hashes, integrity results, custody chains and their verification status, timeline,
findings, correlations and insights - and persists it as JSONB.

Everything downstream renders from that snapshot, which gives two properties a live query
cannot: re-rendering an old report reproduces exactly what was originally attested to, and
a signature over the snapshot hash remains meaningful even after the case moves on.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import (
    BigInteger,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, CreatedAtMixin, TimestampMixin, UUIDPrimaryKey
from app.models.enums import ReportFormat, ReportStatus, enum_type

if TYPE_CHECKING:
    from app.models.case import Case
    from app.models.evidence import StoredObject
    from app.models.user import User


class Report(UUIDPrimaryKey, TimestampMixin, Base):
    __tablename__ = "reports"
    __table_args__ = (
        UniqueConstraint("case_id", "reference", name="uq_reports_case_id_reference"),
        Index("ix_reports_status", "status"),
    )

    reference: Mapped[str] = mapped_column(String(24), nullable=False)
    case_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True
    )
    title: Mapped[str] = mapped_column(String(240), nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    status: Mapped[ReportStatus] = mapped_column(
        enum_type(ReportStatus), nullable=False, default=ReportStatus.draft
    )
    classification: Mapped[str] = mapped_column(String(32), nullable=False, default="RESTRICTED")

    # Which sections the author chose to include, and rendering options.
    spec: Mapped[dict[str, Any]] = mapped_column(nullable=False, default=dict)
    # Immutable point-in-time capture of everything the report attests to.
    snapshot: Mapped[dict[str, Any]] = mapped_column(nullable=False, default=dict)
    snapshot_sha256: Mapped[str | None] = mapped_column(String(64))
    snapshot_captured_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # Author-written prose; kept separate from generated content so a reader can tell them apart.
    executive_summary: Mapped[str | None] = mapped_column(Text)
    conclusion: Mapped[str | None] = mapped_column(Text)
    distribution_list: Mapped[list[Any]] = mapped_column(nullable=False, default=list)

    prepared_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    prepared_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    submitted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    reviewed_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    review_note: Mapped[str | None] = mapped_column(Text)

    # Signing is the attestation step, gated on the report:sign permission.
    signature: Mapped[bytes | None] = mapped_column(LargeBinary(64))
    signing_key_id: Mapped[str | None] = mapped_column(String(32))
    signed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    superseded_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("reports.id", ondelete="SET NULL")
    )

    # Counts captured at generation time, so a stored report never disagrees with itself.
    evidence_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    finding_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    integrity_verified_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    integrity_failed_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    custody_chain_intact: Mapped[bool | None] = mapped_column()

    case: Mapped[Case] = relationship(back_populates="reports")
    prepared_by: Mapped[User | None] = relationship(foreign_keys=[prepared_by_id])
    reviewed_by: Mapped[User | None] = relationship(foreign_keys=[reviewed_by_id])
    artifacts: Mapped[list[ReportArtifact]] = relationship(
        back_populates="report", cascade="all, delete-orphan"
    )

    @property
    def is_signed(self) -> bool:
        return self.signature is not None


class ReportArtifact(UUIDPrimaryKey, CreatedAtMixin, Base):
    """A rendered file for a report.

    Rendered output is stored through the same encrypted, content-addressed object store as
    evidence, because a forensic report contains the evidence's most sensitive extracts and
    deserves identical protection.
    """

    __tablename__ = "report_artifacts"
    __table_args__ = (
        UniqueConstraint("report_id", "format", name="uq_report_artifacts_report_id_format"),
    )

    report_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("reports.id", ondelete="CASCADE"), nullable=False, index=True
    )
    format: Mapped[ReportFormat] = mapped_column(enum_type(ReportFormat), nullable=False)
    filename: Mapped[str] = mapped_column(String(240), nullable=False)
    size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    stored_object_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("stored_objects.id", ondelete="RESTRICT"), nullable=False
    )
    page_count: Mapped[int | None] = mapped_column(Integer)
    render_duration_ms: Mapped[int | None] = mapped_column(Integer)
    generated_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )

    report: Mapped[Report] = relationship(back_populates="artifacts")
    stored_object: Mapped[StoredObject] = relationship()
