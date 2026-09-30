"""Case models - the investigation container."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
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
    CasePersonRole,
    CaseStatus,
    Confidence,
    FindingKind,
    IncidentType,
    Severity,
    enum_type,
)

if TYPE_CHECKING:
    from app.models.analysis import Entity
    from app.models.evidence import Evidence
    from app.models.report import Report
    from app.models.user import User

finding_evidence = Table(
    "finding_evidence",
    Base.metadata,
    Column("finding_id", ForeignKey("findings.id", ondelete="CASCADE"), primary_key=True),
    Column("evidence_id", ForeignKey("evidence.id", ondelete="CASCADE"), primary_key=True),
)


class Case(UUIDPrimaryKey, TimestampMixin, Base):
    __tablename__ = "cases"
    __table_args__ = (
        Index("ix_cases_status_severity", "status", "severity"),
        Index(
            "ix_cases_reference_trgm",
            "reference",
            postgresql_using="gin",
            postgresql_ops={"reference": "gin_trgm_ops"},
        ),
    )

    reference: Mapped[str] = mapped_column(String(24), unique=True, nullable=False)
    title: Mapped[str] = mapped_column(String(240), nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False, default="")

    incident_type: Mapped[IncidentType] = mapped_column(enum_type(IncidentType), nullable=False)
    severity: Mapped[Severity] = mapped_column(enum_type(Severity), nullable=False)
    status: Mapped[CaseStatus] = mapped_column(
        enum_type(CaseStatus), nullable=False, default=CaseStatus.draft, index=True
    )

    # Three distinct times that investigators genuinely need to distinguish.
    incident_occurred_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    reported_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    opened_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    lead_investigator_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), index=True
    )
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )

    # Organisational context that appears on report cover pages.
    jurisdiction: Mapped[str | None] = mapped_column(String(96))
    organization: Mapped[str | None] = mapped_column(String(128))
    external_reference: Mapped[str | None] = mapped_column(String(96))
    classification: Mapped[str] = mapped_column(String(32), nullable=False, default="RESTRICTED")

    # Cached risk score. Recomputed by the intelligence engine; the breakdown is stored so
    # the interface can always explain how the number was reached rather than asserting it.
    risk_score: Mapped[float | None] = mapped_column(Numeric(5, 2))
    risk_breakdown: Mapped[dict[str, Any]] = mapped_column(nullable=False, default=dict)
    risk_computed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    last_activity_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)

    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    closed_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    closure_summary: Mapped[str | None] = mapped_column(Text)

    retention_policy_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("retention_policies.id", ondelete="SET NULL")
    )
    retention_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    legal_hold: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    tags: Mapped[list[Any]] = mapped_column(nullable=False, default=list)

    lead_investigator: Mapped[User | None] = relationship(
        back_populates="owned_cases", foreign_keys=[lead_investigator_id], lazy="joined"
    )
    created_by: Mapped[User | None] = relationship(foreign_keys=[created_by_id])
    closed_by: Mapped[User | None] = relationship(foreign_keys=[closed_by_id])

    assignments: Mapped[list[CaseAssignment]] = relationship(
        back_populates="case", cascade="all, delete-orphan"
    )
    evidence_items: Mapped[list[Evidence]] = relationship(
        back_populates="case", cascade="all, delete-orphan"
    )
    persons: Mapped[list[CasePerson]] = relationship(
        back_populates="case", cascade="all, delete-orphan"
    )
    notes: Mapped[list[CaseNote]] = relationship(
        back_populates="case", cascade="all, delete-orphan"
    )
    findings: Mapped[list[Finding]] = relationship(
        back_populates="case", cascade="all, delete-orphan"
    )
    status_history: Mapped[list[CaseStatusHistory]] = relationship(
        back_populates="case", cascade="all, delete-orphan"
    )
    reports: Mapped[list[Report]] = relationship(
        back_populates="case", cascade="all, delete-orphan"
    )

    @property
    def is_open(self) -> bool:
        return self.status not in (CaseStatus.closed, CaseStatus.archived)


class CaseAssignment(UUIDPrimaryKey, Base):
    """Which users may work a case, and in what capacity.

    This table is the basis of object-level authorization: it is joined in
    ``apply_case_scope`` so unauthorized rows are never selected in the first place.
    """

    __tablename__ = "case_assignments"
    __table_args__ = (
        UniqueConstraint("case_id", "user_id", name="uq_case_assignments_case_id_user_id"),
    )

    case_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    role_on_case: Mapped[str] = mapped_column(
        String(48), nullable=False, default="forensic_analyst"
    )
    assigned_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    assigned_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    unassigned_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    case: Mapped[Case] = relationship(back_populates="assignments")
    user: Mapped[User] = relationship(back_populates="case_assignments", foreign_keys=[user_id])
    assigned_by: Mapped[User | None] = relationship(foreign_keys=[assigned_by_id])


class CaseStatusHistory(UUIDPrimaryKey, CreatedAtMixin, Base):
    __tablename__ = "case_status_history"

    case_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True
    )
    from_status: Mapped[CaseStatus | None] = mapped_column(enum_type(CaseStatus))
    to_status: Mapped[CaseStatus] = mapped_column(enum_type(CaseStatus), nullable=False)
    changed_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    reason: Mapped[str | None] = mapped_column(Text)

    case: Mapped[Case] = relationship(back_populates="status_history")
    changed_by: Mapped[User | None] = relationship()


class CasePerson(UUIDPrimaryKey, TimestampMixin, Base):
    """A person or organisation related to the case.

    ``linked_entity_id`` connects an investigator-declared person to an entity the
    analysis engine extracted from evidence, which is how "this suspect's email appears in
    three artifacts" becomes answerable.
    """

    __tablename__ = "case_persons"

    case_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True
    )
    role: Mapped[CasePersonRole] = mapped_column(enum_type(CasePersonRole), nullable=False)
    full_name: Mapped[str] = mapped_column(String(160), nullable=False)
    aliases: Mapped[list[Any]] = mapped_column(nullable=False, default=list)
    organization: Mapped[str | None] = mapped_column(String(160))
    email: Mapped[str | None] = mapped_column(String(255))
    phone: Mapped[str | None] = mapped_column(String(48))
    address: Mapped[str | None] = mapped_column(Text)
    national_id: Mapped[str | None] = mapped_column(String(64))
    notes: Mapped[str | None] = mapped_column(Text)
    linked_entity_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("entities.id", ondelete="SET NULL")
    )

    case: Mapped[Case] = relationship(back_populates="persons")
    linked_entity: Mapped[Entity | None] = relationship()


class CaseNote(UUIDPrimaryKey, TimestampMixin, Base):
    __tablename__ = "case_notes"

    case_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True
    )
    author_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    body: Mapped[str] = mapped_column(Text, nullable=False)
    is_pinned: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    case: Mapped[Case] = relationship(back_populates="notes")
    author: Mapped[User | None] = relationship()


class Finding(UUIDPrimaryKey, TimestampMixin, Base):
    """An investigator's or analyst's documented conclusion.

    Findings are authored by people, which is what distinguishes them from
    :class:`~app.models.analysis.Insight` (produced by the engine). Reports present the two
    separately so a reader always knows whether a human or the platform asserted something.
    """

    __tablename__ = "findings"
    __table_args__ = (UniqueConstraint("case_id", "sequence", name="uq_findings_case_id_sequence"),)

    case_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True
    )
    sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    kind: Mapped[FindingKind] = mapped_column(enum_type(FindingKind), nullable=False)
    title: Mapped[str] = mapped_column(String(240), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    confidence: Mapped[Confidence] = mapped_column(
        enum_type(Confidence), nullable=False, default=Confidence.moderate
    )
    severity: Mapped[Severity] = mapped_column(
        enum_type(Severity), nullable=False, default=Severity.medium
    )
    author_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    is_included_in_report: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    case: Mapped[Case] = relationship(back_populates="findings")
    author: Mapped[User | None] = relationship()
    evidence_items: Mapped[list[Evidence]] = relationship(
        secondary=finding_evidence, lazy="selectin"
    )
