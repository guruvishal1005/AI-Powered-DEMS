"""Chain-of-custody model.

Each evidence item owns an append-only sequence of events forming a hash chain:

    entry_hash[n] = SHA256(canonical_json(payload[n]) || entry_hash[n-1])

Because every entry commits to its predecessor, altering, deleting or reordering history
changes every subsequent hash and is therefore detectable by replaying the chain. Database
triggers (see the initial migration) additionally reject ``UPDATE`` and ``DELETE`` on this
table, so append-only is enforced by the database rather than by convention.

Actor identity is stored **denormalised** as ``actor_label`` in addition to the foreign key.
A custody record must remain readable and attributable for years, potentially after the
user account has been removed, so the record cannot depend on the ``users`` row surviving.
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

from app.db.base import Base, UUIDPrimaryKey
from app.models.enums import CustodyAction, IntegrityStatus, enum_type

if TYPE_CHECKING:
    from app.models.evidence import Evidence
    from app.models.user import User


class CustodyEvent(UUIDPrimaryKey, Base):
    __tablename__ = "custody_events"
    __table_args__ = (
        UniqueConstraint("evidence_id", "sequence", name="uq_custody_events_evidence_id_sequence"),
        UniqueConstraint("entry_hash", name="uq_custody_events_entry_hash"),
        Index("ix_custody_events_case_recorded", "case_id", "recorded_at"),
        Index("ix_custody_events_action", "action"),
    )

    evidence_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("evidence.id", ondelete="CASCADE"), nullable=False, index=True
    )
    # Denormalised so case-scoped custody queries and authorization scoping avoid a join.
    case_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True
    )
    sequence: Mapped[int] = mapped_column(Integer, nullable=False)

    action: Mapped[CustodyAction] = mapped_column(enum_type(CustodyAction), nullable=False)

    actor_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    # Survives deletion of the user account; this is the forensic record of who acted.
    actor_label: Mapped[str] = mapped_column(String(255), nullable=False)
    actor_role: Mapped[str | None] = mapped_column(String(48))

    # See app.core.clock for why these are separate.
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    recorded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )

    # State transition captured at the moment of the event.
    previous_state: Mapped[dict[str, Any]] = mapped_column(nullable=False, default=dict)
    new_state: Mapped[dict[str, Any]] = mapped_column(nullable=False, default=dict)

    reason: Mapped[str | None] = mapped_column(Text)
    notes: Mapped[str | None] = mapped_column(Text)

    # Integrity snapshot: what the artifact hashed to when this event was recorded.
    sha256_at_event: Mapped[str | None] = mapped_column(String(64))
    integrity_status_at_event: Mapped[IntegrityStatus | None] = mapped_column(
        enum_type(IntegrityStatus)
    )

    ip_address: Mapped[str | None] = mapped_column(String(64))
    user_agent: Mapped[str | None] = mapped_column(String(512))
    request_id: Mapped[str | None] = mapped_column(String(64))

    details: Mapped[dict[str, Any]] = mapped_column(nullable=False, default=dict)

    # --- Hash chain ---
    # Null only for the genesis event of each evidence item.
    previous_hash: Mapped[str | None] = mapped_column(String(64))
    entry_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    canonical_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    # Ed25519 signature over entry_hash, binding the record to the platform's key.
    signature: Mapped[bytes | None] = mapped_column(LargeBinary(64))
    signing_key_id: Mapped[str | None] = mapped_column(String(32))

    evidence: Mapped[Evidence] = relationship(back_populates="custody_events")
    actor: Mapped[User | None] = relationship()


class AuditLogEntry(UUIDPrimaryKey, Base):
    """Platform-wide append-only audit chain.

    Where :class:`CustodyEvent` answers "what happened to this artifact?", the audit log
    answers "what happened on this platform?" - including reads, denied attempts and
    administrative changes that never touch evidence.

    ``sequence`` is a single global ordering, assigned under an advisory lock by
    :mod:`app.audit.writer`, because a hash chain requires a total order.
    """

    __tablename__ = "audit_log"
    __table_args__ = (
        UniqueConstraint("sequence", name="uq_audit_log_sequence"),
        UniqueConstraint("entry_hash", name="uq_audit_log_entry_hash"),
        Index("ix_audit_log_actor_recorded", "actor_id", "recorded_at"),
        Index("ix_audit_log_resource", "resource_type", "resource_id"),
        Index("ix_audit_log_action_recorded", "action", "recorded_at"),
    )

    sequence: Mapped[int] = mapped_column(BigInteger, nullable=False)

    action: Mapped[str] = mapped_column(String(64), nullable=False)
    resource_type: Mapped[str] = mapped_column(String(48), nullable=False)
    resource_id: Mapped[str | None] = mapped_column(String(64))
    resource_label: Mapped[str | None] = mapped_column(String(240))

    actor_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    actor_label: Mapped[str] = mapped_column(String(255), nullable=False)
    actor_roles: Mapped[list[Any]] = mapped_column(nullable=False, default=list)

    # Denied attempts are as important as successful ones; both are recorded.
    result: Mapped[str] = mapped_column(String(16), nullable=False, default="success")

    case_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("cases.id", ondelete="SET NULL"), index=True
    )

    ip_address: Mapped[str | None] = mapped_column(String(64), index=True)
    user_agent: Mapped[str | None] = mapped_column(String(512))
    request_id: Mapped[str | None] = mapped_column(String(64))
    http_method: Mapped[str | None] = mapped_column(String(8))
    http_path: Mapped[str | None] = mapped_column(String(512))
    status_code: Mapped[int | None] = mapped_column(Integer)

    before_state: Mapped[dict[str, Any] | None] = mapped_column()
    after_state: Mapped[dict[str, Any] | None] = mapped_column()
    reason: Mapped[str | None] = mapped_column(Text)
    detail: Mapped[str | None] = mapped_column(Text)

    recorded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )

    previous_hash: Mapped[str | None] = mapped_column(String(64))
    entry_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    canonical_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    signature: Mapped[bytes | None] = mapped_column(LargeBinary(64))
    signing_key_id: Mapped[str | None] = mapped_column(String(32))

    actor: Mapped[User | None] = relationship()
