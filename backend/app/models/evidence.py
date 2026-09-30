"""Evidence models.

The split between :class:`Evidence`, :class:`EvidenceVersion` and :class:`StoredObject` is
deliberate:

* ``Evidence`` is the *forensic item* an investigator reasons about ("the laptop's auth
  log"), and it is what custody attaches to.
* ``EvidenceVersion`` is a specific acquired revision of that item, each with its own hash.
* ``StoredObject`` is the encrypted blob on disk, addressed by plaintext SHA-256 and
  reference-counted, so two identical artifacts are stored once but remain distinct items
  with independent custody.
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
    LargeBinary,
    String,
    Table,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, CreatedAtMixin, TimestampMixin, UUIDPrimaryKey
from app.models.enums import (
    AcquisitionMethod,
    EvidenceStatus,
    EvidenceType,
    IntegrityStatus,
    SourceCategory,
    enum_type,
)

if TYPE_CHECKING:
    from app.models.analysis import AnalysisRun, EntityOccurrence, Observation
    from app.models.case import Case
    from app.models.custody import CustodyEvent
    from app.models.user import User

evidence_tags = Table(
    "evidence_tags",
    Base.metadata,
    Column("evidence_id", ForeignKey("evidence.id", ondelete="CASCADE"), primary_key=True),
    Column("tag_id", ForeignKey("tags.id", ondelete="CASCADE"), primary_key=True),
)


class StoredObject(UUIDPrimaryKey, CreatedAtMixin, Base):
    """An encrypted blob in the object store.

    Envelope encryption: a random 256-bit data key (DEK) encrypts the artifact with
    AES-256-GCM, and the DEK itself is wrapped by the master key (KEK) from configuration.
    Only the wrapped DEK is persisted, so the database alone cannot decrypt anything.

    ``sha256`` is the hash of the **plaintext**, because that is the value an investigator
    must be able to reproduce from the original artifact independently of this platform.
    ``ciphertext_sha256`` additionally allows an integrity sweep to detect at-rest
    modification without spending the cost of decrypting every object.
    """

    __tablename__ = "stored_objects"

    sha256: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)

    backend: Mapped[str] = mapped_column(String(32), nullable=False, default="local_encrypted")
    storage_key: Mapped[str] = mapped_column(String(512), nullable=False)

    encryption_algorithm: Mapped[str] = mapped_column(
        String(32), nullable=False, default="AES-256-GCM"
    )
    nonce: Mapped[bytes] = mapped_column(LargeBinary(12), nullable=False)
    wrapped_key: Mapped[bytes] = mapped_column(LargeBinary(60), nullable=False)
    # Identifies which KEK wrapped the DEK, so keys can be rotated without re-encrypting.
    key_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    ciphertext_size: Mapped[int] = mapped_column(BigInteger, nullable=False)
    ciphertext_sha256: Mapped[str] = mapped_column(String(64), nullable=False)

    # Number of Evidence versions pointing here; the blob is only removable at zero.
    reference_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Tag(UUIDPrimaryKey, CreatedAtMixin, Base):
    __tablename__ = "tags"

    name: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    category: Mapped[str | None] = mapped_column(String(32))
    color: Mapped[str | None] = mapped_column(String(16))
    description: Mapped[str | None] = mapped_column(Text)


class Evidence(UUIDPrimaryKey, TimestampMixin, Base):
    __tablename__ = "evidence"
    __table_args__ = (
        Index("ix_evidence_case_status", "case_id", "status"),
        Index("ix_evidence_sha256", "sha256"),
        Index(
            "ix_evidence_filename_trgm",
            "original_filename",
            postgresql_using="gin",
            postgresql_ops={"original_filename": "gin_trgm_ops"},
        ),
    )

    reference: Mapped[str] = mapped_column(String(24), unique=True, nullable=False)
    case_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True
    )

    title: Mapped[str] = mapped_column(String(240), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    original_filename: Mapped[str] = mapped_column(String(512), nullable=False)

    evidence_type: Mapped[EvidenceType] = mapped_column(enum_type(EvidenceType), nullable=False)
    source_category: Mapped[SourceCategory] = mapped_column(
        enum_type(SourceCategory), nullable=False
    )
    acquisition_method: Mapped[AcquisitionMethod] = mapped_column(
        enum_type(AcquisitionMethod), nullable=False
    )

    # Where the artifact came from in the physical or logical world.
    source_description: Mapped[str | None] = mapped_column(String(320))
    source_identifier: Mapped[str | None] = mapped_column(String(160))
    source_location: Mapped[str | None] = mapped_column(String(240))

    # Acquisition may predate this platform and may have been performed by someone who is
    # not a platform user, so the collector is recorded as text as well as an optional FK.
    acquired_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    acquired_by_name: Mapped[str | None] = mapped_column(String(160))
    acquired_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    received_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    uploaded_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), index=True
    )
    uploaded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    # Denormalised from the current version so listings and search do not need a join.
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    mime_type: Mapped[str] = mapped_column(String(160), nullable=False)
    # MIME detected from content versus what the filename claimed. A mismatch is a
    # masquerading signal, so it is stored rather than recomputed.
    declared_mime_type: Mapped[str | None] = mapped_column(String(160))
    mime_mismatch: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    # Shannon entropy per byte (0-8); high values suggest encryption or compression.
    entropy: Mapped[float | None] = mapped_column(Float)

    version_count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    current_version_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("evidence_versions.id", ondelete="SET NULL", use_alter=True)
    )

    status: Mapped[EvidenceStatus] = mapped_column(
        enum_type(EvidenceStatus), nullable=False, default=EvidenceStatus.registered, index=True
    )
    integrity_status: Mapped[IntegrityStatus] = mapped_column(
        enum_type(IntegrityStatus), nullable=False, default=IntegrityStatus.pending, index=True
    )
    integrity_note: Mapped[str | None] = mapped_column(Text)
    last_verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # Head of this item's custody hash chain, denormalised so the interface can show
    # verification state without replaying every event.
    custody_head_hash: Mapped[str | None] = mapped_column(String(64))
    custody_event_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    analysis_completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Summary of extracted metadata, kept as JSONB for flexible per-type shapes.
    extracted_metadata: Mapped[dict[str, Any]] = mapped_column(nullable=False, default=dict)

    legal_hold: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    retention_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    case: Mapped[Case] = relationship(back_populates="evidence_items")
    uploaded_by: Mapped[User | None] = relationship(foreign_keys=[uploaded_by_id])
    acquired_by: Mapped[User | None] = relationship(foreign_keys=[acquired_by_id])
    tags: Mapped[list[Tag]] = relationship(secondary=evidence_tags, lazy="selectin")
    versions: Mapped[list[EvidenceVersion]] = relationship(
        back_populates="evidence",
        cascade="all, delete-orphan",
        foreign_keys="EvidenceVersion.evidence_id",
        order_by="EvidenceVersion.version_number",
    )
    current_version: Mapped[EvidenceVersion | None] = relationship(
        foreign_keys=[current_version_id], post_update=True
    )
    custody_events: Mapped[list[CustodyEvent]] = relationship(
        back_populates="evidence", cascade="all, delete-orphan"
    )
    integrity_checks: Mapped[list[IntegrityCheck]] = relationship(
        back_populates="evidence", cascade="all, delete-orphan"
    )
    notes: Mapped[list[EvidenceNote]] = relationship(
        back_populates="evidence", cascade="all, delete-orphan"
    )
    analysis_runs: Mapped[list[AnalysisRun]] = relationship(
        back_populates="evidence", cascade="all, delete-orphan"
    )
    entity_occurrences: Mapped[list[EntityOccurrence]] = relationship(
        back_populates="evidence", cascade="all, delete-orphan"
    )
    observations: Mapped[list[Observation]] = relationship(
        back_populates="evidence", cascade="all, delete-orphan"
    )

    @property
    def integrity_ok(self) -> bool:
        return self.integrity_status is IntegrityStatus.verified


class EvidenceVersion(UUIDPrimaryKey, CreatedAtMixin, Base):
    """A single acquired revision of an evidence item."""

    __tablename__ = "evidence_versions"
    __table_args__ = (
        UniqueConstraint(
            "evidence_id", "version_number", name="uq_evidence_versions_evidence_id_version_number"
        ),
    )

    evidence_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("evidence.id", ondelete="CASCADE"), nullable=False, index=True
    )
    version_number: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    stored_object_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("stored_objects.id", ondelete="RESTRICT"), nullable=False
    )

    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    sha1: Mapped[str | None] = mapped_column(String(40))
    md5: Mapped[str | None] = mapped_column(String(32))
    size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    mime_type: Mapped[str] = mapped_column(String(160), nullable=False)

    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    # Why this version exists: original acquisition, re-acquisition, derived artifact.
    reason: Mapped[str] = mapped_column(String(240), nullable=False, default="initial acquisition")
    is_current: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    evidence: Mapped[Evidence] = relationship(back_populates="versions", foreign_keys=[evidence_id])
    stored_object: Mapped[StoredObject] = relationship(lazy="joined")
    created_by: Mapped[User | None] = relationship()


class IntegrityCheck(UUIDPrimaryKey, CreatedAtMixin, Base):
    """One verification attempt and its outcome.

    Both the expected and computed digests are recorded even on success, so a report can
    show the actual comparison rather than merely asserting that it passed.
    """

    __tablename__ = "integrity_checks"

    evidence_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("evidence.id", ondelete="CASCADE"), nullable=False, index=True
    )
    evidence_version_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("evidence_versions.id", ondelete="SET NULL")
    )
    status: Mapped[IntegrityStatus] = mapped_column(enum_type(IntegrityStatus), nullable=False)
    expected_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    computed_sha256: Mapped[str | None] = mapped_column(String(64))
    ciphertext_verified: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    # What prompted the check: manual, scheduled_sweep, pre_download, pre_report.
    trigger: Mapped[str] = mapped_column(String(32), nullable=False, default="manual")
    checked_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    duration_ms: Mapped[int | None] = mapped_column(Integer)
    detail: Mapped[str | None] = mapped_column(Text)

    evidence: Mapped[Evidence] = relationship(back_populates="integrity_checks")
    checked_by: Mapped[User | None] = relationship()


class EvidenceNote(UUIDPrimaryKey, TimestampMixin, Base):
    __tablename__ = "evidence_notes"

    evidence_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("evidence.id", ondelete="CASCADE"), nullable=False, index=True
    )
    author_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    body: Mapped[str] = mapped_column(Text, nullable=False)

    evidence: Mapped[Evidence] = relationship(back_populates="notes")
    author: Mapped[User | None] = relationship()
