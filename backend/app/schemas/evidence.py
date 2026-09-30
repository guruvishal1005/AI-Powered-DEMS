"""Evidence request and response shapes."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, Field, field_validator

from app.models.enums import (
    AcquisitionMethod,
    CustodyAction,
    EvidenceStatus,
    EvidenceType,
    IntegrityStatus,
    SourceCategory,
)
from app.schemas.common import ActorRef, CaseRef, ORMModel


class AcquisitionMetadata(BaseModel):
    """Provenance supplied by the investigator at upload time.

    Sent as a JSON part alongside the file. These are *claims about the physical world* that the
    platform cannot verify - who seized a laptop, and when - so they are stored as reported and
    attributed to the person who reported them, never presented as platform-verified fact.
    """

    title: str | None = Field(default=None, max_length=240)
    description: str = Field(default="", max_length=20000)
    evidence_type: EvidenceType | None = None
    source_category: SourceCategory = SourceCategory.digital_device
    acquisition_method: AcquisitionMethod = AcquisitionMethod.file_export
    source_description: str | None = Field(default=None, max_length=320)
    source_identifier: str | None = Field(default=None, max_length=160)
    source_location: str | None = Field(default=None, max_length=240)
    acquired_at: datetime | None = None
    acquired_by_name: str | None = Field(default=None, max_length=160)
    acquired_by_id: uuid.UUID | None = None
    received_at: datetime | None = None
    collection_notes: str | None = Field(default=None, max_length=20000)
    tags: list[str] = Field(default_factory=list)

    @field_validator("acquired_at", "received_at")
    @classmethod
    def not_in_future(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        from app.core.clock import ensure_utc, utcnow

        normalised = ensure_utc(value)
        if normalised > utcnow():
            raise ValueError("an acquisition time cannot be in the future")
        return normalised


class HashSetOut(BaseModel):
    """The digests recorded for one artifact.

    SHA-256 is the integrity control. SHA-1 and MD5 are published for cross-referencing against
    external tooling and reference sets only, and the interface labels them as such rather than
    presenting three equally authoritative hashes.
    """

    sha256: str
    sha1: str | None = None
    md5: str | None = None


class StoredObjectOut(ORMModel):
    """Storage-level facts about an artifact, for the preservation panel."""

    size_bytes: int
    encryption_algorithm: str
    key_version: int
    ciphertext_size: int
    backend: str
    reference_count: int
    last_verified_at: datetime | None


class EvidenceVersionOut(ORMModel):
    id: uuid.UUID
    version_number: int
    sha256: str
    sha1: str | None
    md5: str | None
    size_bytes: int
    mime_type: str
    reason: str
    is_current: bool
    created_by: ActorRef | None
    created_at: datetime


class EvidenceSummaryOut(ORMModel):
    id: uuid.UUID
    reference: str
    case_id: uuid.UUID
    title: str
    original_filename: str
    evidence_type: EvidenceType
    source_category: SourceCategory
    acquisition_method: AcquisitionMethod
    sha256: str
    size_bytes: int
    mime_type: str
    declared_mime_type: str | None
    mime_mismatch: bool
    entropy: float | None
    status: EvidenceStatus
    integrity_status: IntegrityStatus
    last_verified_at: datetime | None
    version_count: int
    custody_event_count: int
    acquired_at: datetime | None
    uploaded_at: datetime
    uploaded_by: ActorRef | None
    legal_hold: bool
    analysis_completed_at: datetime | None
    tags: list[str]

    @field_validator("tags", mode="before")
    @classmethod
    def tag_names(cls, value: object) -> object:
        """Render the tag relationship as plain names."""
        if isinstance(value, list):
            return [
                item if isinstance(item, str) else getattr(item, "name", str(item))
                for item in value
            ]
        return value


class EvidenceDetailOut(EvidenceSummaryOut):
    case: CaseRef | None
    description: str
    source_description: str | None
    source_identifier: str | None
    source_location: str | None
    acquired_by_name: str | None
    acquired_by: ActorRef | None
    received_at: datetime | None
    integrity_note: str | None
    custody_head_hash: str | None
    extracted_metadata: dict[str, object]
    retention_expires_at: datetime | None
    current_version: EvidenceVersionOut | None
    created_at: datetime
    updated_at: datetime


class EvidenceUpdate(BaseModel):
    title: str | None = Field(default=None, min_length=1, max_length=240)
    description: str | None = Field(default=None, max_length=20000)
    evidence_type: EvidenceType | None = None
    source_category: SourceCategory | None = None
    acquisition_method: AcquisitionMethod | None = None
    source_description: str | None = Field(default=None, max_length=320)
    source_identifier: str | None = Field(default=None, max_length=160)
    source_location: str | None = Field(default=None, max_length=240)
    acquired_at: datetime | None = None
    acquired_by_name: str | None = Field(default=None, max_length=160)
    received_at: datetime | None = None


class EvidenceTagsUpdate(BaseModel):
    tags: list[str] = Field(default_factory=list)


class EvidenceNoteCreate(BaseModel):
    body: str = Field(min_length=1, max_length=20000)


class EvidenceNoteOut(ORMModel):
    id: uuid.UUID
    body: str
    author: ActorRef | None
    created_at: datetime
    updated_at: datetime


class IntegrityCheckOut(ORMModel):
    id: uuid.UUID
    status: IntegrityStatus
    expected_sha256: str
    computed_sha256: str | None
    ciphertext_verified: bool
    trigger: str
    checked_by: ActorRef | None
    duration_ms: int | None
    detail: str | None
    created_at: datetime


class VerificationOut(BaseModel):
    """The result of a verification, phrased so the outcome is unambiguous."""

    evidence_id: uuid.UUID
    evidence_reference: str
    status: IntegrityStatus
    verified: bool
    expected_sha256: str
    computed_sha256: str | None
    ciphertext_verified: bool
    duration_ms: int
    detail: str
    checked_at: datetime


class ArchiveRequest(BaseModel):
    reason: str = Field(min_length=3, max_length=2000)


class LegalHoldRequest(BaseModel):
    hold: bool
    reason: str = Field(min_length=3, max_length=2000)


class PreviewOut(BaseModel):
    """A bounded, text-safe excerpt of an artifact.

    Binary content is returned hex-encoded rather than as raw bytes, and the response always
    states whether it was truncated, so the interface can never present a partial artifact as
    though it were complete.
    """

    evidence_id: uuid.UUID
    evidence_reference: str
    mime_type: str
    encoding: str
    content: str
    bytes_returned: int
    total_bytes: int
    truncated: bool
    integrity_status: IntegrityStatus
    note: str


class CustodyEventOut(ORMModel):
    """One link in an evidence item's chain of custody.

    The hash fields are exposed deliberately. An investigator or opposing expert must be able to
    see that each entry commits to its predecessor, and a chain the interface merely asserts is
    intact is not evidence of anything.
    """

    id: uuid.UUID
    sequence: int
    action: CustodyAction
    actor_id: uuid.UUID | None
    actor_label: str
    actor_role: str | None
    occurred_at: datetime
    recorded_at: datetime
    previous_state: dict[str, object]
    new_state: dict[str, object]
    reason: str | None
    notes: str | None
    sha256_at_event: str | None
    integrity_status_at_event: IntegrityStatus | None
    ip_address: str | None
    request_id: str | None
    details: dict[str, object]
    previous_hash: str | None
    entry_hash: str
    signing_key_id: str | None


class ChainBreakOut(ORMModel):
    kind: str
    sequence: int
    record_id: str
    detail: str


class ChainStatusOut(BaseModel):
    evidence_id: uuid.UUID
    evidence_reference: str
    event_count: int
    intact: bool
    trustworthy: bool
    head_hash: str | None
    head_matches_record: bool
    signatures_checked: int
    signatures_valid: int
    breaks: list[ChainBreakOut]
    summary: str
    verified_at: datetime


class StorageSummaryOut(BaseModel):
    object_count: int
    unique_bytes: int
    encrypted_bytes: int
    logical_bytes: int
    deduplicated_bytes: int
