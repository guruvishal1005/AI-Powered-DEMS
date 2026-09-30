"""Case request and response shapes."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, Field, field_validator

from app.models.enums import (
    CasePersonRole,
    CaseStatus,
    IncidentType,
    Severity,
)
from app.schemas.common import ActorRef, ORMModel


class CaseAssignmentOut(ORMModel):
    id: uuid.UUID
    user: ActorRef
    role_on_case: str
    assigned_at: datetime
    unassigned_at: datetime | None = None


class CaseSummaryOut(ORMModel):
    """Row shape for case listings.

    Deliberately narrower than the detail response: a list of two hundred cases should not each
    carry their assignments and notes, and the counts the dashboard needs are aggregates rather
    than loaded collections.
    """

    id: uuid.UUID
    reference: str
    title: str
    incident_type: IncidentType
    severity: Severity
    status: CaseStatus
    opened_at: datetime | None
    incident_occurred_at: datetime | None
    last_activity_at: datetime | None
    lead_investigator: ActorRef | None
    classification: str
    jurisdiction: str | None
    organization: str | None
    external_reference: str | None
    risk_score: float | None
    legal_hold: bool
    tags: list[str]
    created_at: datetime
    updated_at: datetime


class CaseDetailOut(CaseSummaryOut):
    summary: str
    reported_at: datetime | None
    closed_at: datetime | None
    closed_by: ActorRef | None
    closure_summary: str | None
    created_by: ActorRef | None
    risk_breakdown: dict[str, object]
    risk_computed_at: datetime | None
    retention_expires_at: datetime | None
    assignments: list[CaseAssignmentOut]


class CaseCreate(BaseModel):
    title: str = Field(min_length=3, max_length=240)
    summary: str = Field(default="", max_length=20000)
    incident_type: IncidentType
    severity: Severity
    incident_occurred_at: datetime | None = None
    reported_at: datetime | None = None
    lead_investigator_id: uuid.UUID | None = None
    jurisdiction: str | None = Field(default=None, max_length=96)
    organization: str | None = Field(default=None, max_length=128)
    external_reference: str | None = Field(default=None, max_length=96)
    classification: str = Field(default="RESTRICTED", max_length=32)
    tags: list[str] = Field(default_factory=list)
    status: CaseStatus = CaseStatus.active

    @field_validator("incident_occurred_at", "reported_at")
    @classmethod
    def not_in_future(cls, value: datetime | None) -> datetime | None:
        """Reject future timestamps for events that have already happened.

        An incident cannot have occurred tomorrow. Catching this at the boundary matters because
        these values feed the investigation timeline, where a single wrong date silently distorts
        every conclusion drawn from the sequence of events.
        """
        if value is None:
            return None
        from app.core.clock import ensure_utc, utcnow

        normalised = ensure_utc(value)
        if normalised > utcnow():
            raise ValueError("this timestamp cannot be in the future")
        return normalised


class CaseUpdate(BaseModel):
    """Partial update. Only the fields present in the request body are applied."""

    title: str | None = Field(default=None, min_length=3, max_length=240)
    summary: str | None = Field(default=None, max_length=20000)
    incident_type: IncidentType | None = None
    severity: Severity | None = None
    incident_occurred_at: datetime | None = None
    reported_at: datetime | None = None
    jurisdiction: str | None = Field(default=None, max_length=96)
    organization: str | None = Field(default=None, max_length=128)
    external_reference: str | None = Field(default=None, max_length=96)
    classification: str | None = Field(default=None, max_length=32)
    tags: list[str] | None = None


class CaseStatusChange(BaseModel):
    status: CaseStatus
    reason: str | None = Field(default=None, max_length=2000)
    closure_summary: str | None = Field(default=None, max_length=20000)


class CaseAssignRequest(BaseModel):
    user_id: uuid.UUID
    role_on_case: str = Field(default="forensic_analyst", max_length=48)


class SetLeadRequest(BaseModel):
    user_id: uuid.UUID


class CaseNoteCreate(BaseModel):
    body: str = Field(min_length=1, max_length=20000)
    is_pinned: bool = False


class CaseNoteOut(ORMModel):
    id: uuid.UUID
    body: str
    is_pinned: bool
    author: ActorRef | None
    created_at: datetime
    updated_at: datetime


class CasePersonCreate(BaseModel):
    role: CasePersonRole
    full_name: str = Field(min_length=1, max_length=160)
    aliases: list[str] = Field(default_factory=list)
    organization: str | None = Field(default=None, max_length=160)
    email: str | None = Field(default=None, max_length=255)
    phone: str | None = Field(default=None, max_length=48)
    address: str | None = None
    national_id: str | None = Field(default=None, max_length=64)
    notes: str | None = None


class CasePersonOut(ORMModel):
    id: uuid.UUID
    role: CasePersonRole
    full_name: str
    aliases: list[str]
    organization: str | None
    email: str | None
    phone: str | None
    address: str | None
    national_id: str | None
    notes: str | None
    linked_entity_id: uuid.UUID | None
    created_at: datetime


class CaseStatusHistoryOut(ORMModel):
    id: uuid.UUID
    from_status: CaseStatus | None
    to_status: CaseStatus
    changed_by: ActorRef | None
    reason: str | None
    created_at: datetime
