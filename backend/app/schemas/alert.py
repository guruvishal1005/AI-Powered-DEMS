"""Alert and notification shapes."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from app.models.enums import AlertSource, AlertStatus, AlertType, Severity
from app.schemas.common import ActorRef, CaseRef, EvidenceRef, ORMModel


class AlertEventOut(ORMModel):
    id: uuid.UUID
    action: str
    actor_id: uuid.UUID | None
    actor_label: str
    note: str | None
    from_status: AlertStatus | None
    to_status: AlertStatus | None
    created_at: datetime


class AlertSummaryOut(ORMModel):
    id: uuid.UUID
    reference: str
    type: AlertType
    source: AlertSource
    severity: Severity
    status: AlertStatus
    title: str
    occurrence_count: int
    first_seen_at: datetime
    last_seen_at: datetime
    case_id: uuid.UUID | None
    evidence_id: uuid.UUID | None
    assigned_to: ActorRef | None
    created_at: datetime


class AlertDetailOut(AlertSummaryOut):
    description: str
    recommended_action: str | None
    dedupe_key: str
    subject_user_id: uuid.UUID | None
    anomaly_id: uuid.UUID | None
    acknowledged_at: datetime | None
    resolved_at: datetime | None
    resolution_note: str | None
    details: dict[str, Any]
    case: CaseRef | None = None
    evidence: EvidenceRef | None = None
    events: list[AlertEventOut] = Field(default_factory=list)


class AlertNoteRequest(BaseModel):
    note: str | None = Field(default=None, max_length=4000)


class AlertResolveRequest(BaseModel):
    note: str = Field(min_length=3, max_length=4000)


class AlertAssignRequest(BaseModel):
    assignee_id: uuid.UUID


class NotificationOut(ORMModel):
    id: uuid.UUID
    kind: str
    title: str
    body: str | None
    severity: Severity
    link: str | None
    alert_id: uuid.UUID | None
    read_at: datetime | None
    is_dismissed: bool
    created_at: datetime
