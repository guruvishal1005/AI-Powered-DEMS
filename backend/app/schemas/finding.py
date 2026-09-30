"""Human-authored investigative findings.

Kept distinct from analyzer-produced ``analysis_findings`` and engine-produced insights so a
report can never blur what a person concluded with what the platform detected.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, Field

from app.models.enums import Confidence, FindingKind, Severity
from app.schemas.common import ActorRef, EvidenceRef, ORMModel


class FindingCreate(BaseModel):
    kind: FindingKind
    title: str = Field(min_length=3, max_length=240)
    description: str = Field(min_length=3, max_length=40000)
    confidence: Confidence = Confidence.moderate
    severity: Severity = Severity.medium
    evidence_ids: list[uuid.UUID] = Field(default_factory=list)
    is_included_in_report: bool = True


class FindingUpdate(BaseModel):
    kind: FindingKind | None = None
    title: str | None = Field(default=None, min_length=3, max_length=240)
    description: str | None = Field(default=None, min_length=3, max_length=40000)
    confidence: Confidence | None = None
    severity: Severity | None = None
    evidence_ids: list[uuid.UUID] | None = None
    is_included_in_report: bool | None = None


class FindingOut(ORMModel):
    id: uuid.UUID
    case_id: uuid.UUID
    sequence: int
    kind: FindingKind
    title: str
    description: str
    confidence: Confidence
    severity: Severity
    is_included_in_report: bool
    author: ActorRef | None
    evidence_items: list[EvidenceRef]
    created_at: datetime
    updated_at: datetime
