"""Analysis-run and analyzer-produced finding shapes."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from app.models.enums import AnalysisStatus, Severity
from app.schemas.common import ORMModel


class AnalysisRunOut(ORMModel):
    id: uuid.UUID
    evidence_id: uuid.UUID
    case_id: uuid.UUID
    analyzer: str
    analyzer_version: str
    status: AnalysisStatus
    started_at: datetime | None
    completed_at: datetime | None
    duration_ms: int | None
    entity_count: int
    observation_count: int
    finding_count: int
    error: str | None
    skip_reason: str | None
    summary: dict[str, Any]
    created_at: datetime


class AnalysisFindingOut(ORMModel):
    id: uuid.UUID
    evidence_id: uuid.UUID
    case_id: uuid.UUID
    code: str
    title: str
    description: str
    severity: Severity
    confidence: float
    analyzer: str
    analyzer_version: str
    locator: dict[str, Any]
    excerpt: str | None
    attributes: dict[str, Any]
    created_at: datetime
