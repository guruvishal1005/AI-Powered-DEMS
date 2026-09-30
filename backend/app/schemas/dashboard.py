"""Command Center aggregates.

Every figure here is a real query over scoped rows. The dashboard is not allowed to invent
metrics, and it is not allowed to show counts the caller is not entitled to see.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel

from app.models.enums import Severity
from app.schemas.alert import AlertSummaryOut
from app.schemas.case import CaseSummaryOut
from app.schemas.common import CountByLabel, TimeBucket
from app.schemas.evidence import EvidenceSummaryOut


class IntegrityOverview(BaseModel):
    by_status: dict[str, int]
    verified: int
    failed: int
    pending: int
    last_failure_at: datetime | None = None


class DashboardOut(BaseModel):
    generated_at: datetime
    cases_by_status: dict[str, int]
    cases_open: int
    cases_total: int
    evidence_total: int
    evidence_by_type: list[CountByLabel]
    integrity: IntegrityOverview
    open_alerts: dict[str, int]
    queue_depth: int
    jobs_failed_24h: int
    storage_bytes: int
    recent_cases: list[CaseSummaryOut]
    attention_cases: list[CaseSummaryOut]
    recent_evidence: list[EvidenceSummaryOut]
    recent_alerts: list[AlertSummaryOut]
    activity: list[TimeBucket]
    worst_alert_severity: Severity | None = None
    extras: dict[str, Any] = {}
