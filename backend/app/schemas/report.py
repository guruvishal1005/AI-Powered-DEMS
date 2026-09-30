"""Forensic report shapes.

A report is an immutable artifact: the snapshot is captured once, and every subsequent render
and signature is over that snapshot. Re-rendering therefore reproduces what was attested to,
even after the live case has moved on.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from app.models.enums import ReportFormat, ReportStatus
from app.schemas.common import ActorRef, ORMModel


class ReportSpec(BaseModel):
    """Which sections to include. Defaults cover a complete forensic report."""

    include_executive_summary: bool = True
    include_evidence_inventory: bool = True
    include_integrity: bool = True
    include_custody: bool = True
    include_timeline: bool = True
    include_findings: bool = True
    include_correlations: bool = True
    include_insights: bool = True
    include_audit_summary: bool = True
    include_hash_table: bool = True


class ReportCreate(BaseModel):
    title: str = Field(min_length=3, max_length=240)
    classification: str = Field(default="RESTRICTED", max_length=32)
    executive_summary: str | None = Field(default=None, max_length=40000)
    conclusion: str | None = Field(default=None, max_length=40000)
    distribution_list: list[str] = Field(default_factory=list)
    spec: ReportSpec = Field(default_factory=ReportSpec)


class ReportUpdate(BaseModel):
    title: str | None = Field(default=None, min_length=3, max_length=240)
    classification: str | None = Field(default=None, max_length=32)
    executive_summary: str | None = Field(default=None, max_length=40000)
    conclusion: str | None = Field(default=None, max_length=40000)
    distribution_list: list[str] | None = None
    spec: ReportSpec | None = None


class ReportArtifactOut(ORMModel):
    id: uuid.UUID
    format: ReportFormat
    filename: str
    size_bytes: int
    sha256: str
    page_count: int | None
    render_duration_ms: int | None
    created_at: datetime


class ReportSummaryOut(ORMModel):
    id: uuid.UUID
    reference: str
    case_id: uuid.UUID
    title: str
    version: int
    status: ReportStatus
    classification: str
    evidence_count: int
    finding_count: int
    integrity_verified_count: int
    integrity_failed_count: int
    custody_chain_intact: bool | None
    snapshot_sha256: str | None
    is_signed: bool
    prepared_by: ActorRef | None
    prepared_at: datetime | None
    reviewed_by: ActorRef | None
    reviewed_at: datetime | None
    signed_at: datetime | None
    created_at: datetime
    updated_at: datetime


class ReportDetailOut(ReportSummaryOut):
    executive_summary: str | None
    conclusion: str | None
    distribution_list: list[Any]
    spec: dict[str, Any]
    snapshot_captured_at: datetime | None
    review_note: str | None
    signing_key_id: str | None
    superseded_by_id: uuid.UUID | None
    artifacts: list[ReportArtifactOut]


class ReportSubmitRequest(BaseModel):
    note: str | None = Field(default=None, max_length=4000)


class ReportReviewRequest(BaseModel):
    note: str = Field(min_length=3, max_length=4000)


class ReportVerifyOut(BaseModel):
    report_id: uuid.UUID
    reference: str
    snapshot_sha256: str | None
    signature_present: bool
    signature_valid: bool
    signing_key_id: str | None
    status: ReportStatus
    detail: str
