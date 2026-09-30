"""Timeline request and response shapes.

A timeline is assembled from several independently recorded sources (custody, observations,
findings, lifecycle, alerts). The wire format therefore always names the source of each event,
so a reconstruction can never be mistaken for a single homogeneous log.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

from app.models.enums import ObservationKind, Severity
from app.schemas.common import ORMModel

TimelineSource = Literal[
    "custody",
    "observation",
    "analysis_finding",
    "finding",
    "lifecycle",
    "alert",
    "integrity",
]


class TimelineEventOut(BaseModel):
    """One point on the reconstructed timeline."""

    id: str
    source: TimelineSource
    occurred_at: datetime
    recorded_at: datetime | None = None
    time_confidence: str | None = None
    timezone_assumed: bool = False
    kind: str
    title: str
    summary: str | None = None
    severity: Severity | None = None
    case_id: uuid.UUID | None = None
    evidence_id: uuid.UUID | None = None
    evidence_reference: str | None = None
    actor_label: str | None = None
    locator: dict[str, Any] = Field(default_factory=dict)
    excerpt: str | None = None
    attributes: dict[str, Any] = Field(default_factory=dict)


class TimelineBucketOut(BaseModel):
    """A zoom-level aggregate. Returned when the requested window is too dense to plot raw."""

    bucket_start: datetime
    bucket_end: datetime
    count: int
    by_source: dict[str, int]
    by_kind: dict[str, int]
    peak_severity: Severity | None = None


class TimelineOut(BaseModel):
    """Either raw events or buckets, never both mixed without saying so."""

    case_id: uuid.UUID | None
    window_start: datetime | None
    window_end: datetime | None
    resolution: Literal["raw", "minute", "hour", "day"]
    total: int
    events: list[TimelineEventOut]
    buckets: list[TimelineBucketOut]
    sources: dict[str, int]


class ObservationOut(ORMModel):
    id: uuid.UUID
    evidence_id: uuid.UUID
    case_id: uuid.UUID
    kind: ObservationKind
    occurred_at: datetime
    time_confidence: str
    timezone_assumed: bool
    summary: str
    actor_value: str | None
    source_value: str | None
    target_value: str | None
    outcome: str | None
    analyzer: str
    analyzer_version: str
    locator: dict[str, Any]
    excerpt: str | None
    attributes: dict[str, Any]
    created_at: datetime
