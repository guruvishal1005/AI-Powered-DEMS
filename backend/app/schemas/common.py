"""Shared response shapes."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class ORMModel(BaseModel):
    """Base for response models read directly from ORM instances."""

    model_config = ConfigDict(from_attributes=True)


class ErrorDetail(BaseModel):
    """Uniform error envelope.

    ``code`` is a stable machine-readable identifier so the frontend can branch on the kind
    of failure without matching on human-readable prose.
    """

    code: str
    message: str
    details: dict[str, Any] = Field(default_factory=dict)
    request_id: str | None = None


class ErrorResponse(BaseModel):
    error: ErrorDetail


class ActorRef(ORMModel):
    """Compact user reference for embedding in other responses."""

    id: uuid.UUID
    full_name: str
    email: str
    job_title: str | None = None
    badge_number: str | None = None


class CaseRef(ORMModel):
    id: uuid.UUID
    reference: str
    title: str


class EvidenceRef(ORMModel):
    id: uuid.UUID
    reference: str
    title: str
    original_filename: str


class CountByLabel(BaseModel):
    label: str
    count: int


class TimeBucket(BaseModel):
    bucket_start: datetime
    count: int


class OperationResult(BaseModel):
    ok: bool = True
    message: str | None = None
