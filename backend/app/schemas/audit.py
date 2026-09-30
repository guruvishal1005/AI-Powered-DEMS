"""Audit-log query shapes."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel

from app.schemas.common import ORMModel


class AuditEntryOut(ORMModel):
    id: uuid.UUID
    sequence: int
    action: str
    resource_type: str
    resource_id: str | None
    resource_label: str | None
    actor_id: uuid.UUID | None
    actor_label: str
    actor_roles: list[Any]
    result: str
    case_id: uuid.UUID | None
    ip_address: str | None
    request_id: str | None
    http_method: str | None
    http_path: str | None
    status_code: int | None
    before_state: dict[str, Any] | None
    after_state: dict[str, Any] | None
    reason: str | None
    detail: str | None
    recorded_at: datetime
    previous_hash: str | None
    entry_hash: str
    signing_key_id: str | None


class AuditChainStatusOut(BaseModel):
    entries_checked: int
    intact: bool
    summary: str
    head_hash: str | None
    first_sequence: int | None
    last_sequence: int | None
    signatures_checked: int
    signatures_valid: int
    breaks: list[dict[str, Any]]
    verified_at: datetime


class SearchHitOut(BaseModel):
    kind: str
    id: uuid.UUID
    reference: str | None
    title: str
    subtitle: str | None = None
    href: str


class SearchResultsOut(BaseModel):
    query: str
    cases: list[SearchHitOut]
    evidence: list[SearchHitOut]
    entities: list[SearchHitOut]
    hashes: list[SearchHitOut]
