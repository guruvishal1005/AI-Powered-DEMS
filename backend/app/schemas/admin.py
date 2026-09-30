"""Administration and compliance request/response shapes."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, EmailStr, Field

from app.core.config import settings
from app.models.enums import BackupStatus, DispositionAction, JobStatus, UserStatus
from app.schemas.auth import RoleSummary
from app.schemas.common import ORMModel


class PermissionOut(ORMModel):
    id: uuid.UUID
    code: str
    category: str
    label: str
    description: str
    is_sensitive: bool


class RoleDetailOut(RoleSummary):
    is_system: bool
    permissions: list[PermissionOut]
    user_count: int = 0


class RoleUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=2, max_length=96)
    description: str | None = Field(default=None, max_length=2000)
    permission_codes: list[str] | None = None


class UserCreate(BaseModel):
    email: EmailStr
    full_name: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=settings.password_min_length, max_length=256)
    job_title: str | None = Field(default=None, max_length=96)
    department: str | None = Field(default=None, max_length=96)
    badge_number: str | None = Field(default=None, max_length=32)
    phone: str | None = Field(default=None, max_length=32)
    role_slugs: list[str] = Field(min_length=1)
    must_change_password: bool = True


class UserUpdate(BaseModel):
    full_name: str | None = Field(default=None, min_length=1, max_length=128)
    job_title: str | None = Field(default=None, max_length=96)
    department: str | None = Field(default=None, max_length=96)
    badge_number: str | None = Field(default=None, max_length=32)
    phone: str | None = Field(default=None, max_length=32)
    timezone: str | None = Field(default=None, max_length=64)
    status: UserStatus | None = None
    role_slugs: list[str] | None = None


class UserSummaryOut(ORMModel):
    id: uuid.UUID
    email: str
    full_name: str
    job_title: str | None
    department: str | None
    badge_number: str | None
    status: UserStatus
    is_superuser: bool
    mfa_enabled: bool
    last_login_at: datetime | None
    locked_until: datetime | None
    roles: list[RoleSummary]
    created_at: datetime


class UserDetailOut(UserSummaryOut):
    phone: str | None
    timezone: str
    must_change_password: bool
    failed_login_count: int
    initials: str


class ResetPasswordRequest(BaseModel):
    new_password: str = Field(min_length=settings.password_min_length, max_length=256)
    must_change_password: bool = True


class SystemSettingOut(ORMModel):
    key: str
    value: dict[str, Any]
    category: str
    label: str
    description: str
    is_sensitive: bool
    updated_at: datetime


class SystemSettingUpdate(BaseModel):
    value: dict[str, Any]


class RetentionPolicyCreate(BaseModel):
    name: str = Field(min_length=2, max_length=96)
    description: str = Field(default="", max_length=4000)
    criteria: dict[str, Any] = Field(default_factory=dict)
    retention_days: int = Field(ge=1, le=36500)
    disposition_action: DispositionAction = DispositionAction.review
    requires_review: bool = True
    warn_days_before: int = Field(default=30, ge=0, le=365)
    is_default: bool = False
    enabled: bool = True


class RetentionPolicyOut(ORMModel):
    id: uuid.UUID
    name: str
    description: str
    criteria: dict[str, Any]
    retention_days: int
    disposition_action: DispositionAction
    requires_review: bool
    warn_days_before: int
    is_default: bool
    enabled: bool
    created_at: datetime
    updated_at: datetime


class LegalHoldCreate(BaseModel):
    case_id: uuid.UUID | None = None
    evidence_id: uuid.UUID | None = None
    reason: str = Field(min_length=8, max_length=4000)
    authority: str | None = Field(default=None, max_length=160)
    reference: str | None = Field(default=None, max_length=64)


class LegalHoldOut(ORMModel):
    id: uuid.UUID
    reference: str
    case_id: uuid.UUID | None
    evidence_id: uuid.UUID | None
    reason: str
    authority: str | None
    applied_by_id: uuid.UUID | None
    released_at: datetime | None
    release_reason: str | None
    created_at: datetime


class LegalHoldRelease(BaseModel):
    reason: str = Field(min_length=8, max_length=4000)


class JobOut(ORMModel):
    id: uuid.UUID
    task: str
    status: JobStatus
    priority: int
    attempts: int
    max_attempts: int
    created_at: datetime
    run_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    duration_ms: int | None
    last_error: str | None
    case_id: uuid.UUID | None
    evidence_id: uuid.UUID | None
    dedupe_key: str | None


class JobStatsOut(BaseModel):
    by_status: dict[str, int]
    queue_depth: int
    running: int
    failed_24h: int
    oldest_queued_at: datetime | None


class PeriodicTaskOut(ORMModel):
    id: uuid.UUID
    name: str
    task: str
    description: str
    interval_seconds: int
    enabled: bool
    next_run_at: datetime
    last_run_at: datetime | None
    last_status: str | None
    last_error: str | None
    run_count: int


class PeriodicTaskUpdate(BaseModel):
    enabled: bool | None = None
    interval_seconds: int | None = Field(default=None, ge=30, le=86400 * 30)


class BackupOut(ORMModel):
    id: uuid.UUID
    kind: str
    status: BackupStatus
    started_at: datetime
    finished_at: datetime | None
    duration_ms: int | None
    storage_key: str | None
    size_bytes: int | None
    object_count: int
    sha256: str | None
    custody_chain_verified: bool | None
    audit_chain_verified: bool | None
    restore_verified: bool | None
    verification_note: str | None
    error: str | None


class HealthSampleOut(ORMModel):
    queue_depth: int
    jobs_running: int
    jobs_failed_24h: int
    evidence_count: int
    storage_bytes: int
    integrity_failures: int
    open_alerts: int
    worst_alert_severity: str | None
    details: dict[str, Any]
    created_at: datetime


class SystemHealthOut(BaseModel):
    status: str
    version: str
    environment: str
    queue: JobStatsOut
    latest_sample: HealthSampleOut | None
    samples: list[HealthSampleOut]
    storage_bytes: int
    storage_objects: int


class ApiTokenCreate(BaseModel):
    name: str = Field(min_length=2, max_length=96)
    scopes: list[str] = Field(default_factory=list)
    expires_at: datetime | None = None


class ApiTokenCreatedOut(BaseModel):
    """Returned once. The secret is never stored in recoverable form."""

    id: uuid.UUID
    name: str
    prefix: str
    token: str
    scopes: list[Any]
    expires_at: datetime | None
    created_at: datetime


class ApiTokenOut(ORMModel):
    id: uuid.UUID
    name: str
    prefix: str
    scopes: list[Any]
    expires_at: datetime | None
    last_used_at: datetime | None
    revoked_at: datetime | None
    created_at: datetime
