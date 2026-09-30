"""Authentication schemas."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, EmailStr, Field

from app.core.config import settings
from app.schemas.common import ORMModel


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=256)
    # Purely cosmetic: lets a user recognise a device in their session list.
    device_label: str | None = Field(default=None, max_length=128)


class RoleSummary(ORMModel):
    id: uuid.UUID
    slug: str
    name: str
    description: str
    rank: int


class AuthenticatedUser(ORMModel):
    """The caller's own profile, including the permissions actually in force."""

    id: uuid.UUID
    email: str
    full_name: str
    job_title: str | None
    department: str | None
    badge_number: str | None
    phone: str | None
    status: str
    timezone: str
    initials: str
    mfa_enabled: bool
    must_change_password: bool
    last_login_at: datetime | None
    roles: list[RoleSummary]
    permissions: list[str]


class LoginResponse(BaseModel):
    """Access token is returned in the body for the SPA to hold in memory only.

    The refresh token is not here: it is set as an ``httpOnly`` cookie so that script cannot
    read it. The CSRF token is returned so the client can echo it back on refresh and logout.
    """

    access_token: str
    token_type: str = "bearer"  # noqa: S105 - OAuth2 token type, not a secret
    expires_in: int = settings.access_token_ttl_seconds
    expires_at: datetime
    csrf_token: str
    user: AuthenticatedUser


class RefreshResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"  # noqa: S105 - OAuth2 token type, not a secret
    expires_in: int = settings.access_token_ttl_seconds
    expires_at: datetime
    csrf_token: str


class ChangePasswordRequest(BaseModel):
    current_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=settings.password_min_length, max_length=256)


class SessionSummary(ORMModel):
    id: uuid.UUID
    created_at: datetime
    last_seen_at: datetime
    expires_at: datetime
    ip_address: str | None
    user_agent: str | None
    device_label: str | None
    revoked_at: datetime | None
    is_current: bool = False


class UpdateProfileRequest(BaseModel):
    full_name: str | None = Field(default=None, min_length=1, max_length=128)
    job_title: str | None = Field(default=None, max_length=96)
    department: str | None = Field(default=None, max_length=96)
    phone: str | None = Field(default=None, max_length=32)
    timezone: str | None = Field(default=None, max_length=64)
