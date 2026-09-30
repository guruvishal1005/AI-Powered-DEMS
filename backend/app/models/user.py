"""Identity, roles and session models.

Permissions live in the database rather than in code constants so an administrator can
genuinely re-map what a role may do at runtime. :data:`app.models.enums.Permission` is the
authoritative catalogue of codes; the ``permissions`` table is the editable projection of it.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Table,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import CITEXT
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, CreatedAtMixin, TimestampMixin, UUIDPrimaryKey
from app.models.enums import UserStatus, enum_type

if TYPE_CHECKING:
    from app.models.case import Case, CaseAssignment

role_permissions = Table(
    "role_permissions",
    Base.metadata,
    Column("role_id", ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True),
    Column("permission_id", ForeignKey("permissions.id", ondelete="CASCADE"), primary_key=True),
)

user_roles = Table(
    "user_roles",
    Base.metadata,
    Column("user_id", ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
    Column("role_id", ForeignKey("roles.id", ondelete="RESTRICT"), primary_key=True),
)


class PermissionRecord(UUIDPrimaryKey, Base):
    """One atomic capability, e.g. ``evidence:download``."""

    __tablename__ = "permissions"

    code: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    category: Mapped[str] = mapped_column(String(32), nullable=False)
    label: Mapped[str] = mapped_column(String(96), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    # Marks grants whose misuse is most consequential, so the admin UI can warn before
    # attaching them to a role.
    is_sensitive: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    roles: Mapped[list[Role]] = relationship(
        secondary=role_permissions, back_populates="permissions"
    )


class Role(UUIDPrimaryKey, TimestampMixin, Base):
    __tablename__ = "roles"

    slug: Mapped[str] = mapped_column(String(48), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(96), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    # System roles may be re-permissioned but never deleted, so the platform cannot be
    # left with no way to administer it.
    is_system: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    # Higher rank wins when displaying a user's primary role.
    rank: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    permissions: Mapped[list[PermissionRecord]] = relationship(
        secondary=role_permissions, back_populates="roles", lazy="selectin"
    )
    users: Mapped[list[User]] = relationship(secondary=user_roles, back_populates="roles")

    @property
    def permission_codes(self) -> frozenset[str]:
        return frozenset(permission.code for permission in self.permissions)


class User(UUIDPrimaryKey, TimestampMixin, Base):
    __tablename__ = "users"

    email: Mapped[str] = mapped_column(CITEXT(), unique=True, nullable=False)
    full_name: Mapped[str] = mapped_column(String(128), nullable=False)
    password_hash: Mapped[str] = mapped_column(String(256), nullable=False)

    # Professional identity, quoted in reports and custody records.
    badge_number: Mapped[str | None] = mapped_column(String(32))
    job_title: Mapped[str | None] = mapped_column(String(96))
    department: Mapped[str | None] = mapped_column(String(96))
    phone: Mapped[str | None] = mapped_column(String(32))

    status: Mapped[UserStatus] = mapped_column(
        enum_type(UserStatus), nullable=False, default=UserStatus.active
    )
    is_superuser: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    must_change_password: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    # Account protection state, driven by app.services.auth_service.
    failed_login_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    password_changed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    mfa_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    mfa_secret: Mapped[str | None] = mapped_column(String(256))

    timezone: Mapped[str] = mapped_column(String(64), nullable=False, default="UTC")
    preferences: Mapped[dict[str, Any]] = mapped_column(nullable=False, default=dict)

    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )

    roles: Mapped[list[Role]] = relationship(
        secondary=user_roles, back_populates="users", lazy="selectin"
    )
    sessions: Mapped[list[UserSession]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )
    owned_cases: Mapped[list[Case]] = relationship(
        back_populates="lead_investigator",
        foreign_keys="Case.lead_investigator_id",
    )
    case_assignments: Mapped[list[CaseAssignment]] = relationship(
        back_populates="user",
        foreign_keys="CaseAssignment.user_id",
        cascade="all, delete-orphan",
    )

    @property
    def permission_codes(self) -> frozenset[str]:
        """Union of every permission granted by the user's roles."""
        codes: set[str] = set()
        for role in self.roles:
            codes.update(role.permission_codes)
        return frozenset(codes)

    @property
    def primary_role(self) -> Role | None:
        return max(self.roles, key=lambda role: role.rank, default=None)

    @property
    def initials(self) -> str:
        parts = [part for part in self.full_name.split() if part]
        if not parts:
            return "?"
        if len(parts) == 1:
            return parts[0][:2].upper()
        return (parts[0][0] + parts[-1][0]).upper()


class UserSession(UUIDPrimaryKey, Base):
    """A signed-in device.

    Sessions are separated from the refresh tokens they issue so that a token can rotate
    on every use while the session (and therefore the device entry a user sees in
    settings) stays stable and independently revocable.
    """

    __tablename__ = "user_sessions"

    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_reason: Mapped[str | None] = mapped_column(String(96))

    ip_address: Mapped[str | None] = mapped_column(String(64))
    user_agent: Mapped[str | None] = mapped_column(String(512))
    device_label: Mapped[str | None] = mapped_column(String(128))

    user: Mapped[User] = relationship(back_populates="sessions")
    refresh_tokens: Mapped[list[RefreshToken]] = relationship(
        back_populates="session", cascade="all, delete-orphan"
    )

    @property
    def is_active(self) -> bool:
        return self.revoked_at is None


class RefreshToken(UUIDPrimaryKey, Base):
    """A single-use refresh token.

    Only the SHA-256 of the token is stored, so a database disclosure does not yield
    usable credentials. Rotation is recorded via ``replaced_by_id``: if a token that has
    already been used is presented again, that indicates theft or replay, and the whole
    session is revoked rather than just the token.
    """

    __tablename__ = "refresh_tokens"

    session_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("user_sessions.id", ondelete="CASCADE"), nullable=False, index=True
    )
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    replaced_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("refresh_tokens.id", ondelete="SET NULL")
    )

    session: Mapped[UserSession] = relationship(back_populates="refresh_tokens")


class LoginAttempt(UUIDPrimaryKey, CreatedAtMixin, Base):
    """Every authentication attempt, successful or not.

    Recorded against the submitted email rather than only a resolved user, so attempts
    against non-existent accounts (enumeration probes) are still visible.
    """

    __tablename__ = "login_attempts"
    __table_args__ = (Index("ix_login_attempts_email_created", "email", "created_at"),)

    email: Mapped[str] = mapped_column(String(255), nullable=False)
    user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    successful: Mapped[bool] = mapped_column(Boolean, nullable=False)
    failure_reason: Mapped[str | None] = mapped_column(String(64))
    ip_address: Mapped[str | None] = mapped_column(String(64), index=True)
    user_agent: Mapped[str | None] = mapped_column(String(512))


class ApiToken(UUIDPrimaryKey, CreatedAtMixin, Base):
    """Long-lived token for scripted access, scoped to a subset of the owner's permissions."""

    __tablename__ = "api_tokens"
    __table_args__ = (UniqueConstraint("user_id", "name", name="uq_api_tokens_user_id_name"),)

    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(96), nullable=False)
    # Displayed prefix lets a user identify a token without revealing it.
    prefix: Mapped[str] = mapped_column(String(16), nullable=False)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    scopes: Mapped[list[Any]] = mapped_column(nullable=False, default=list)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    user: Mapped[User] = relationship()
