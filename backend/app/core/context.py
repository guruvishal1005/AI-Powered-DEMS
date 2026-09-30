"""Request context.

Every service method takes a :class:`RequestContext` instead of reading globals. This is
what makes attribution structural rather than optional: a service physically cannot write
a custody event or audit entry without knowing who caused it, so "who did this?" can never
be answered with *unknown* because a call site forgot to pass the actor along.

Background work uses :func:`system_context`, which is attributed to the platform itself
and always records why it ran.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Self

if TYPE_CHECKING:
    from app.models.user import User

SYSTEM_ACTOR_LABEL = "system"


@dataclass(frozen=True, slots=True)
class RequestContext:
    """Who is acting, from where, and under which request."""

    actor_id: uuid.UUID | None
    actor_label: str
    permissions: frozenset[str] = field(default_factory=frozenset)
    roles: tuple[str, ...] = ()
    ip_address: str | None = None
    user_agent: str | None = None
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    session_id: uuid.UUID | None = None
    # True only for background work. Grants a permission bypass; see :meth:`has`.
    is_system: bool = False
    # A protected account that cannot be disabled or stripped of administration. Confers no
    # permission bypass.
    is_superuser: bool = False
    reason: str | None = None

    @classmethod
    def for_user(
        cls,
        user: User,
        *,
        permissions: frozenset[str],
        ip_address: str | None = None,
        user_agent: str | None = None,
        request_id: str | None = None,
        session_id: uuid.UUID | None = None,
    ) -> Self:
        return cls(
            actor_id=user.id,
            actor_label=user.email,
            permissions=permissions,
            roles=tuple(role.slug for role in user.roles),
            ip_address=ip_address,
            user_agent=user_agent,
            request_id=request_id or str(uuid.uuid4()),
            session_id=session_id,
            is_superuser=user.is_superuser,
        )

    def has(self, permission: str) -> bool:
        """Whether the actor holds a permission.

        Note what deliberately does *not* grant a bypass here: ``is_superuser``. A protected
        account is protected from being locked out of user management, but it is not exempt
        from the permission table. If it were, controls such as "administrators cannot
        download evidence content" would be defeated by a single boolean, which is exactly
        the kind of quiet exception that makes separation of duties meaningless.

        Only :func:`system_context` bypasses, because background work is not user-driven and
        is still fully attributed in the audit trail.
        """
        if self.is_system:
            return True
        return permission in self.permissions

    def with_reason(self, reason: str) -> RequestContext:
        """Attach an investigator-supplied justification (required for downloads)."""
        return RequestContext(
            actor_id=self.actor_id,
            actor_label=self.actor_label,
            permissions=self.permissions,
            roles=self.roles,
            ip_address=self.ip_address,
            user_agent=self.user_agent,
            request_id=self.request_id,
            session_id=self.session_id,
            is_system=self.is_system,
            is_superuser=self.is_superuser,
            reason=reason,
        )


def system_context(reason: str, *, request_id: str | None = None) -> RequestContext:
    """Context for scheduled jobs and worker tasks.

    System work is trusted for permissions (it is not user-driven) but is still fully
    attributed in the audit trail, and always states the reason it ran.
    """
    return RequestContext(
        actor_id=None,
        actor_label=SYSTEM_ACTOR_LABEL,
        permissions=frozenset(),
        ip_address=None,
        user_agent="cybertrace-worker",
        request_id=request_id or str(uuid.uuid4()),
        is_system=True,
        reason=reason,
    )
