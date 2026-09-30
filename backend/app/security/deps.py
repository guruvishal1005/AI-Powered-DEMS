"""FastAPI security dependencies.

``require(...)`` is the single gate through which every protected endpoint passes. It is
written so that a denial is *recorded* rather than merely refused: an attempt to reach
something you may not reach is exactly the signal a forensic platform must keep, and it is
written with its own short-lived session and committed immediately so the record survives the
rollback of the request that triggered it.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from datetime import timedelta
from typing import Annotated

from fastapi import Depends, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.audit.writer import append_audit
from app.core.clock import utcnow
from app.core.context import RequestContext
from app.core.errors import AuthenticationRequired, PermissionDenied
from app.db.session import SessionLocal, get_db
from app.models.enums import AuditResult, Permission, UserStatus
from app.models.user import User, UserSession

# Writing last_seen_at on every request would mean a database write per API call for no real
# benefit, so it is only refreshed once the stored value is this stale.
SESSION_TOUCH_INTERVAL = timedelta(seconds=60)


def client_ip(request: Request) -> str | None:
    """Best-effort client address.

    ``X-Forwarded-For`` is honoured because this service is expected to sit behind a reverse
    proxy in any real deployment. It is only meaningful when that proxy is trusted to
    overwrite the header; a directly exposed deployment must not trust it.
    """
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()[:64]
    return request.client.host if request.client else None


def _bearer_token(request: Request) -> str:
    header = request.headers.get("authorization")
    if not header or not header.lower().startswith("bearer "):
        raise AuthenticationRequired("Authentication is required")
    token = header[7:].strip()
    if not token:
        raise AuthenticationRequired("Authentication is required")
    return token


def get_context(
    request: Request,
    db: Annotated[Session, Depends(get_db)],
) -> RequestContext:
    """Resolve the caller into a :class:`RequestContext`, or refuse the request.

    Permissions are read from the database here, not from the token, so a suspension or role
    change applies to the very next request.
    """
    from app.security.tokens import decode_access_token

    claims = decode_access_token(_bearer_token(request))

    user = db.execute(select(User).where(User.id == claims.user_id)).scalar_one_or_none()
    if user is None:
        raise AuthenticationRequired("Account no longer exists")
    if user.status is not UserStatus.active:
        raise AuthenticationRequired(f"Account is {user.status.value}")
    if user.locked_until is not None and user.locked_until > utcnow():
        raise AuthenticationRequired("Account is temporarily locked")

    session_row = db.execute(
        select(UserSession).where(UserSession.id == claims.session_id)
    ).scalar_one_or_none()
    if session_row is None or session_row.user_id != user.id:
        raise AuthenticationRequired("Session not recognised")
    if session_row.revoked_at is not None:
        raise AuthenticationRequired("Session has been revoked")
    if session_row.expires_at <= utcnow():
        raise AuthenticationRequired("Session has expired")

    now = utcnow()
    if now - session_row.last_seen_at > SESSION_TOUCH_INTERVAL:
        session_row.last_seen_at = now
        db.commit()

    return RequestContext.for_user(
        user,
        permissions=user.permission_codes,
        ip_address=client_ip(request),
        user_agent=(request.headers.get("user-agent") or "")[:512] or None,
        request_id=getattr(request.state, "request_id", None),
        session_id=session_row.id,
    )


CurrentContext = Annotated[RequestContext, Depends(get_context)]


def get_current_user(
    ctx: CurrentContext,
    db: Annotated[Session, Depends(get_db)],
) -> User:
    user = db.execute(select(User).where(User.id == ctx.actor_id)).scalar_one_or_none()
    if user is None:
        raise AuthenticationRequired("Account no longer exists")
    return user


CurrentUser = Annotated[User, Depends(get_current_user)]


def _record_denial(
    ctx: RequestContext,
    request: Request,
    missing: tuple[Permission, ...],
) -> None:
    """Persist a denied attempt in its own transaction.

    The request that caused this is about to raise, and its session will be rolled back. A
    separate session keeps the record, which is the whole point: refusals must be as durable
    as successes.
    """
    with SessionLocal() as session:
        try:
            append_audit(
                session,
                ctx,
                action="access.denied",
                resource_type="endpoint",
                resource_id=request.url.path,
                resource_label=f"{request.method} {request.url.path}",
                result=AuditResult.denied,
                detail="missing permission(s): " + ", ".join(p.value for p in missing),
                http_method=request.method,
                http_path=str(request.url.path),
                status_code=403,
            )
            session.commit()
        except Exception:
            session.rollback()
            raise


def require(*permissions: Permission) -> Callable[..., RequestContext]:
    """Dependency factory enforcing that the caller holds every listed permission."""

    def dependency(request: Request, ctx: CurrentContext) -> RequestContext:
        missing = tuple(permission for permission in permissions if not ctx.has(permission))
        if missing:
            _record_denial(ctx, request, missing)
            readable = ", ".join(permission.value for permission in missing)
            raise PermissionDenied(
                f"This action requires: {readable}",
                details={"missing_permissions": [p.value for p in missing]},
            )
        return ctx

    return dependency


def require_any(*permissions: Permission) -> Callable[..., RequestContext]:
    """As :func:`require`, but satisfied by holding any one of the listed permissions."""

    def dependency(request: Request, ctx: CurrentContext) -> RequestContext:
        if not any(ctx.has(permission) for permission in permissions):
            _record_denial(ctx, request, permissions)
            readable = " or ".join(permission.value for permission in permissions)
            raise PermissionDenied(
                f"This action requires: {readable}",
                details={"missing_permissions": [p.value for p in permissions]},
            )
        return ctx

    return dependency


def resolve_actor_id(ctx: RequestContext) -> uuid.UUID:
    """Actor id for contexts that must be user-driven (never the system worker)."""
    if ctx.actor_id is None:
        raise PermissionDenied("This action requires an authenticated user")
    return ctx.actor_id
