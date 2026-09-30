"""Authentication endpoints.

Cookie handling deserves a note. The refresh cookie is scoped to the auth path rather than
the whole site, so it is only ever transmitted on the handful of requests that actually need
it - an ordinary API call cannot leak it, and a bug elsewhere cannot read it. The CSRF cookie
is intentionally *not* ``httpOnly``, because the client has to read it in order to echo it
back in a header; that is the entire mechanism of a double-submit check.
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Request, Response, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.errors import AuthenticationRequired, PermissionDenied
from app.db.session import get_db
from app.models.user import User, UserSession
from app.schemas.auth import (
    AuthenticatedUser,
    ChangePasswordRequest,
    LoginRequest,
    LoginResponse,
    RefreshResponse,
    SessionSummary,
    UpdateProfileRequest,
)
from app.schemas.common import OperationResult
from app.security.deps import CurrentContext, CurrentUser, client_ip
from app.security.tokens import create_csrf_token, verify_csrf
from app.services import auth_service

router = APIRouter(prefix="/auth", tags=["Authentication"])

DbSession = Annotated[Session, Depends(get_db)]

CSRF_HEADER = "X-CSRF-Token"


def _cookie_path() -> str:
    return f"{settings.api_prefix}/auth"


def _set_auth_cookies(response: Response, *, refresh_token: str, csrf_token: str) -> None:
    response.set_cookie(
        settings.refresh_cookie_name,
        refresh_token,
        max_age=settings.refresh_token_ttl_seconds,
        httponly=True,
        secure=settings.cookie_secure,
        samesite=settings.cookie_samesite,
        domain=settings.cookie_domain,
        path=_cookie_path(),
    )
    response.set_cookie(
        settings.csrf_cookie_name,
        csrf_token,
        max_age=settings.refresh_token_ttl_seconds,
        # Readable by same-origin script by design: the client must echo it in a header.
        httponly=False,
        secure=settings.cookie_secure,
        samesite=settings.cookie_samesite,
        domain=settings.cookie_domain,
        path="/",
    )


def _clear_auth_cookies(response: Response) -> None:
    response.delete_cookie(
        settings.refresh_cookie_name, path=_cookie_path(), domain=settings.cookie_domain
    )
    response.delete_cookie(settings.csrf_cookie_name, path="/", domain=settings.cookie_domain)


def _authenticated_user(user: User) -> AuthenticatedUser:
    return AuthenticatedUser(
        id=user.id,
        email=user.email,
        full_name=user.full_name,
        job_title=user.job_title,
        department=user.department,
        badge_number=user.badge_number,
        phone=user.phone,
        status=user.status.value,
        timezone=user.timezone,
        initials=user.initials,
        mfa_enabled=user.mfa_enabled,
        must_change_password=user.must_change_password,
        last_login_at=user.last_login_at,
        roles=sorted(user.roles, key=lambda role: -role.rank),
        permissions=sorted(user.permission_codes),
    )


@router.post("/login", response_model=LoginResponse)
def login(
    payload: LoginRequest,
    request: Request,
    response: Response,
    db: DbSession,
) -> LoginResponse:
    result = auth_service.authenticate(
        db,
        email=payload.email,
        password=payload.password,
        ip_address=client_ip(request),
        user_agent=(request.headers.get("user-agent") or "")[:512] or None,
        device_label=payload.device_label,
    )
    _set_auth_cookies(response, refresh_token=result.refresh.token, csrf_token=result.csrf_token)
    return LoginResponse(
        access_token=result.access_token,
        expires_at=result.access_expires_at,
        csrf_token=result.csrf_token,
        user=_authenticated_user(result.user),
    )


@router.post("/refresh", response_model=RefreshResponse)
def refresh(request: Request, response: Response, db: DbSession) -> RefreshResponse:
    """Exchange the refresh cookie for a new access token.

    Requires the CSRF double-submit to match, because this endpoint authenticates from a
    cookie and would otherwise be reachable cross-site.
    """
    if not verify_csrf(
        request.cookies.get(settings.csrf_cookie_name), request.headers.get(CSRF_HEADER)
    ):
        raise PermissionDenied("CSRF validation failed")

    presented = request.cookies.get(settings.refresh_cookie_name)
    if not presented:
        raise AuthenticationRequired("No session cookie present")

    result = auth_service.rotate_refresh_token(
        db,
        presented_token=presented,
        ip_address=client_ip(request),
        user_agent=(request.headers.get("user-agent") or "")[:512] or None,
    )
    _set_auth_cookies(response, refresh_token=result.refresh.token, csrf_token=result.csrf_token)
    return RefreshResponse(
        access_token=result.access_token,
        expires_at=result.access_expires_at,
        csrf_token=result.csrf_token,
    )


@router.post("/logout", response_model=OperationResult)
def logout(
    request: Request,
    response: Response,
    ctx: CurrentContext,
    db: DbSession,
) -> OperationResult:
    auth_service.logout(db, ctx, session_id=ctx.session_id)
    _clear_auth_cookies(response)
    return OperationResult(message="Signed out")


@router.get("/me", response_model=AuthenticatedUser)
def read_me(user: CurrentUser) -> AuthenticatedUser:
    return _authenticated_user(user)


@router.patch("/me", response_model=AuthenticatedUser)
def update_me(
    payload: UpdateProfileRequest,
    user: CurrentUser,
    ctx: CurrentContext,
    db: DbSession,
) -> AuthenticatedUser:
    from app.audit.writer import append_audit

    before = {
        "full_name": user.full_name,
        "job_title": user.job_title,
        "department": user.department,
        "phone": user.phone,
        "timezone": user.timezone,
    }
    for field, value in payload.model_dump(exclude_unset=True).items():
        if value is not None:
            setattr(user, field, value)

    append_audit(
        db,
        ctx,
        action="user.profile_updated",
        resource_type="user",
        resource_id=user.id,
        resource_label=user.email,
        before_state=before,
        after_state=payload.model_dump(exclude_unset=True),
    )
    db.commit()
    return _authenticated_user(user)


@router.post("/password", response_model=OperationResult)
def change_password(
    payload: ChangePasswordRequest,
    request: Request,
    response: Response,
    user: CurrentUser,
    ctx: CurrentContext,
    db: DbSession,
) -> OperationResult:
    auth_service.change_password(
        db,
        ctx,
        user,
        current_password=payload.current_password,
        new_password=payload.new_password,
        current_session_id=ctx.session_id,
    )
    # The current session survives, but its refresh token chain is reissued so the cookie
    # cannot outlive the credential change.
    _clear_auth_cookies(response)
    return OperationResult(
        message="Password changed. Other sessions have been signed out; please sign in again."
    )


@router.get("/sessions", response_model=list[SessionSummary])
def list_sessions(user: CurrentUser, ctx: CurrentContext, db: DbSession) -> list[SessionSummary]:
    rows = (
        db.execute(
            select(UserSession)
            .where(UserSession.user_id == user.id)
            .where(UserSession.revoked_at.is_(None))
            .order_by(UserSession.last_seen_at.desc())
        )
        .scalars()
        .all()
    )
    return [
        SessionSummary.model_validate(row).model_copy(
            update={"is_current": row.id == ctx.session_id}
        )
        for row in rows
    ]


@router.delete(
    "/sessions/{session_id}",
    response_model=OperationResult,
    status_code=status.HTTP_200_OK,
)
def revoke_session(
    session_id: uuid.UUID,
    user: CurrentUser,
    ctx: CurrentContext,
    db: DbSession,
) -> OperationResult:
    auth_service.revoke_session(db, ctx, session_id=session_id, actor_user=user)
    return OperationResult(message="Session revoked")


@router.get("/csrf", response_model=OperationResult)
def issue_csrf(response: Response) -> OperationResult:
    """Issue a CSRF cookie before signing in.

    The login form itself is not CSRF-sensitive, but the client needs the cookie in place for
    the refresh call that follows, and fetching it separately keeps that flow uniform.
    """
    token = create_csrf_token()
    response.set_cookie(
        settings.csrf_cookie_name,
        token,
        max_age=settings.refresh_token_ttl_seconds,
        httponly=False,
        secure=settings.cookie_secure,
        samesite=settings.cookie_samesite,
        path="/",
    )
    return OperationResult(message=token)
