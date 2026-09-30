"""Authentication and session lifecycle.

Design points that are security-relevant rather than incidental:

**Uniform failure.** A wrong password, an unknown address and a disabled account all produce
the same ``invalid_credentials`` response, and an unknown address still performs a password
verification against a dummy hash. Without that, response timing and wording would let an
attacker enumerate which accounts exist.

**Lockout counts attempts, not passwords.** The counter increments on any failed attempt and
resets only on success, so spraying a few common passwords across many attempts still trips it.

**Refresh tokens are single-use, and reuse is treated as compromise.** Presenting a token
that has already been exchanged means either a stolen token or a replay, and in neither case
can the session be trusted, so the entire session is revoked rather than just that token.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.audit.writer import append_audit
from app.core.clock import utcnow
from app.core.config import settings
from app.core.context import RequestContext, system_context
from app.core.errors import (
    AccountLocked,
    AuthenticationRequired,
    InvalidCredentials,
    PermissionDenied,
    RateLimited,
    ValidationFailed,
)
from app.core.logging import get_logger
from app.models.enums import AlertSource, AlertType, AuditResult, Severity, UserStatus
from app.models.user import LoginAttempt, RefreshToken, User, UserSession
from app.security.crypto import (
    hash_password,
    hash_token,
    password_needs_rehash,
    verify_password,
)
from app.security.tokens import (
    IssuedRefreshToken,
    create_access_token,
    create_csrf_token,
    create_refresh_token,
)

logger = get_logger(__name__)

# Verified against when the email is unknown, so the work performed is indistinguishable
# from a real check. Generated once at import for a non-existent password.
_DUMMY_HASH = hash_password(uuid.uuid4().hex)


@dataclass(slots=True)
class AuthResult:
    user: User
    session: UserSession
    access_token: str
    access_expires_at: object
    refresh: IssuedRefreshToken
    csrf_token: str


def _record_attempt(
    session: Session,
    email: str,
    *,
    successful: bool,
    user_id: uuid.UUID | None,
    reason: str | None,
    ip_address: str | None,
    user_agent: str | None,
) -> None:
    session.add(
        LoginAttempt(
            email=email[:255],
            user_id=user_id,
            successful=successful,
            failure_reason=reason,
            ip_address=ip_address,
            user_agent=user_agent,
        )
    )


def _enforce_ip_rate_limit(session: Session, ip_address: str | None) -> None:
    """Throttle attempts per source address over the last minute.

    This is a coarse control that complements per-account lockout: lockout protects one
    account from many guesses, this protects many accounts from one source.
    """
    if not ip_address:
        return
    window_start = utcnow() - timedelta(minutes=1)
    recent = session.execute(
        select(func.count())
        .select_from(LoginAttempt)
        .where(LoginAttempt.ip_address == ip_address)
        .where(LoginAttempt.created_at >= window_start)
        .where(LoginAttempt.successful.is_(False))
    ).scalar_one()
    if recent >= settings.login_rate_limit_per_minute:
        raise RateLimited(
            "Too many sign-in attempts from this address. Try again in a minute.",
            details={"retry_after_seconds": 60},
        )


def authenticate(
    session: Session,
    *,
    email: str,
    password: str,
    ip_address: str | None,
    user_agent: str | None,
    device_label: str | None = None,
) -> AuthResult:
    _enforce_ip_rate_limit(session, ip_address)

    user = session.execute(select(User).where(User.email == email)).scalar_one_or_none()
    anonymous_ctx = RequestContext(
        actor_id=None,
        actor_label=email,
        ip_address=ip_address,
        user_agent=user_agent,
    )

    if user is None:
        # Perform equivalent work so a missing account is not distinguishable by timing.
        verify_password(password, _DUMMY_HASH)
        _record_attempt(
            session,
            email,
            successful=False,
            user_id=None,
            reason="unknown_account",
            ip_address=ip_address,
            user_agent=user_agent,
        )
        append_audit(
            session,
            anonymous_ctx,
            action="auth.login",
            resource_type="user",
            resource_label=email,
            result=AuditResult.failure,
            detail="unknown account",
        )
        session.commit()
        raise InvalidCredentials("Email or password is incorrect")

    now = utcnow()
    if user.locked_until is not None and user.locked_until > now:
        _record_attempt(
            session,
            email,
            successful=False,
            user_id=user.id,
            reason="locked",
            ip_address=ip_address,
            user_agent=user_agent,
        )
        session.commit()
        remaining = int((user.locked_until - now).total_seconds())
        raise AccountLocked(
            "This account is temporarily locked after repeated failed attempts.",
            details={"retry_after_seconds": remaining},
        )

    if not verify_password(password, user.password_hash):
        user.failed_login_count += 1
        reason = "bad_password"
        locked = False
        if user.failed_login_count >= settings.max_failed_logins:
            user.locked_until = now + timedelta(seconds=settings.lockout_seconds)
            user.failed_login_count = 0
            locked = True
            reason = "locked_out"

        _record_attempt(
            session,
            email,
            successful=False,
            user_id=user.id,
            reason=reason,
            ip_address=ip_address,
            user_agent=user_agent,
        )
        append_audit(
            session,
            anonymous_ctx,
            action="auth.login",
            resource_type="user",
            resource_id=user.id,
            resource_label=user.email,
            result=AuditResult.failure,
            detail=reason,
        )

        if locked:
            # Imported here to avoid a circular import at module load.
            from app.services.alert_service import raise_alert

            raise_alert(
                session,
                system_context("account lockout triggered by failed authentication"),
                alert_type=AlertType.account_locked,
                source=AlertSource.security_monitor,
                severity=Severity.high,
                title=f"Account locked: {user.email}",
                description=(
                    f"{settings.max_failed_logins} consecutive failed sign-in attempts for "
                    f"{user.email}. The account is locked for "
                    f"{settings.lockout_seconds // 60} minutes."
                ),
                dedupe_key=f"account_locked:{user.id}",
                subject_user_id=user.id,
                details={"ip_address": ip_address, "user_agent": user_agent},
                recommended_action=(
                    "Confirm with the account holder whether they were the source. If not, "
                    "review recent audit entries from this address."
                ),
            )

        session.commit()
        if locked:
            raise AccountLocked(
                "Too many failed attempts. This account has been locked temporarily.",
                details={"retry_after_seconds": settings.lockout_seconds},
            )
        raise InvalidCredentials("Email or password is incorrect")

    if user.status is not UserStatus.active:
        _record_attempt(
            session,
            email,
            successful=False,
            user_id=user.id,
            reason=f"status_{user.status.value}",
            ip_address=ip_address,
            user_agent=user_agent,
        )
        session.commit()
        # Deliberately the same message as a bad password: whether an account exists but is
        # suspended is itself information an attacker should not receive.
        raise InvalidCredentials("Email or password is incorrect")

    # --- Success ---
    user.failed_login_count = 0
    user.locked_until = None
    user.last_login_at = now

    # Transparently upgrade a hash that used weaker parameters than are configured now.
    if password_needs_rehash(user.password_hash):
        user.password_hash = hash_password(password)

    user_session = UserSession(
        user_id=user.id,
        created_at=now,
        expires_at=now + timedelta(seconds=settings.refresh_token_ttl_seconds),
        last_seen_at=now,
        ip_address=ip_address,
        user_agent=user_agent,
        device_label=device_label,
    )
    session.add(user_session)
    session.flush()

    refresh = create_refresh_token()
    session.add(
        RefreshToken(
            session_id=user_session.id,
            token_hash=refresh.token_hash,
            issued_at=now,
            expires_at=refresh.expires_at,
        )
    )

    access_token, access_expires_at = create_access_token(user.id, user_session.id)
    csrf_token = create_csrf_token()

    _record_attempt(
        session,
        email,
        successful=True,
        user_id=user.id,
        reason=None,
        ip_address=ip_address,
        user_agent=user_agent,
    )
    append_audit(
        session,
        RequestContext.for_user(
            user,
            permissions=user.permission_codes,
            ip_address=ip_address,
            user_agent=user_agent,
            session_id=user_session.id,
        ),
        action="auth.login",
        resource_type="user",
        resource_id=user.id,
        resource_label=user.email,
        result=AuditResult.success,
    )
    session.commit()

    logger.info("login_succeeded", user_id=str(user.id), session_id=str(user_session.id))
    return AuthResult(
        user=user,
        session=user_session,
        access_token=access_token,
        access_expires_at=access_expires_at,
        refresh=refresh,
        csrf_token=csrf_token,
    )


def rotate_refresh_token(
    session: Session,
    *,
    presented_token: str,
    ip_address: str | None,
    user_agent: str | None,
) -> AuthResult:
    """Exchange a refresh token for a new access token and a replacement refresh token."""
    token_hash = hash_token(presented_token)
    stored = session.execute(
        select(RefreshToken).where(RefreshToken.token_hash == token_hash)
    ).scalar_one_or_none()

    if stored is None:
        raise AuthenticationRequired("Session is no longer valid. Please sign in again.")

    user_session = session.execute(
        select(UserSession).where(UserSession.id == stored.session_id)
    ).scalar_one_or_none()
    if user_session is None:
        raise AuthenticationRequired("Session is no longer valid. Please sign in again.")

    now = utcnow()

    if stored.used_at is not None or stored.revoked_at is not None:
        # Replay of a spent token. The token was either stolen or the client is broken; in
        # both cases the safe response is to end the whole session, not just this token.
        _revoke_session(session, user_session, reason="refresh_token_reuse")
        user = session.get(User, user_session.user_id)
        append_audit(
            session,
            RequestContext(
                actor_id=user_session.user_id,
                actor_label=user.email if user else str(user_session.user_id),
                ip_address=ip_address,
                user_agent=user_agent,
            ),
            action="auth.refresh_reuse_detected",
            resource_type="session",
            resource_id=user_session.id,
            result=AuditResult.denied,
            detail="a spent refresh token was presented; the session was revoked",
        )

        from app.services.alert_service import raise_alert

        raise_alert(
            session,
            system_context("refresh token reuse detected"),
            alert_type=AlertType.unauthorized_access_attempt,
            source=AlertSource.security_monitor,
            severity=Severity.critical,
            title="Refresh token reuse detected",
            description=(
                "A refresh token that had already been exchanged was presented again. This "
                "indicates token theft or replay. The session has been revoked."
            ),
            dedupe_key=f"refresh_reuse:{user_session.id}",
            subject_user_id=user_session.user_id,
            details={"ip_address": ip_address, "session_id": str(user_session.id)},
            recommended_action=(
                "Contact the account holder and review audit entries for this session."
            ),
        )
        session.commit()
        raise AuthenticationRequired("Session ended for security reasons. Please sign in again.")

    if stored.expires_at <= now or user_session.revoked_at is not None:
        raise AuthenticationRequired("Session has expired. Please sign in again.")

    user = session.get(User, user_session.user_id)
    if user is None or user.status is not UserStatus.active:
        raise AuthenticationRequired("Account is not active")

    replacement = create_refresh_token(
        ttl_seconds=int((user_session.expires_at - now).total_seconds())
    )
    new_token = RefreshToken(
        session_id=user_session.id,
        token_hash=replacement.token_hash,
        issued_at=now,
        expires_at=min(replacement.expires_at, user_session.expires_at),
    )
    session.add(new_token)
    session.flush()

    stored.used_at = now
    stored.replaced_by_id = new_token.id
    user_session.last_seen_at = now

    access_token, access_expires_at = create_access_token(user.id, user_session.id)
    session.commit()

    return AuthResult(
        user=user,
        session=user_session,
        access_token=access_token,
        access_expires_at=access_expires_at,
        refresh=replacement,
        csrf_token=create_csrf_token(),
    )


def _revoke_session(session: Session, user_session: UserSession, *, reason: str) -> None:
    now = utcnow()
    if user_session.revoked_at is None:
        user_session.revoked_at = now
        user_session.revoked_reason = reason
    for token in user_session.refresh_tokens:
        if token.revoked_at is None:
            token.revoked_at = now


def logout(session: Session, ctx: RequestContext, *, session_id: uuid.UUID | None) -> None:
    if session_id is None:
        return
    user_session = session.get(UserSession, session_id)
    if user_session is None or user_session.user_id != ctx.actor_id:
        return
    _revoke_session(session, user_session, reason="user_logout")
    append_audit(
        session,
        ctx,
        action="auth.logout",
        resource_type="session",
        resource_id=session_id,
        result=AuditResult.success,
    )
    session.commit()


def revoke_session(
    session: Session, ctx: RequestContext, *, session_id: uuid.UUID, actor_user: User
) -> None:
    """Revoke one of the caller's own sessions from the settings screen."""
    user_session = session.get(UserSession, session_id)
    if user_session is None or user_session.user_id != actor_user.id:
        raise PermissionDenied("You can only revoke your own sessions")
    _revoke_session(session, user_session, reason="revoked_by_user")
    append_audit(
        session,
        ctx,
        action="auth.session_revoked",
        resource_type="session",
        resource_id=session_id,
        result=AuditResult.success,
    )
    session.commit()


def change_password(
    session: Session,
    ctx: RequestContext,
    user: User,
    *,
    current_password: str,
    new_password: str,
    current_session_id: uuid.UUID | None,
) -> None:
    """Change a password and end every other session.

    Ending the other sessions is the point of the operation: someone changing a password
    usually believes it may be known to another party, so leaving existing sessions alive
    would defeat the intent.
    """
    if not verify_password(current_password, user.password_hash):
        append_audit(
            session,
            ctx,
            action="auth.password_change",
            resource_type="user",
            resource_id=user.id,
            result=AuditResult.failure,
            detail="current password did not match",
        )
        session.commit()
        raise InvalidCredentials("Current password is incorrect")

    if verify_password(new_password, user.password_hash):
        raise ValidationFailed("The new password must differ from the current one")

    user.password_hash = hash_password(new_password)
    user.password_changed_at = utcnow()
    user.must_change_password = False

    for user_session in user.sessions:
        if user_session.id != current_session_id and user_session.revoked_at is None:
            _revoke_session(session, user_session, reason="password_changed")

    append_audit(
        session,
        ctx,
        action="auth.password_change",
        resource_type="user",
        resource_id=user.id,
        result=AuditResult.success,
        detail="password changed; other sessions revoked",
    )
    session.commit()
