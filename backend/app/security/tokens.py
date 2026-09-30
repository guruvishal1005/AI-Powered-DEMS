"""Access tokens, refresh tokens and CSRF tokens.

The token design answers a specific pair of threats:

*Cross-site scripting* - the access token is short-lived and held only in the SPA's memory,
never in ``localStorage``, so injected script cannot lift a durable credential.

*Cross-site request forgery* - the refresh token lives in an ``httpOnly`` cookie (invisible
to script), which reintroduces CSRF exposure on the refresh endpoint, so that endpoint
additionally requires a double-submit CSRF token that script on *another* origin cannot read.

Deliberately, the access token carries **no permissions**. Permissions are resolved from the
database on every request, which costs one indexed query and buys immediate effect for role
changes, suspensions and revocations. A permission baked into a 15-minute token would mean a
revoked analyst keeps their access for up to 15 minutes, which is not acceptable for a
platform holding evidence.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta

import jwt

from app.core.clock import utcnow
from app.core.config import settings
from app.core.errors import AuthenticationRequired
from app.security.crypto import constant_time_equal, generate_token, hash_token

ISSUER = "cybertrace"
# The JWT "typ" claim, not a credential. Present so a refresh token can never be replayed
# where an access token is expected.
ACCESS_TOKEN_TYPE = "access"  # noqa: S105


@dataclass(frozen=True, slots=True)
class AccessTokenClaims:
    user_id: uuid.UUID
    session_id: uuid.UUID
    token_id: str
    issued_at: datetime
    expires_at: datetime


def create_access_token(
    user_id: uuid.UUID, session_id: uuid.UUID, *, ttl_seconds: int | None = None
) -> tuple[str, datetime]:
    now = utcnow()
    ttl = ttl_seconds if ttl_seconds is not None else settings.access_token_ttl_seconds
    expires_at = now + timedelta(seconds=ttl)
    payload = {
        "iss": ISSUER,
        "sub": str(user_id),
        "sid": str(session_id),
        "jti": uuid.uuid4().hex,
        "typ": ACCESS_TOKEN_TYPE,
        "iat": int(now.timestamp()),
        "exp": int(expires_at.timestamp()),
    }
    token = jwt.encode(payload, settings.secret_key, algorithm=settings.jwt_algorithm)
    return token, expires_at


def decode_access_token(token: str) -> AccessTokenClaims:
    try:
        payload = jwt.decode(
            token,
            settings.secret_key,
            algorithms=[settings.jwt_algorithm],
            issuer=ISSUER,
            options={"require": ["exp", "iat", "sub", "iss"]},
        )
    except jwt.ExpiredSignatureError as exc:
        raise AuthenticationRequired("Access token has expired") from exc
    except jwt.InvalidTokenError as exc:
        raise AuthenticationRequired("Access token is not valid") from exc

    if payload.get("typ") != ACCESS_TOKEN_TYPE:
        raise AuthenticationRequired("Wrong token type for this endpoint")

    try:
        return AccessTokenClaims(
            user_id=uuid.UUID(payload["sub"]),
            session_id=uuid.UUID(payload["sid"]),
            token_id=payload["jti"],
            issued_at=datetime.fromtimestamp(payload["iat"], tz=utcnow().tzinfo),
            expires_at=datetime.fromtimestamp(payload["exp"], tz=utcnow().tzinfo),
        )
    except (KeyError, ValueError) as exc:
        raise AuthenticationRequired("Access token claims are malformed") from exc


# --------------------------------------------------------------------------------------
# Refresh tokens
# --------------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class IssuedRefreshToken:
    """The plaintext token goes to the client once; only the digest is ever stored."""

    token: str
    token_hash: str
    expires_at: datetime


def create_refresh_token(*, ttl_seconds: int | None = None) -> IssuedRefreshToken:
    ttl = ttl_seconds if ttl_seconds is not None else settings.refresh_token_ttl_seconds
    token = generate_token(48)
    return IssuedRefreshToken(
        token=token,
        token_hash=hash_token(token),
        expires_at=utcnow() + timedelta(seconds=ttl),
    )


# --------------------------------------------------------------------------------------
# CSRF
# --------------------------------------------------------------------------------------


def create_csrf_token() -> str:
    return generate_token(24)


def verify_csrf(cookie_value: str | None, header_value: str | None) -> bool:
    """Double-submit check.

    The cookie is readable by same-origin script and sent automatically; the header can only
    be set by script that can read the cookie. An attacker on another origin can cause the
    cookie to be sent but cannot read it to populate the header, so the pair must match.
    """
    if not cookie_value or not header_value:
        return False
    return constant_time_equal(cookie_value, header_value)
