"""Authentication, session and account-protection behaviour."""

from __future__ import annotations

from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.clock import utcnow
from app.core.config import settings
from app.core.ratelimit import auth_limiter
from app.models.custody import AuditLogEntry
from app.models.user import LoginAttempt, RefreshToken, User, UserSession
from app.services import auth_service
from tests.conftest import TEST_PASSWORD, auth_headers, login

API = settings.api_prefix


@pytest.fixture(autouse=True)
def _clear_throttle() -> None:
    """The edge throttle is process-global, so it must not leak between tests."""
    auth_limiter.reset()


def test_login_returns_token_and_sets_httponly_refresh_cookie(
    client: TestClient, investigator: User
) -> None:
    response = client.post(
        f"{API}/auth/login", json={"email": investigator.email, "password": TEST_PASSWORD}
    )
    assert response.status_code == 200
    body = response.json()

    assert body["access_token"]
    assert body["user"]["email"] == investigator.email
    assert "evidence:download" in body["user"]["permissions"]

    # The refresh token must never be readable by script.
    cookie_header = response.headers.get("set-cookie", "")
    assert settings.refresh_cookie_name in cookie_header
    assert "HttpOnly" in cookie_header
    # The CSRF cookie deliberately is readable, because the client must echo it in a header.
    assert settings.csrf_cookie_name in cookie_header


def test_login_rejects_wrong_password_without_revealing_account_state(
    client: TestClient, investigator: User
) -> None:
    wrong = client.post(
        f"{API}/auth/login", json={"email": investigator.email, "password": "not-the-password"}
    )
    unknown = client.post(
        f"{API}/auth/login", json={"email": "nobody@cybertrace.gov", "password": "whatever123"}
    )

    assert wrong.status_code == 401
    assert unknown.status_code == 401
    # Identical code and message: an attacker learns nothing about which accounts exist.
    assert wrong.json()["error"]["code"] == unknown.json()["error"]["code"]
    assert wrong.json()["error"]["message"] == unknown.json()["error"]["message"]


def test_failed_attempts_are_recorded_even_for_unknown_accounts(
    client: TestClient, db: Session
) -> None:
    client.post(
        f"{API}/auth/login", json={"email": "probe@cybertrace.gov", "password": "guess1234"}
    )
    attempt = db.execute(
        select(LoginAttempt).where(LoginAttempt.email == "probe@cybertrace.gov")
    ).scalar_one()
    assert attempt.successful is False
    assert attempt.failure_reason == "unknown_account"


def test_account_locks_after_configured_failures(
    client: TestClient, db: Session, investigator: User
) -> None:
    for _ in range(settings.max_failed_logins):
        client.post(
            f"{API}/auth/login", json={"email": investigator.email, "password": "wrong-password"}
        )

    db.expire_all()
    locked = db.execute(select(User).where(User.id == investigator.id)).scalar_one()
    assert locked.locked_until is not None
    assert locked.locked_until > utcnow()

    # Even the correct password is refused while the lock stands.
    response = client.post(
        f"{API}/auth/login", json={"email": investigator.email, "password": TEST_PASSWORD}
    )
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "account_locked"


def test_lockout_raises_a_security_alert(
    client: TestClient, db: Session, investigator: User
) -> None:
    from app.models.alert import Alert
    from app.models.enums import AlertType

    for _ in range(settings.max_failed_logins):
        client.post(
            f"{API}/auth/login", json={"email": investigator.email, "password": "wrong-password"}
        )

    alert = db.execute(select(Alert).where(Alert.type == AlertType.account_locked)).scalar_one()
    assert alert.subject_user_id == investigator.id
    assert alert.severity.value == "high"


def test_me_requires_authentication(client: TestClient) -> None:
    assert client.get(f"{API}/auth/me").status_code == 401


def test_me_returns_permissions_in_force(client: TestClient, auditor: User) -> None:
    token = login(client, auditor.email)
    response = client.get(f"{API}/auth/me", headers=auth_headers(token))
    assert response.status_code == 200

    permissions = set(response.json()["permissions"])
    assert "audit:read" in permissions
    # The auditor's remit is oversight, not access to case material.
    assert "evidence:download" not in permissions
    assert "evidence:preview" not in permissions


def test_administrator_cannot_read_evidence_content(
    client: TestClient, administrator: User
) -> None:
    """Separation of duties: platform operation does not confer access to evidence."""
    token = login(client, administrator.email)
    permissions = set(
        client.get(f"{API}/auth/me", headers=auth_headers(token)).json()["permissions"]
    )

    assert "user:manage" in permissions
    assert "retention:manage" in permissions
    assert "evidence:download" not in permissions
    assert "evidence:preview" not in permissions


def test_refresh_requires_csrf_header(client: TestClient, investigator: User) -> None:
    login(client, investigator.email)
    # Cookies are present on the client, but without the echoed header this is a CSRF attempt.
    response = client.post(f"{API}/auth/refresh")
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "permission_denied"


def test_refresh_rotates_the_token(client: TestClient, db: Session, investigator: User) -> None:
    login(client, investigator.email)
    csrf = client.cookies[settings.csrf_cookie_name]
    original_refresh = client.cookies[settings.refresh_cookie_name]

    response = client.post(f"{API}/auth/refresh", headers={"X-CSRF-Token": csrf})
    assert response.status_code == 200
    assert response.json()["access_token"]

    # A new refresh token was issued, and the old one is marked spent.
    assert client.cookies[settings.refresh_cookie_name] != original_refresh
    tokens = db.execute(select(RefreshToken)).scalars().all()
    assert len(tokens) == 2
    spent = [token for token in tokens if token.used_at is not None]
    assert len(spent) == 1
    assert spent[0].replaced_by_id is not None


def test_reusing_a_spent_refresh_token_revokes_the_session(
    client: TestClient, db: Session, investigator: User
) -> None:
    """Replay of a spent token means theft, so the whole session is ended."""
    login(client, investigator.email)
    csrf = client.cookies[settings.csrf_cookie_name]
    stolen = client.cookies[settings.refresh_cookie_name]

    first = client.post(f"{API}/auth/refresh", headers={"X-CSRF-Token": csrf})
    assert first.status_code == 200

    # The CSRF token rotates alongside the refresh token, so the replay must present the
    # current one; otherwise it is rejected as CSRF before the reuse check is ever reached.
    current_csrf = client.cookies[settings.csrf_cookie_name]

    # Present the original refresh token a second time, as a thief with a captured cookie would.
    client.cookies.set(settings.refresh_cookie_name, stolen, path=f"{settings.api_prefix}/auth")
    replay = client.post(f"{API}/auth/refresh", headers={"X-CSRF-Token": current_csrf})
    assert replay.status_code == 401

    session_row = db.execute(select(UserSession)).scalar_one()
    assert session_row.revoked_at is not None
    assert session_row.revoked_reason == "refresh_token_reuse"


def test_logout_revokes_the_session(client: TestClient, db: Session, investigator: User) -> None:
    token = login(client, investigator.email)
    assert client.post(f"{API}/auth/logout", headers=auth_headers(token)).status_code == 200

    session_row = db.execute(select(UserSession)).scalar_one()
    assert session_row.revoked_at is not None

    # The access token is still cryptographically valid but its session is gone.
    assert client.get(f"{API}/auth/me", headers=auth_headers(token)).status_code == 401


def test_revoked_role_takes_effect_immediately(
    client: TestClient, db: Session, investigator: User
) -> None:
    """Permissions are read per request, so a role change is not delayed by token lifetime."""
    token = login(client, investigator.email)
    assert (
        "case:create"
        in client.get(f"{API}/auth/me", headers=auth_headers(token)).json()["permissions"]
    )

    investigator.roles.clear()
    db.flush()

    refreshed = client.get(f"{API}/auth/me", headers=auth_headers(token))
    assert refreshed.status_code == 200
    assert refreshed.json()["permissions"] == []


def test_suspended_account_is_refused_with_a_live_token(
    client: TestClient, db: Session, investigator: User
) -> None:
    from app.models.enums import UserStatus

    token = login(client, investigator.email)
    investigator.status = UserStatus.suspended
    db.flush()

    assert client.get(f"{API}/auth/me", headers=auth_headers(token)).status_code == 401


def test_password_change_revokes_other_sessions(
    client: TestClient, db: Session, investigator: User
) -> None:
    ctx_token = login(client, investigator.email)
    current_session_id = db.execute(select(UserSession.id)).scalar_one()

    # A second, older session that must not survive the password change.
    other = UserSession(
        user_id=investigator.id,
        created_at=utcnow() - timedelta(days=1),
        expires_at=utcnow() + timedelta(days=1),
        last_seen_at=utcnow() - timedelta(hours=2),
        device_label="old laptop",
    )
    db.add(other)
    db.flush()

    response = client.post(
        f"{API}/auth/password",
        headers=auth_headers(ctx_token),
        json={"current_password": TEST_PASSWORD, "new_password": "Rearranged!2026x"},
    )
    assert response.status_code == 200

    db.expire_all()
    assert db.get(UserSession, other.id).revoked_at is not None
    assert db.get(UserSession, current_session_id).revoked_at is None


def test_password_change_rejects_wrong_current_password(
    client: TestClient, investigator: User
) -> None:
    token = login(client, investigator.email)
    response = client.post(
        f"{API}/auth/password",
        headers=auth_headers(token),
        json={"current_password": "not-it", "new_password": "Rearranged!2026x"},
    )
    assert response.status_code == 401


def test_ip_rate_limit_blocks_a_burst(client: TestClient, db: Session) -> None:
    codes = []
    for index in range(settings.login_rate_limit_per_minute + 4):
        response = client.post(
            f"{API}/auth/login",
            json={"email": f"spray{index}@cybertrace.gov", "password": "guessing12345"},
        )
        codes.append(response.status_code)
    assert 429 in codes


def test_login_is_recorded_in_the_audit_chain(
    client: TestClient, db: Session, investigator: User
) -> None:
    login(client, investigator.email)
    entry = db.execute(
        select(AuditLogEntry).where(AuditLogEntry.action == "auth.login")
    ).scalar_one()

    assert entry.result == "success"
    assert entry.actor_label == investigator.email
    assert entry.entry_hash
    assert entry.signature is not None


def test_sessions_endpoint_lists_only_own_sessions(
    client: TestClient, db: Session, investigator: User, analyst: User
) -> None:
    db.add(
        UserSession(
            user_id=analyst.id,
            created_at=utcnow(),
            expires_at=utcnow() + timedelta(days=1),
            last_seen_at=utcnow(),
            device_label="someone else",
        )
    )
    db.flush()

    token = login(client, investigator.email)
    sessions = client.get(f"{API}/auth/sessions", headers=auth_headers(token)).json()

    assert len(sessions) == 1
    assert sessions[0]["is_current"] is True


def test_authenticate_rehashes_a_weak_password_hash(db: Session, investigator: User) -> None:
    from argon2 import PasswordHasher

    weak = PasswordHasher(time_cost=1, memory_cost=8, parallelism=1)
    investigator.password_hash = weak.hash(TEST_PASSWORD)
    db.flush()
    original = investigator.password_hash

    auth_service.authenticate(
        db,
        email=investigator.email,
        password=TEST_PASSWORD,
        ip_address="127.0.0.1",
        user_agent="pytest",
    )
    assert investigator.password_hash != original
