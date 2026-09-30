"""Security headers and authentication throttling."""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.core.config import settings
from app.core.ratelimit import auth_limiter
from app.models.user import User

API = settings.api_prefix


def test_api_responses_carry_security_headers(client: TestClient) -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert "geolocation=()" in response.headers["permissions-policy"]
    assert "default-src 'none'" in response.headers["content-security-policy"]
    assert "X-Request-ID" in response.headers or "x-request-id" in response.headers


def test_login_is_rate_limited(client: TestClient, investigator: User) -> None:
    auth_limiter.reset()
    statuses = []
    for _ in range(40):
        response = client.post(
            f"{API}/auth/login",
            json={"email": investigator.email, "password": "definitely-wrong-password"},
        )
        statuses.append(response.status_code)
        if response.status_code == 429:
            assert response.json()["error"]["code"] == "rate_limited"
            assert "Retry-After" in response.headers or "retry-after" in response.headers
            return
    raise AssertionError(f"login was never throttled; statuses={statuses[-5:]}")
