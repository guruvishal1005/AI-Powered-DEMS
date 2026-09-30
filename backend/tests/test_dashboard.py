"""Command Center aggregates.

The activity series uses ``date_trunc``. PostgreSQL rejects that query when the truncation
unit is a bound parameter, because SELECT / GROUP BY / ORDER BY then compile as three
different expressions. This test is the regression lock for that failure.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.core.config import settings
from app.models.user import User
from tests.conftest import auth_headers, login

API = settings.api_prefix


def test_dashboard_returns_scoped_aggregates(client: TestClient, investigator: User) -> None:
    token = login(client, investigator.email)
    response = client.get(f"{API}/dashboard", headers=auth_headers(token))
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["cases_total"] >= 0
    assert body["evidence_total"] >= 0
    assert isinstance(body["activity"], list)
    assert "verified" in body["integrity"]
    assert "failed" in body["integrity"]
