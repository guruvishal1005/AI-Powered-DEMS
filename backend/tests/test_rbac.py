"""RBAC denial matrix and SQL object scoping.

These tests hit the HTTP surface so they cover both enforcement layers: the permission
dependency that returns 403, and the SQL scope that simply never selects another
investigator's cases. The frontend is not involved; hiding a button would not be a control.

Case and evidence rows are created through the API rather than the service layer so this
thread never holds the audit-chain advisory lock that denial recording also needs.
"""

from __future__ import annotations

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.enums import Permission, RoleSlug
from app.models.user import User
from tests.conftest import auth_headers, login, make_user

API = settings.api_prefix

CASE_BODY = {
    "title": "Scoped investigation",
    "summary": "Used by the RBAC suite.",
    "incident_type": "unauthorized_access",
    "severity": "high",
}


def _create_case(client: TestClient, token: str, title: str = CASE_BODY["title"]) -> dict:
    response = client.post(
        f"{API}/cases", json={**CASE_BODY, "title": title}, headers=auth_headers(token)
    )
    assert response.status_code == 201, response.text
    return response.json()


def _upload(client: TestClient, token: str, case_id: str, name: str = "note.txt") -> dict:
    response = client.post(
        f"{API}/evidence",
        data={"case_id": case_id, "metadata": '{"title": "note.txt"}'},
        files={"file": (name, b"classified artifact bytes\n", "text/plain")},
        headers=auth_headers(token),
    )
    assert response.status_code == 201, response.text
    return response.json()


def test_auditor_and_admin_roles_lack_download_grant(
    auditor: User, administrator: User, investigator: User
) -> None:
    assert Permission.evidence_download.value not in auditor.permission_codes
    assert Permission.evidence_download.value not in administrator.permission_codes
    assert Permission.evidence_download.value in investigator.permission_codes


def test_auditor_cannot_download_evidence(
    client: TestClient, investigator: User, auditor: User, storage_root: object
) -> None:
    inv = login(client, investigator.email)
    case = _create_case(client, inv)
    evidence = _upload(client, inv, case["id"])

    token = login(client, auditor.email)
    response = client.get(
        f"{API}/evidence/{evidence['id']}/download",
        params={"reason": "audit review of original bytes"},
        headers=auth_headers(token),
    )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "permission_denied"

    meta = client.get(f"{API}/evidence/{evidence['id']}", headers=auth_headers(token))
    assert meta.status_code == 200
    assert meta.json()["sha256"]


def test_administrator_cannot_download_evidence(
    client: TestClient, investigator: User, administrator: User, storage_root: object
) -> None:
    inv = login(client, investigator.email)
    case = _create_case(client, inv)
    evidence = _upload(client, inv, case["id"])

    token = login(client, administrator.email)
    response = client.get(
        f"{API}/evidence/{evidence['id']}/download",
        params={"reason": "platform admin curiosity"},
        headers=auth_headers(token),
    )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "permission_denied"


def test_investigator_download_requires_a_reason_and_succeeds(
    client: TestClient, investigator: User, storage_root: object
) -> None:
    token = login(client, investigator.email)
    case = _create_case(client, token)
    evidence = _upload(client, token, case["id"])

    missing_reason = client.get(
        f"{API}/evidence/{evidence['id']}/download", headers=auth_headers(token)
    )
    assert missing_reason.status_code == 422

    ok = client.get(
        f"{API}/evidence/{evidence['id']}/download",
        params={"reason": "Independent hash verification"},
        headers=auth_headers(token),
    )
    assert ok.status_code == 200
    assert ok.headers["content-type"].startswith("application/octet-stream")
    assert "attachment" in ok.headers["content-disposition"]
    assert ok.headers["x-cybertrace-sha256"] == evidence["sha256"]
    assert ok.content == b"classified artifact bytes\n"


def test_analyst_cannot_create_or_close_cases(
    client: TestClient, investigator: User, analyst: User
) -> None:
    token = login(client, analyst.email)
    created = client.post(
        f"{API}/cases",
        json={
            "title": "Analyst-created case",
            "summary": "Should be refused",
            "incident_type": "phishing",
            "severity": "medium",
        },
        headers=auth_headers(token),
    )
    assert created.status_code == 403

    inv = login(client, investigator.email)
    case = _create_case(client, inv, title="Case an analyst may read")
    assigned = client.post(
        f"{API}/cases/{case['id']}/assignments",
        json={"user_id": str(analyst.id), "role_on_case": "forensic_analyst"},
        headers=auth_headers(inv),
    )
    assert assigned.status_code in {200, 201}, assigned.text

    closed = client.post(
        f"{API}/cases/{case['id']}/status",
        json={"status": "closed", "reason": "analyst attempted closure", "closure_summary": "no"},
        headers=auth_headers(token),
    )
    assert closed.status_code == 403


def test_investigator_cannot_select_another_investigators_case(
    client: TestClient, db: Session, investigator: User
) -> None:
    other = make_user(db, role=RoleSlug.investigator, email="other-inv@cybertrace.gov")
    db.flush()

    other_token = login(client, other.email)
    hidden = _create_case(client, other_token, title="Other investigator's case")

    token = login(client, investigator.email)
    visible = _create_case(client, token, title="Own case")

    listing = client.get(f"{API}/cases", headers=auth_headers(token))
    assert listing.status_code == 200
    ids = {row["id"] for row in listing.json()["items"]}
    assert visible["id"] in ids
    assert hidden["id"] not in ids

    leak = client.get(f"{API}/cases/{hidden['id']}", headers=auth_headers(token))
    assert leak.status_code == 404


def test_auditor_can_read_across_cases_but_still_cannot_download(
    client: TestClient, investigator: User, auditor: User, storage_root: object
) -> None:
    inv = login(client, investigator.email)
    case = _create_case(client, inv)
    evidence = _upload(client, inv, case["id"])

    token = login(client, auditor.email)
    listing = client.get(f"{API}/cases", headers=auth_headers(token))
    assert listing.status_code == 200
    assert any(row["id"] == case["id"] for row in listing.json()["items"])

    download = client.get(
        f"{API}/evidence/{evidence['id']}/download",
        params={"reason": "compliance export"},
        headers=auth_headers(token),
    )
    assert download.status_code == 403
