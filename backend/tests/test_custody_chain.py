"""Custody-chain tamper detection, independent of the audit-log suite."""

from __future__ import annotations

import io

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from app.audit.chain import verify_custody_chain
from app.models.enums import IncidentType, Severity
from app.models.user import User
from app.services import case_service, evidence_service
from tests.conftest import context_for


def _ingest(db: Session, user: User):
    case = case_service.create_case(
        db,
        context_for(user),
        title="Custody fixture",
        summary="Custody tests",
        incident_type=IncidentType.phishing,
        severity=Severity.low,
    )
    return evidence_service.ingest_evidence(
        db,
        context_for(user),
        case_id=case.id,
        stream=io.BytesIO(b"chain-of-custody-bytes\n"),
        original_filename="custody.txt",
    )


def test_update_on_custody_is_refused(
    db: Session, investigator: User, storage_root: object
) -> None:
    _ingest(db, investigator)
    with pytest.raises(DBAPIError) as excinfo:
        db.execute(text("update custody_events set notes = 'tampered' where sequence = 1"))
    assert "append-only" in str(excinfo.value)
    db.rollback()


def test_edited_custody_event_breaks_verification(
    db: Session, investigator: User, storage_root: object
) -> None:
    evidence = _ingest(db, investigator)
    db.commit()

    db.execute(text("alter table custody_events disable trigger trg_custody_events_append_only"))
    db.execute(text("update custody_events set notes = 'quietly rewritten' where sequence = 1"))
    db.execute(text("alter table custody_events enable trigger trg_custody_events_append_only"))

    result = verify_custody_chain(db, evidence.id)
    assert result.intact is False
    assert any(item.kind == "content_modified" for item in result.breaks)


def test_genesis_custody_event_is_written_on_ingest(
    db: Session, investigator: User, storage_root: object
) -> None:
    evidence = _ingest(db, investigator)
    events = list(
        db.execute(
            text(
                "select sequence, action, previous_hash "
                "from custody_events where evidence_id = :id order by sequence"
            ),
            {"id": evidence.id},
        )
    )
    assert events
    assert events[0].sequence == 1
    assert events[0].previous_hash is None
    assert evidence.custody_event_count >= 1
