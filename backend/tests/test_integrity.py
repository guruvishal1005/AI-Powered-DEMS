"""Integrity failure modes: ciphertext tamper, plaintext mismatch, missing object."""

from __future__ import annotations

import io
from pathlib import Path

from sqlalchemy.orm import Session

from app.core.config import settings
from app.forensics.integrity import verify_evidence
from app.models.enums import IncidentType, IntegrityStatus, Severity
from app.models.user import User
from app.services import case_service, evidence_service
from tests.conftest import context_for

PAYLOAD = b"integrity-fixture-bytes-please-keep\n"


def _item(db: Session, user: User):
    case = case_service.create_case(
        db,
        context_for(user),
        title="Integrity fixture",
        summary="Integrity tests",
        incident_type=IncidentType.malware_infection,
        severity=Severity.medium,
    )
    evidence = evidence_service.ingest_evidence(
        db,
        context_for(user),
        case_id=case.id,
        stream=io.BytesIO(PAYLOAD),
        original_filename="fixture.bin",
    )
    db.flush()
    db.refresh(evidence)
    return evidence


def test_unmodified_object_verifies(
    db: Session, investigator: User, storage_root: object
) -> None:
    evidence = _item(db, investigator)
    result = verify_evidence(db, evidence, context_for(investigator), trigger="test")
    assert result.ok
    assert result.status is IntegrityStatus.verified
    assert result.ciphertext_verified is True
    assert result.computed_sha256 == evidence.sha256


def test_flipped_ciphertext_is_decryption_failure(
    db: Session, investigator: User, storage_root: Path
) -> None:
    evidence = _item(db, investigator)
    stored = evidence.current_version.stored_object
    path = Path(settings.storage_root) / stored.storage_key
    blob = bytearray(path.read_bytes())
    blob[0] ^= 0xFF
    path.write_bytes(blob)

    result = verify_evidence(db, evidence, context_for(investigator), trigger="test")
    assert result.ok is False
    assert result.status is IntegrityStatus.decryption_failed
    assert result.ciphertext_verified is False


def test_recorded_hash_mismatch_is_distinct_from_gcm_failure(
    db: Session, investigator: User, storage_root: object
) -> None:
    """Ciphertext still authenticates; the recorded plaintext digest does not match."""
    evidence = _item(db, investigator)
    stored = evidence.current_version.stored_object
    stored.sha256 = "0" * 64
    evidence.sha256 = stored.sha256
    evidence.current_version.sha256 = stored.sha256
    db.flush()

    result = verify_evidence(db, evidence, context_for(investigator), trigger="test")
    assert result.status is IntegrityStatus.hash_mismatch
    assert result.ciphertext_verified is True
    assert result.computed_sha256 != stored.sha256


def test_missing_object_is_reported_separately(
    db: Session, investigator: User, storage_root: Path
) -> None:
    evidence = _item(db, investigator)
    stored = evidence.current_version.stored_object
    path = Path(settings.storage_root) / stored.storage_key
    path.unlink()

    result = verify_evidence(db, evidence, context_for(investigator), trigger="test")
    assert result.status is IntegrityStatus.object_missing
    assert result.ok is False
