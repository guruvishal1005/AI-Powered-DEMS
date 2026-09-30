"""Audit chain integrity.

Two independent controls are verified here, and it matters that they are independent:

1. Database triggers refuse ``UPDATE``, ``DELETE`` and ``TRUNCATE``, which stops tampering by
   anyone holding an ordinary application connection.
2. The hash chain *detects* tampering by someone privileged enough to defeat control 1.

The tests below deliberately disable the triggers in order to simulate an attacker with owner
rights on the database. That is the threat the hash chain exists for: without it, a
sufficiently privileged insider could rewrite history and leave no trace.
"""

from __future__ import annotations

from itertools import pairwise

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from app.audit.chain import GENESIS_HASH, verify_audit_chain
from app.audit.writer import append_audit
from app.models.custody import AuditLogEntry
from app.models.enums import AuditResult
from app.models.user import User
from tests.conftest import context_for


def _write_entries(db: Session, user: User, count: int) -> list[AuditLogEntry]:
    ctx = context_for(user)
    return [
        append_audit(
            db,
            ctx,
            action="case.viewed",
            resource_type="case",
            resource_id=f"case-{index}",
            resource_label=f"Case {index}",
            detail=f"entry {index}",
        )
        for index in range(count)
    ]


def test_entries_form_a_linked_chain(db: Session, investigator: User) -> None:
    entries = _write_entries(db, investigator, 4)

    assert entries[0].sequence == 1
    assert entries[0].previous_hash is None
    for previous, current in pairwise(entries):
        assert current.sequence == previous.sequence + 1
        assert current.previous_hash == previous.entry_hash
        assert current.entry_hash != previous.entry_hash


def test_every_entry_is_signed(db: Session, investigator: User) -> None:
    entries = _write_entries(db, investigator, 2)
    for entry in entries:
        assert entry.signature is not None
        assert len(entry.signature) == 64  # Ed25519
        assert entry.signing_key_id


def test_verification_reports_an_intact_chain(db: Session, investigator: User) -> None:
    _write_entries(db, investigator, 5)
    result = verify_audit_chain(db)

    assert result.intact is True
    assert result.breaks == []
    assert result.entries_checked == 5
    assert result.signatures_checked == 5
    assert result.signatures_valid == 5
    assert "intact" in result.summary


def test_update_is_refused_by_the_database(db: Session, investigator: User) -> None:
    """An ordinary connection cannot edit history at all."""
    _write_entries(db, investigator, 1)

    with pytest.raises(DBAPIError) as excinfo:
        db.execute(text("update audit_log set action = 'tampered' where sequence = 1"))
    assert "append-only" in str(excinfo.value)
    db.rollback()


def test_delete_is_refused_without_explicit_opt_in(db: Session, investigator: User) -> None:
    _write_entries(db, investigator, 1)

    with pytest.raises(DBAPIError) as excinfo:
        db.execute(text("delete from audit_log where sequence = 1"))
    assert "append-only" in str(excinfo.value)
    db.rollback()


def test_edited_content_is_detected(db: Session, investigator: User) -> None:
    """Simulate an attacker with owner rights who edits a record in place."""
    _write_entries(db, investigator, 4)
    db.commit()

    db.execute(text("alter table audit_log disable trigger trg_audit_log_append_only"))
    db.execute(
        text("update audit_log set detail = 'quietly rewritten' where sequence = 2")
    )
    db.execute(text("alter table audit_log enable trigger trg_audit_log_append_only"))

    result = verify_audit_chain(db)

    assert result.intact is False
    kinds = {break_.kind for break_ in result.breaks}
    assert "content_modified" in kinds
    modified = next(b for b in result.breaks if b.kind == "content_modified")
    assert modified.sequence == 2
    assert "does not match" in modified.detail


def test_removed_record_is_detected(db: Session, investigator: User) -> None:
    """Deleting a record breaks both the sequence and the hash link that spanned it."""
    _write_entries(db, investigator, 5)
    db.commit()

    db.execute(text("alter table audit_log disable trigger trg_audit_log_append_only"))
    db.execute(text("delete from audit_log where sequence = 3"))
    db.execute(text("alter table audit_log enable trigger trg_audit_log_append_only"))

    result = verify_audit_chain(db)

    assert result.intact is False
    kinds = {break_.kind for break_ in result.breaks}
    assert "sequence_gap" in kinds
    assert "link_broken" in kinds


def test_reordering_records_is_detected(db: Session, investigator: User) -> None:
    """Swapping two entries' payloads invalidates both of their hashes."""
    _write_entries(db, investigator, 4)
    db.commit()

    db.execute(text("alter table audit_log disable trigger trg_audit_log_append_only"))
    db.execute(
        text(
            """
            update audit_log a
               set detail = b.detail
              from audit_log b
             where a.sequence = 2 and b.sequence = 3
            """
        )
    )
    db.execute(text("alter table audit_log enable trigger trg_audit_log_append_only"))

    result = verify_audit_chain(db)
    assert result.intact is False
    assert any(break_.kind == "content_modified" for break_ in result.breaks)


def test_forged_signature_is_detected(db: Session, investigator: User) -> None:
    """A record whose hash was recomputed still fails, because the signature will not verify."""
    entries = _write_entries(db, investigator, 2)
    db.commit()
    target_sequence = entries[1].sequence

    # Recompute a consistent hash for altered content but leave the original signature.
    from app.audit.chain import audit_payload, compute_entry_hash

    entries[1].detail = "rewritten with a matching hash"
    forged_hash = compute_entry_hash(audit_payload(entries[1]), entries[1].previous_hash)

    db.execute(text("alter table audit_log disable trigger trg_audit_log_append_only"))
    db.execute(
        text(
            "update audit_log set detail = :detail, entry_hash = :hash where sequence = :sequence"
        ),
        {
            "detail": "rewritten with a matching hash",
            "hash": forged_hash,
            "sequence": target_sequence,
        },
    )
    db.execute(text("alter table audit_log enable trigger trg_audit_log_append_only"))
    db.expire_all()

    result = verify_audit_chain(db)

    assert result.intact is False
    assert any(break_.kind == "invalid_signature" for break_ in result.breaks)


def test_denied_attempts_are_recorded_as_denied(db: Session, auditor: User) -> None:
    append_audit(
        db,
        context_for(auditor),
        action="evidence.download",
        resource_type="evidence",
        resource_id="E-2026-00001",
        result=AuditResult.denied,
        detail="missing permission(s): evidence:download",
    )
    entry = db.execute(
        select(AuditLogEntry).where(AuditLogEntry.result == AuditResult.denied.value)
    ).scalar_one()

    assert entry.actor_label == auditor.email
    assert "evidence:download" in (entry.detail or "")


def test_genesis_hash_constant_is_used_for_the_first_link(db: Session, investigator: User) -> None:
    """The first entry has no predecessor, so verification substitutes the genesis constant."""
    from app.audit.chain import audit_payload, compute_entry_hash

    entry = _write_entries(db, investigator, 1)[0]
    assert entry.previous_hash is None
    assert entry.entry_hash == compute_entry_hash(audit_payload(entry), GENESIS_HASH)
