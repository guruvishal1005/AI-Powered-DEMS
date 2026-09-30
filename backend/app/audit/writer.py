"""Append-only chain writers.

A hash chain requires a total order, so appends must be serialised. These writers take a
PostgreSQL *advisory transaction lock* rather than locking rows: the lock is held only for
the moment needed to read the current head and insert the successor, is released
automatically at commit or rollback, and cannot deadlock against ordinary table access.

The audit chain uses one global lock. Custody chains are per evidence item, so each takes a
lock derived from its own id, which means uploads to different items append concurrently
without contending at all.
"""

from __future__ import annotations

import hashlib
import uuid
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.audit.chain import compute_entry_hash, custody_payload
from app.core.canonical import CANONICAL_VERSION
from app.core.clock import utcnow
from app.core.context import RequestContext
from app.models.custody import AuditLogEntry, CustodyEvent
from app.models.enums import AuditResult, CustodyAction
from app.models.evidence import Evidence
from app.security.crypto import sign_record, signing_key_id

# Distinct namespaces keep the two chains' advisory locks from ever colliding.
AUDIT_LOCK_NAMESPACE = 0x43544141  # "CTAA"
CUSTODY_LOCK_NAMESPACE = 0x43544143  # "CTAC"


def _take_advisory_lock(session: Session, namespace: int, key: int) -> None:
    session.execute(select(func.pg_advisory_xact_lock(namespace, key)))


def _uuid_to_lock_key(value: uuid.UUID) -> int:
    """Map a UUID onto a signed 32-bit advisory-lock key.

    Collisions are harmless: two different evidence items sharing a key merely serialise
    against each other, which costs a little concurrency but never correctness.
    """
    digest = hashlib.sha256(value.bytes).digest()[:4]
    return int.from_bytes(digest, "big", signed=True)


def append_audit(
    session: Session,
    ctx: RequestContext,
    *,
    action: str,
    resource_type: str,
    resource_id: str | uuid.UUID | None = None,
    resource_label: str | None = None,
    result: AuditResult = AuditResult.success,
    case_id: uuid.UUID | None = None,
    before_state: dict[str, Any] | None = None,
    after_state: dict[str, Any] | None = None,
    reason: str | None = None,
    detail: str | None = None,
    http_method: str | None = None,
    http_path: str | None = None,
    status_code: int | None = None,
) -> AuditLogEntry:
    """Append one entry to the global audit chain."""
    _take_advisory_lock(session, AUDIT_LOCK_NAMESPACE, 0)

    head = session.execute(
        select(AuditLogEntry.sequence, AuditLogEntry.entry_hash)
        .order_by(AuditLogEntry.sequence.desc())
        .limit(1)
    ).first()
    next_sequence = (head.sequence + 1) if head else 1
    previous_hash = head.entry_hash if head else None

    entry = AuditLogEntry(
        sequence=next_sequence,
        action=action,
        resource_type=resource_type,
        resource_id=str(resource_id) if resource_id is not None else None,
        resource_label=resource_label,
        actor_id=ctx.actor_id,
        actor_label=ctx.actor_label,
        actor_roles=list(ctx.roles),
        result=result.value,
        case_id=case_id,
        ip_address=ctx.ip_address,
        user_agent=ctx.user_agent,
        request_id=ctx.request_id,
        http_method=http_method,
        http_path=http_path,
        status_code=status_code,
        before_state=before_state,
        after_state=after_state,
        reason=reason or ctx.reason,
        detail=detail,
        recorded_at=utcnow(),
        previous_hash=previous_hash,
        canonical_version=CANONICAL_VERSION,
    )

    from app.audit.chain import audit_payload

    entry.entry_hash = compute_entry_hash(audit_payload(entry), previous_hash)
    entry.signature = sign_record(entry.entry_hash)
    entry.signing_key_id = signing_key_id()

    session.add(entry)
    session.flush()
    return entry


def append_custody(
    session: Session,
    ctx: RequestContext,
    evidence: Evidence,
    action: CustodyAction,
    *,
    occurred_at: Any = None,
    previous_state: dict[str, Any] | None = None,
    new_state: dict[str, Any] | None = None,
    reason: str | None = None,
    notes: str | None = None,
    details: dict[str, Any] | None = None,
) -> CustodyEvent:
    """Append one event to an evidence item's custody chain.

    The artifact's hash and integrity state at the moment of the event are captured into the
    record, so the chain answers "what did this look like when it was touched?" without
    depending on the mutable evidence row still holding those values later.
    """
    _take_advisory_lock(session, CUSTODY_LOCK_NAMESPACE, _uuid_to_lock_key(evidence.id))

    head = session.execute(
        select(CustodyEvent.sequence, CustodyEvent.entry_hash)
        .where(CustodyEvent.evidence_id == evidence.id)
        .order_by(CustodyEvent.sequence.desc())
        .limit(1)
    ).first()
    next_sequence = (head.sequence + 1) if head else 1
    previous_hash = head.entry_hash if head else None

    now = utcnow()
    event = CustodyEvent(
        evidence_id=evidence.id,
        case_id=evidence.case_id,
        sequence=next_sequence,
        action=action,
        actor_id=ctx.actor_id,
        actor_label=ctx.actor_label,
        actor_role=ctx.roles[0] if ctx.roles else None,
        occurred_at=occurred_at or now,
        recorded_at=now,
        previous_state=previous_state or {},
        new_state=new_state or {},
        reason=reason or ctx.reason,
        notes=notes,
        sha256_at_event=evidence.sha256,
        integrity_status_at_event=evidence.integrity_status,
        ip_address=ctx.ip_address,
        user_agent=ctx.user_agent,
        request_id=ctx.request_id,
        details=details or {},
        previous_hash=previous_hash,
        canonical_version=CANONICAL_VERSION,
    )

    event.entry_hash = compute_entry_hash(custody_payload(event), previous_hash)
    event.signature = sign_record(event.entry_hash)
    event.signing_key_id = signing_key_id()

    session.add(event)

    # Denormalised head pointer, so listings can show chain state without a replay.
    evidence.custody_head_hash = event.entry_hash
    evidence.custody_event_count = next_sequence

    session.flush()
    return event
