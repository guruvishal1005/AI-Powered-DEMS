"""Hash-chain construction and verification.

Each record commits to its predecessor:

    entry_hash[n] = SHA256( canonical(payload[n]) || 0x1F || entry_hash[n-1] )

The ``0x1F`` unit separator between payload and previous hash matters: without an
unambiguous delimiter, a payload ending in hex characters could in principle be rearranged
to produce the same digest as a different payload/predecessor pair. With it, the two fields
cannot be confused.

Verification replays the stored payloads and recomputes the chain. Three distinct failures
are reported separately, because they point at different kinds of interference:

``content_modified``
    A row's fields no longer hash to its stored ``entry_hash`` - the record itself was edited.
``link_broken``
    A row's ``previous_hash`` does not match its predecessor's ``entry_hash`` - a record was
    inserted or removed.
``sequence_gap``
    Sequence numbers are not contiguous - a record was deleted outright.
"""

from __future__ import annotations

import hashlib
import uuid
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.canonical import CANONICAL_VERSION, canonical_bytes
from app.models.custody import AuditLogEntry, CustodyEvent
from app.security.crypto import verify_record_signature

# Notional predecessor of the first record in any chain.
GENESIS_HASH = "0" * 64
SEPARATOR = b"\x1f"


def compute_entry_hash(payload: dict[str, Any], previous_hash: str | None) -> str:
    material = (
        canonical_bytes(payload) + SEPARATOR + (previous_hash or GENESIS_HASH).encode("ascii")
    )
    return hashlib.sha256(material).hexdigest()


def custody_payload(event: CustodyEvent) -> dict[str, Any]:
    """The exact field set committed to by a custody entry's hash.

    Adding or removing a field here changes every hash, so a change must be accompanied by a
    bump to :data:`app.core.canonical.CANONICAL_VERSION` and support for verifying older
    versions.
    """
    return {
        "canonical_version": event.canonical_version,
        "evidence_id": event.evidence_id,
        "case_id": event.case_id,
        "sequence": event.sequence,
        "action": event.action,
        "actor_id": event.actor_id,
        "actor_label": event.actor_label,
        "actor_role": event.actor_role,
        "occurred_at": event.occurred_at,
        "recorded_at": event.recorded_at,
        "previous_state": event.previous_state,
        "new_state": event.new_state,
        "reason": event.reason,
        "notes": event.notes,
        "sha256_at_event": event.sha256_at_event,
        "integrity_status_at_event": event.integrity_status_at_event,
        "ip_address": event.ip_address,
        "user_agent": event.user_agent,
        "request_id": event.request_id,
        "details": event.details,
    }


def audit_payload(entry: AuditLogEntry) -> dict[str, Any]:
    return {
        "canonical_version": entry.canonical_version,
        "sequence": entry.sequence,
        "action": entry.action,
        "resource_type": entry.resource_type,
        "resource_id": entry.resource_id,
        "resource_label": entry.resource_label,
        "actor_id": entry.actor_id,
        "actor_label": entry.actor_label,
        "actor_roles": entry.actor_roles,
        "result": entry.result,
        "case_id": entry.case_id,
        "ip_address": entry.ip_address,
        "user_agent": entry.user_agent,
        "request_id": entry.request_id,
        "http_method": entry.http_method,
        "http_path": entry.http_path,
        "status_code": entry.status_code,
        "before_state": entry.before_state,
        "after_state": entry.after_state,
        "reason": entry.reason,
        "detail": entry.detail,
        "recorded_at": entry.recorded_at,
    }


@dataclass(slots=True)
class ChainBreak:
    kind: str
    sequence: int
    record_id: str
    detail: str


@dataclass(slots=True)
class ChainVerification:
    """Outcome of replaying a chain."""

    chain: str
    entries_checked: int
    intact: bool
    breaks: list[ChainBreak] = field(default_factory=list)
    signatures_checked: int = 0
    signatures_valid: int = 0
    first_sequence: int | None = None
    last_sequence: int | None = None
    head_hash: str | None = None

    @property
    def summary(self) -> str:
        if self.intact:
            return f"{self.entries_checked} entries verified; chain intact"
        return f"{self.entries_checked} entries checked; {len(self.breaks)} break(s) detected"


class ChainedRecord(Protocol):
    """The fields any chained row must expose to be verifiable.

    Custody events and audit entries share no base class beyond the declarative ``Base``, so
    this protocol is what lets one verifier replay either without the type checker collapsing
    them to a common ancestor that has none of these attributes.
    """

    id: Any
    sequence: int
    canonical_version: int
    previous_hash: str | None
    entry_hash: str
    signature: bytes | None


def _verify_sequence(
    chain_name: str,
    rows: Sequence[ChainedRecord],
    payload_builder: Callable[[Any], dict[str, Any]],
    *,
    check_signatures: bool,
    expect_contiguous_from: int | None,
) -> ChainVerification:
    result = ChainVerification(chain=chain_name, entries_checked=len(rows), intact=True)
    if not rows:
        return result

    result.first_sequence = rows[0].sequence
    result.last_sequence = rows[-1].sequence

    previous_hash: str | None = None
    expected_sequence = expect_contiguous_from

    for index, row in enumerate(rows):
        payload = payload_builder(row)

        if row.canonical_version != CANONICAL_VERSION:
            result.breaks.append(
                ChainBreak(
                    kind="unsupported_version",
                    sequence=row.sequence,
                    record_id=str(row.id),
                    detail=(
                        f"record was written with canonical version {row.canonical_version}, "
                        f"verifier supports {CANONICAL_VERSION}"
                    ),
                )
            )
            previous_hash = row.entry_hash
            continue

        recomputed = compute_entry_hash(payload, row.previous_hash)
        if recomputed != row.entry_hash:
            result.breaks.append(
                ChainBreak(
                    kind="content_modified",
                    sequence=row.sequence,
                    record_id=str(row.id),
                    detail=(
                        "stored entry hash does not match the record's contents "
                        f"(expected {recomputed[:16]}..., stored {row.entry_hash[:16]}...)"
                    ),
                )
            )

        # The first row of a full replay legitimately has no predecessor; a partial replay
        # starts mid-chain, so its previous_hash is checked against the row before it only
        # when we actually have that row in hand.
        if index == 0:
            if expect_contiguous_from is not None and row.previous_hash not in (None, GENESIS_HASH):
                pass  # partial verification: predecessor is outside the window
        elif row.previous_hash != previous_hash:
            result.breaks.append(
                ChainBreak(
                    kind="link_broken",
                    sequence=row.sequence,
                    record_id=str(row.id),
                    detail=(
                        "previous_hash does not match the preceding entry, which indicates "
                        "an inserted or removed record"
                    ),
                )
            )

        if expected_sequence is not None and row.sequence != expected_sequence:
            result.breaks.append(
                ChainBreak(
                    kind="sequence_gap",
                    sequence=row.sequence,
                    record_id=str(row.id),
                    detail=f"expected sequence {expected_sequence}, found {row.sequence}",
                )
            )
            expected_sequence = row.sequence
        if expected_sequence is not None:
            expected_sequence += 1

        if check_signatures and row.signature is not None:
            result.signatures_checked += 1
            if verify_record_signature(row.entry_hash, row.signature):
                result.signatures_valid += 1
            else:
                result.breaks.append(
                    ChainBreak(
                        kind="invalid_signature",
                        sequence=row.sequence,
                        record_id=str(row.id),
                        detail="Ed25519 signature does not verify against this deployment's key",
                    )
                )

        previous_hash = row.entry_hash

    result.head_hash = rows[-1].entry_hash
    result.intact = not result.breaks
    return result


def verify_custody_chain(
    session: Session, evidence_id: uuid.UUID, *, check_signatures: bool = True
) -> ChainVerification:
    """Replay one evidence item's custody chain from its genesis event."""
    rows = list(
        session.execute(
            select(CustodyEvent)
            .where(CustodyEvent.evidence_id == evidence_id)
            .order_by(CustodyEvent.sequence)
        )
        .scalars()
        .all()
    )
    return _verify_sequence(
        f"custody:{evidence_id}",
        rows,
        custody_payload,
        check_signatures=check_signatures,
        expect_contiguous_from=1,
    )


def verify_audit_chain(
    session: Session,
    *,
    start_sequence: int | None = None,
    limit: int | None = None,
    check_signatures: bool = True,
) -> ChainVerification:
    """Replay the global audit chain, optionally a window of it.

    A full replay is O(n) over the whole table, so the admin interface verifies a bounded
    window by default and offers a full verification as an explicit background job.
    """
    stmt = select(AuditLogEntry).order_by(AuditLogEntry.sequence)
    if start_sequence is not None:
        stmt = stmt.where(AuditLogEntry.sequence >= start_sequence)
    if limit is not None:
        stmt = stmt.limit(limit)

    rows = list(session.execute(stmt).scalars().all())
    return _verify_sequence(
        "audit",
        rows,
        audit_payload,
        check_signatures=check_signatures,
        expect_contiguous_from=start_sequence if start_sequence is not None else 1,
    )
