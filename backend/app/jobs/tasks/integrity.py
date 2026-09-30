"""Integrity verification tasks.

Preservation is a continuous claim, not something established once at upload. These tasks are
what let a report state that an artifact has been verified repeatedly over its whole retention
period, and they are what makes silent bit-rot or interference detectable within days rather
than at the moment someone finally tries to use the evidence.

The sweep is deliberately budgeted. Verifying every object on every run would either take
longer than the interval or saturate disk I/O on a busy platform, so each run takes the items
whose verification is stalest, up to a byte budget. Over successive runs that gives every item
regular coverage while keeping any single run bounded.
"""

from __future__ import annotations

import uuid
from dataclasses import asdict
from typing import Any

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.core.clock import utcnow
from app.core.context import RequestContext
from app.core.logging import get_logger
from app.forensics.integrity import verify_evidence
from app.jobs.registry import task
from app.models.enums import EvidenceStatus, IntegrityStatus
from app.models.evidence import Evidence

logger = get_logger(__name__)

# Per-run ceiling on plaintext bytes verified. Full verification decrypts and re-hashes, so this
# is the knob that keeps a sweep from monopolising the disk.
SWEEP_BYTE_BUDGET = 2 * 1024 * 1024 * 1024
SWEEP_ITEM_LIMIT = 200


@task(
    "integrity.verify_evidence",
    max_attempts=2,
    priority=60,
    description="Verify one evidence item's integrity",
    dedupe_template="verify:{evidence_id}",
)
def verify_one(session: Session, ctx: RequestContext, payload: dict[str, Any]) -> dict[str, Any]:
    """Verify a single item, on request or after a suspicious event."""
    evidence_id = uuid.UUID(str(payload["evidence_id"]))
    evidence = session.get(Evidence, evidence_id)
    if evidence is None:
        return {"skipped": "evidence no longer exists", "evidence_id": str(evidence_id)}

    result = verify_evidence(
        session, evidence, ctx, trigger=str(payload.get("trigger", "scheduled"))
    )
    return {
        "evidence": evidence.reference,
        "status": result.status.value,
        "duration_ms": result.duration_ms,
    }


@task(
    "integrity.sweep",
    max_attempts=1,
    priority=200,
    description="Re-verify the evidence items whose verification is stalest",
)
def integrity_sweep(
    session: Session, ctx: RequestContext, payload: dict[str, Any]
) -> dict[str, Any]:
    """Verify a budgeted batch of items, oldest verification first.

    Items already known to have failed are re-checked too. That is intentional: a failure that
    resolves itself (a restored backup, a repaired filesystem) is information, and an item left
    permanently in a failed state without re-examination is an unanswered question.
    """
    budget = int(payload.get("byte_budget", SWEEP_BYTE_BUDGET))
    limit = int(payload.get("item_limit", SWEEP_ITEM_LIMIT))

    candidates = (
        session.execute(
            select(Evidence)
            .where(Evidence.status != EvidenceStatus.disposed)
            # Never verified sorts first, then longest since last verification.
            .order_by(Evidence.last_verified_at.asc().nullsfirst())
            .limit(limit)
        )
        .scalars()
        .all()
    )

    checked = 0
    failed = 0
    bytes_read = 0
    statuses: dict[str, int] = {}

    for evidence in candidates:
        if bytes_read + evidence.size_bytes > budget and checked > 0:
            # Stop before exceeding the budget, but always verify at least one item so a single
            # artifact larger than the whole budget is not skipped forever.
            break
        result = verify_evidence(session, evidence, ctx, trigger="scheduled_sweep")
        checked += 1
        bytes_read += evidence.size_bytes
        statuses[result.status.value] = statuses.get(result.status.value, 0) + 1
        if not result.ok:
            failed += 1

    logger.info("integrity_sweep_completed", checked=checked, failed=failed, bytes_read=bytes_read)
    return {
        "checked": checked,
        "failed": failed,
        "bytes_read": bytes_read,
        "by_status": statuses,
        "candidates_available": len(candidates),
    }


@task(
    "integrity.reverify_failures",
    max_attempts=1,
    priority=80,
    description="Re-check items currently recorded as failing verification",
)
def reverify_failures(
    session: Session, ctx: RequestContext, payload: dict[str, Any]
) -> dict[str, Any]:
    """Re-examine known failures more often than the general sweep would.

    An item in a failed state is an active incident, so it is checked on its own cadence rather
    than waiting for the sweep to come round to it again.
    """
    failing = (
        session.execute(
            select(Evidence).where(
                or_(
                    Evidence.integrity_status == IntegrityStatus.hash_mismatch,
                    Evidence.integrity_status == IntegrityStatus.decryption_failed,
                    Evidence.integrity_status == IntegrityStatus.object_missing,
                )
            )
        )
        .scalars()
        .all()
    )

    recovered = 0
    for evidence in failing:
        result = verify_evidence(session, evidence, ctx, trigger="failure_recheck")
        if result.ok:
            recovered += 1
            logger.warning(
                "integrity_failure_recovered",
                evidence=evidence.reference,
                note="item now verifies; confirm a restore was performed deliberately",
            )

    return {
        "rechecked": len(failing),
        "recovered": recovered,
        "checked_at": utcnow().isoformat(),
    }


@task(
    "integrity.verify_chains",
    max_attempts=1,
    priority=150,
    description="Replay the audit and custody hash chains and alert on any break",
)
def verify_chains(session: Session, ctx: RequestContext, payload: dict[str, Any]) -> dict[str, Any]:
    """Replay the tamper-evident chains and raise a critical alert on any break.

    A chain break is categorically more serious than a single corrupted artifact: it means the
    record of what happened has been interfered with, so it is alerted at critical severity
    regardless of how few entries are affected.
    """
    from app.audit.chain import verify_audit_chain
    from app.models.enums import AlertSource, AlertType, Severity
    from app.services import alert_service

    audit_window = int(payload.get("audit_window", 5000))
    audit = verify_audit_chain(session, limit=audit_window)

    if not audit.intact:
        alert_service.raise_alert(
            session,
            ctx,
            alert_type=AlertType.chain_verification_failure,
            source=AlertSource.integrity_verifier,
            severity=Severity.critical,
            title="Audit chain verification failed",
            description=(
                f"Replaying the audit chain found {len(audit.breaks)} break(s) across "
                f"{audit.entries_checked} entries. The audit record itself may have been "
                "altered."
            ),
            dedupe_key="chain:audit",
            details={
                "breaks": [
                    {"kind": b.kind, "sequence": b.sequence, "detail": b.detail}
                    for b in audit.breaks[:20]
                ],
                "entries_checked": audit.entries_checked,
                "signatures_valid": audit.signatures_valid,
                "signatures_checked": audit.signatures_checked,
            },
            recommended_action=(
                "Treat the platform as compromised until proven otherwise. Compare against "
                "off-host backups of the audit table, review database-level access, and "
                "preserve the current state before making any changes."
            ),
            notify_case_team=False,
        )

    # Custody chains are verified per item; the ones whose evidence was touched most recently are
    # checked first, since recent interference is the case worth catching quickly.
    from app.services.custody_service import chain_status

    limit = int(payload.get("custody_limit", 100))
    items = (
        session.execute(
            select(Evidence)
            .where(Evidence.custody_event_count > 0)
            .order_by(Evidence.updated_at.desc())
            .limit(limit)
        )
        .scalars()
        .all()
    )

    broken: list[str] = []
    for evidence in items:
        status = chain_status(session, evidence)
        if status.trustworthy:
            continue
        broken.append(evidence.reference)
        alert_service.raise_alert(
            session,
            ctx,
            alert_type=AlertType.chain_verification_failure,
            source=AlertSource.integrity_verifier,
            severity=Severity.critical,
            title=f"Custody chain verification failed for {evidence.reference}",
            description=(
                f"Replaying the chain of custody for {evidence.reference} found "
                f"{len(status.breaks)} break(s). The custody record for this artifact can no "
                "longer be relied upon in its current form."
            ),
            dedupe_key=f"chain:custody:{evidence.id}",
            case_id=evidence.case_id,
            evidence_id=evidence.id,
            details={
                "breaks": [asdict(issue) for issue in status.breaks[:20]],
                "event_count": status.event_count,
            },
            recommended_action=(
                "Preserve the current database state, then compare the affected entries with "
                "backups. Do not present this item's custody history in a report until the "
                "discrepancy is explained."
            ),
        )

    logger.info(
        "chain_verification_completed",
        audit_intact=audit.intact,
        custody_checked=len(items),
        custody_broken=len(broken),
    )
    return {
        "audit_intact": audit.intact,
        "audit_entries_checked": audit.entries_checked,
        "audit_breaks": len(audit.breaks),
        "custody_chains_checked": len(items),
        "custody_chains_broken": broken,
    }
