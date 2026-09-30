"""Evidence integrity verification.

Verification answers one question - are these still the bytes that were acquired? - but the
*way* it fails carries most of the forensic value, so the three failure modes are kept strictly
separate:

``decryption_failed``
    AES-GCM authentication rejected the stored ciphertext. Someone or something modified the
    encrypted container at rest. The original content is unrecoverable from this copy.

``hash_mismatch``
    The ciphertext authenticated correctly and decrypted cleanly, yet the plaintext no longer
    matches the digest recorded at acquisition. This is the more alarming outcome: it implies
    substitution through a path that held the encryption key.

``object_missing``
    The stored object is gone. Distinct from corruption, because the response is restoration
    from backup rather than re-acquisition.

Collapsing these into one "corrupt" state would tell an investigator nothing about what
happened, which is why :class:`~app.models.enums.IntegrityStatus` models all three.

Every verification is persisted as an :class:`~app.models.evidence.IntegrityCheck` recording
both digests - including on success, so a report can show the actual comparison rather than
merely asserting that it passed - and every failure raises a custody event and an alert.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.audit.writer import append_custody
from app.core.clock import utcnow
from app.core.context import RequestContext
from app.core.errors import NotFound
from app.core.logging import get_logger
from app.forensics.hashing import MultiHasher
from app.models.enums import (
    AlertSource,
    AlertType,
    CustodyAction,
    EvidenceStatus,
    IntegrityStatus,
    Severity,
)
from app.models.evidence import Evidence, EvidenceVersion, IntegrityCheck, StoredObject
from app.storage.base import (
    CiphertextTampered,
    ObjectMissing,
    PlaintextMismatch,
    StoredObjectRef,
)
from app.storage.local import get_storage

logger = get_logger(__name__)


@dataclass(frozen=True, slots=True)
class VerificationResult:
    """Outcome of verifying one evidence version."""

    status: IntegrityStatus
    expected_sha256: str
    computed_sha256: str | None
    ciphertext_verified: bool
    duration_ms: int
    detail: str

    @property
    def ok(self) -> bool:
        return self.status is IntegrityStatus.verified


def ref_for(stored: StoredObject) -> StoredObjectRef:
    """Build a storage reference from a persisted object row."""
    return StoredObjectRef(
        storage_key=stored.storage_key,
        nonce=stored.nonce,
        wrapped_key=stored.wrapped_key,
        key_version=stored.key_version,
        expected_sha256=stored.sha256,
        expected_ciphertext_sha256=stored.ciphertext_sha256,
        size_bytes=stored.size_bytes,
    )


def verify_object(ref: StoredObjectRef) -> VerificationResult:
    """Fully verify one stored object: authenticate, decrypt, and re-hash the plaintext.

    Order matters. The ciphertext digest is checked first because it is cheap and identifies
    at-rest corruption precisely. The full decrypt follows, and only if AES-GCM authenticates
    the entire artifact is the plaintext hash compared - so a mismatch reported here genuinely
    means authenticated-but-substituted content, not container damage.
    """
    started = time.perf_counter()
    storage = get_storage()

    def elapsed() -> int:
        return int((time.perf_counter() - started) * 1000)

    try:
        ciphertext_ok = storage.verify_ciphertext(ref)
    except ObjectMissing as exc:
        return VerificationResult(
            status=IntegrityStatus.object_missing,
            expected_sha256=ref.expected_sha256,
            computed_sha256=None,
            ciphertext_verified=False,
            duration_ms=elapsed(),
            detail=str(exc),
        )

    hasher = MultiHasher()
    try:
        for chunk in storage.open_stream(ref):
            hasher.update(chunk)
    except CiphertextTampered as exc:
        return VerificationResult(
            status=IntegrityStatus.decryption_failed,
            expected_sha256=ref.expected_sha256,
            computed_sha256=None,
            ciphertext_verified=ciphertext_ok,
            duration_ms=elapsed(),
            detail=(
                f"AES-GCM authentication failed for the stored object. {exc} The encrypted "
                "container has been modified at rest; this copy cannot be trusted or recovered."
            ),
        )
    except ObjectMissing as exc:
        return VerificationResult(
            status=IntegrityStatus.object_missing,
            expected_sha256=ref.expected_sha256,
            computed_sha256=None,
            ciphertext_verified=False,
            duration_ms=elapsed(),
            detail=str(exc),
        )

    computed = hasher.result()
    if computed.sha256 != ref.expected_sha256:
        return VerificationResult(
            status=IntegrityStatus.hash_mismatch,
            expected_sha256=ref.expected_sha256,
            computed_sha256=computed.sha256,
            ciphertext_verified=ciphertext_ok,
            duration_ms=elapsed(),
            detail=(
                "The stored ciphertext authenticated successfully and decrypted cleanly, but "
                "the recovered content does not match the digest recorded at acquisition "
                f"(expected {ref.expected_sha256}, computed {computed.sha256}). Because "
                "authentication succeeded, the content was replaced by a party holding the "
                "encryption key rather than altered on disk."
            ),
        )

    if not ciphertext_ok:
        # Contradictory: GCM authenticated and the plaintext matches, yet the stored file does
        # not hash to the digest taken at ingestion. The evidence itself is intact, so this is
        # not an integrity failure, but it is a bookkeeping fault worth surfacing.
        return VerificationResult(
            status=IntegrityStatus.verified,
            expected_sha256=ref.expected_sha256,
            computed_sha256=computed.sha256,
            ciphertext_verified=False,
            duration_ms=elapsed(),
            detail=(
                "Content verified: the decrypted artifact matches its acquisition digest. Note "
                "that the recorded ciphertext digest did not match, which indicates the stored "
                "object was rewritten with equivalent content rather than that the evidence "
                "changed."
            ),
        )

    return VerificationResult(
        status=IntegrityStatus.verified,
        expected_sha256=ref.expected_sha256,
        computed_sha256=computed.sha256,
        ciphertext_verified=True,
        duration_ms=elapsed(),
        detail=(
            f"SHA-256 of the decrypted artifact matches the digest recorded at acquisition, "
            f"and AES-GCM authenticated {computed.size_bytes} bytes of stored ciphertext."
        ),
    )


def verify_evidence(
    db: Session,
    evidence: Evidence,
    ctx: RequestContext,
    *,
    trigger: str = "manual",
    version: EvidenceVersion | None = None,
    record_custody: bool = True,
) -> VerificationResult:
    """Verify an evidence item's current version and persist the outcome.

    Deliberately writes on every call, success or failure. A verification history with only
    failures in it cannot demonstrate continuous preservation, which is the claim a forensic
    report ultimately needs to make.
    """
    target = version or evidence.current_version
    if target is None:
        raise NotFound("Evidence version", str(evidence.id))

    stored = db.get(StoredObject, target.stored_object_id)
    if stored is None:
        raise NotFound("Stored object", str(target.stored_object_id))

    result = verify_object(ref_for(stored))

    db.add(
        IntegrityCheck(
            evidence_id=evidence.id,
            evidence_version_id=target.id,
            status=result.status,
            expected_sha256=result.expected_sha256,
            computed_sha256=result.computed_sha256,
            ciphertext_verified=result.ciphertext_verified,
            trigger=trigger,
            checked_by_id=ctx.actor_id,
            duration_ms=result.duration_ms,
            detail=result.detail,
        )
    )

    now = utcnow()
    previous_status = evidence.integrity_status
    evidence.integrity_status = result.status
    evidence.integrity_note = result.detail
    evidence.last_verified_at = now
    stored.last_verified_at = now

    if not result.ok:
        # An item that failed verification must not silently continue to look ordinary in
        # listings, so its lifecycle status is escalated too.
        evidence.status = EvidenceStatus.requires_attention

    if record_custody:
        # Written before the alert so the custody chain reflects the check even if alerting
        # fails, and so the event's integrity snapshot carries the *new* status.
        append_custody(
            db,
            ctx,
            evidence,
            CustodyAction.verified if result.ok else CustodyAction.integrity_failed,
            previous_state={"integrity_status": previous_status.value},
            new_state={"integrity_status": result.status.value},
            notes=result.detail,
            details={
                "trigger": trigger,
                "expected_sha256": result.expected_sha256,
                "computed_sha256": result.computed_sha256,
                "ciphertext_verified": result.ciphertext_verified,
                "duration_ms": result.duration_ms,
                "version_number": target.version_number,
            },
        )

    if not result.ok:
        _raise_integrity_alert(db, evidence, result, ctx, trigger)
        logger.error(
            "integrity_verification_failed",
            evidence=evidence.reference,
            status=result.status.value,
            trigger=trigger,
        )

    return result


def _raise_integrity_alert(
    db: Session,
    evidence: Evidence,
    result: VerificationResult,
    ctx: RequestContext,
    trigger: str,
) -> None:
    from app.services import alert_service

    severity = (
        Severity.critical
        if result.status in {IntegrityStatus.hash_mismatch, IntegrityStatus.decryption_failed}
        else Severity.high
    )
    alert_service.raise_alert(
        db,
        ctx,
        alert_type=AlertType.integrity_failure,
        source=AlertSource.integrity_verifier,
        severity=severity,
        title=f"Integrity verification failed for {evidence.reference}",
        description=result.detail,
        # One alert per evidence item and failure mode: a nightly sweep over a broken object
        # should reopen the same alert, not manufacture a new one every night.
        dedupe_key=f"integrity:{evidence.id}:{result.status.value}",
        case_id=evidence.case_id,
        evidence_id=evidence.id,
        details={
            "trigger": trigger,
            "expected_sha256": result.expected_sha256,
            "computed_sha256": result.computed_sha256,
            "ciphertext_verified": result.ciphertext_verified,
            "detected_by": ctx.actor_label,
        },
        recommended_action=_recommended_action(result.status),
    )


def _recommended_action(status: IntegrityStatus) -> str:
    if status is IntegrityStatus.decryption_failed:
        return (
            "Treat this copy as compromised. Restore the object from the most recent verified "
            "backup, verify the restored copy, and review the audit log and filesystem access "
            "records for the period since the last successful verification."
        )
    if status is IntegrityStatus.hash_mismatch:
        return (
            "Do not rely on this artifact. Authentication succeeded, so the substitution was "
            "made by a party with access to the encryption key: review all access to this "
            "evidence item, restore from backup, and re-verify against the acquisition record."
        )
    if status is IntegrityStatus.object_missing:
        return (
            "Restore the stored object from backup and re-verify. Confirm whether the deletion "
            "was an authorised retention disposition by checking the custody chain."
        )
    return "Re-run verification and investigate if the result does not change."


def verify_evidence_by_id(
    db: Session,
    evidence_id: uuid.UUID,
    ctx: RequestContext,
    *,
    trigger: str = "manual",
) -> VerificationResult:
    evidence = db.execute(select(Evidence).where(Evidence.id == evidence_id)).scalar_one_or_none()
    if evidence is None:
        raise NotFound("Evidence", str(evidence_id))
    return verify_evidence(db, evidence, ctx, trigger=trigger)


__all__ = [
    "CiphertextTampered",
    "ObjectMissing",
    "PlaintextMismatch",
    "VerificationResult",
    "ref_for",
    "verify_evidence",
    "verify_evidence_by_id",
    "verify_object",
]
