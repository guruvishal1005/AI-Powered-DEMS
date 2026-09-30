"""Evidence ingestion, retrieval and lifecycle.

Ingestion is the most consequential operation in the platform, because everything downstream -
custody, analysis, findings, reports - inherits whatever is established here. The order of steps
is therefore deliberate:

1. Encrypt and hash in a single streaming pass, so the fingerprint is taken from exactly the
   bytes that were written and nothing is ever buffered whole.
2. Resolve deduplication against the database, publishing the object only once its identity is
   known and no existing copy has been found.
3. **Read the object back, decrypt it and re-hash it** before declaring the item preserved. This
   write-verify step is what imaging tools do, and it is the difference between "we believe we
   stored it" and "we have proven we can retrieve it unchanged".
4. Open the custody chain, with collection and upload recorded as separate events because they
   are separate facts, often performed by different people at different times.
5. Queue analysis, which never blocks the response.

Retrieval mirrors this: content is verified *before* a single byte reaches the client, so a
compromised artifact cannot be silently handed over and then reported as broken afterwards.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from datetime import datetime
from typing import Any, BinaryIO

from sqlalchemy import Select, func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, joinedload, selectinload

from app.audit.writer import append_audit, append_custody
from app.core.canonical import jsonable
from app.core.clock import utcnow
from app.core.context import RequestContext
from app.core.errors import (
    Conflict,
    IntegrityViolation,
    NotFound,
    StorageError,
    ValidationFailed,
)
from app.core.logging import get_logger
from app.core.pagination import PageParams, paginate
from app.forensics import filetype
from app.forensics.integrity import ref_for, verify_evidence, verify_object
from app.models.enums import (
    AcquisitionMethod,
    AuditResult,
    CustodyAction,
    EvidenceStatus,
    EvidenceType,
    IntegrityStatus,
    Severity,
    SourceCategory,
)
from app.models.evidence import (
    Evidence,
    EvidenceNote,
    EvidenceVersion,
    IntegrityCheck,
    StoredObject,
    Tag,
)
from app.security.scoping import scope_case_ids
from app.services import case_service
from app.services.reference_service import next_evidence_reference
from app.storage.base import StagedObject, StoredObjectRef
from app.storage.local import get_storage

logger = get_logger(__name__)

# A download must be justified. The reason is written into the custody chain, so a bare
# "because I wanted it" is worse than useless - it has to be specific enough to review later.
MIN_REASON_LENGTH = 8

_EDITABLE_FIELDS = frozenset(
    {
        "title",
        "description",
        "evidence_type",
        "source_category",
        "acquisition_method",
        "source_description",
        "source_identifier",
        "source_location",
        "acquired_at",
        "acquired_by_name",
        "received_at",
    }
)


def _base_query() -> Select[tuple[Evidence]]:
    return select(Evidence).options(
        joinedload(Evidence.current_version).joinedload(EvidenceVersion.stored_object),
        selectinload(Evidence.tags),
    )


def get_evidence(db: Session, ctx: RequestContext, evidence_id: uuid.UUID) -> Evidence:
    """Load an evidence item within the actor's case scope, or report it as missing."""
    stmt = scope_case_ids(_base_query().where(Evidence.id == evidence_id), ctx, Evidence.case_id)
    evidence = db.execute(stmt).unique().scalar_one_or_none()
    if evidence is None:
        raise NotFound("Evidence", str(evidence_id))
    return evidence


def get_evidence_by_reference(db: Session, ctx: RequestContext, reference: str) -> Evidence:
    stmt = scope_case_ids(
        _base_query().where(Evidence.reference == reference), ctx, Evidence.case_id
    )
    evidence = db.execute(stmt).unique().scalar_one_or_none()
    if evidence is None:
        raise NotFound("Evidence", reference)
    return evidence


def list_evidence(
    db: Session,
    ctx: RequestContext,
    params: PageParams,
    *,
    case_id: uuid.UUID | None = None,
    evidence_type: list[EvidenceType] | None = None,
    status: list[EvidenceStatus] | None = None,
    integrity_status: list[IntegrityStatus] | None = None,
    source_category: list[SourceCategory] | None = None,
    acquisition_method: list[AcquisitionMethod] | None = None,
    uploaded_by_id: uuid.UUID | None = None,
    tag: str | None = None,
    search: str | None = None,
    sha256: str | None = None,
    mime_mismatch: bool | None = None,
    uploaded_after: datetime | None = None,
    uploaded_before: datetime | None = None,
    sort: str = "uploaded",
    descending: bool = True,
) -> tuple[list[Evidence], int]:
    stmt = scope_case_ids(_base_query(), ctx, Evidence.case_id)

    if case_id:
        # Confirms access to the case explicitly, so a caller filtering by an out-of-scope case
        # gets a clear not-found rather than a silently empty page.
        case_service.get_case(db, ctx, case_id)
        stmt = stmt.where(Evidence.case_id == case_id)
    if evidence_type:
        stmt = stmt.where(Evidence.evidence_type.in_(evidence_type))
    if status:
        stmt = stmt.where(Evidence.status.in_(status))
    if integrity_status:
        stmt = stmt.where(Evidence.integrity_status.in_(integrity_status))
    if source_category:
        stmt = stmt.where(Evidence.source_category.in_(source_category))
    if acquisition_method:
        stmt = stmt.where(Evidence.acquisition_method.in_(acquisition_method))
    if uploaded_by_id:
        stmt = stmt.where(Evidence.uploaded_by_id == uploaded_by_id)
    if mime_mismatch is not None:
        stmt = stmt.where(Evidence.mime_mismatch.is_(mime_mismatch))
    if sha256:
        # Hash lookup is exact and case-insensitive; investigators paste digests from tooling
        # in whatever case that tooling emits.
        stmt = stmt.where(Evidence.sha256 == sha256.strip().lower())
    if tag:
        stmt = stmt.where(Evidence.tags.any(Tag.name == tag))
    if uploaded_after:
        stmt = stmt.where(Evidence.uploaded_at >= uploaded_after)
    if uploaded_before:
        stmt = stmt.where(Evidence.uploaded_at <= uploaded_before)
    if search:
        pattern = f"%{search.strip()}%"
        stmt = stmt.where(
            or_(
                Evidence.reference.ilike(pattern),
                Evidence.title.ilike(pattern),
                Evidence.original_filename.ilike(pattern),
                Evidence.description.ilike(pattern),
                Evidence.source_identifier.ilike(pattern),
            )
        )

    sort_columns = {
        "uploaded": Evidence.uploaded_at,
        "acquired": Evidence.acquired_at,
        "size": Evidence.size_bytes,
        "title": Evidence.title,
        "reference": Evidence.reference,
        "type": Evidence.evidence_type,
        "integrity": Evidence.integrity_status,
    }
    column = sort_columns.get(sort, Evidence.uploaded_at)
    order = column.desc().nullslast() if descending else column.asc().nullsfirst()
    stmt = stmt.order_by(order, Evidence.reference.desc())

    return paginate(db, stmt, params)


# ------------------------------------------------------------------ ingestion


def _resolve_stored_object(db: Session, staged: StagedObject) -> tuple[StoredObject, bool]:
    """Find or create the stored object for a staged artifact.

    Deduplication happens here, against the unique index on ``sha256``, and the concurrent case
    is handled explicitly: two simultaneous uploads of the same artifact both stage successfully,
    then one loses the insert race. The loser deletes the object it just published and adopts the
    winner's row, which is safe because the row it adopts carries the data key for the copy that
    is actually being kept.
    """
    storage = get_storage()

    existing = db.execute(
        select(StoredObject).where(StoredObject.sha256 == staged.hashes.sha256)
    ).scalar_one_or_none()
    if existing is not None:
        storage.discard(staged)
        existing.reference_count += 1
        return existing, True

    storage_key = storage.commit(staged)
    try:
        with db.begin_nested():
            stored = StoredObject(
                sha256=staged.hashes.sha256,
                size_bytes=staged.hashes.size_bytes,
                backend="local_encrypted",
                storage_key=storage_key,
                encryption_algorithm=staged.encryption_algorithm,
                nonce=staged.nonce,
                wrapped_key=staged.wrapped_key,
                key_version=staged.key_version,
                ciphertext_size=staged.ciphertext_size,
                ciphertext_sha256=staged.ciphertext_sha256,
                reference_count=1,
            )
            db.add(stored)
            db.flush()
    except IntegrityError:
        storage.delete(
            StoredObjectRef(
                storage_key=storage_key,
                nonce=staged.nonce,
                wrapped_key=staged.wrapped_key,
                key_version=staged.key_version,
                expected_sha256=staged.hashes.sha256,
                expected_ciphertext_sha256=staged.ciphertext_sha256,
                size_bytes=staged.hashes.size_bytes,
            )
        )
        winner = db.execute(
            select(StoredObject).where(StoredObject.sha256 == staged.hashes.sha256)
        ).scalar_one()
        winner.reference_count += 1
        logger.info("stored_object_race_resolved", sha256=staged.hashes.sha256[:16])
        return winner, True

    return stored, False


def _write_verify(stored: StoredObject) -> None:
    """Prove the object can be read back and still hashes to its acquisition digest.

    Without this, a storage or encryption fault would be discovered at the first download or
    scheduled sweep - long after the original artifact may have been released - and the platform
    would have asserted preservation it never actually demonstrated.
    """
    result = verify_object(ref_for(stored))
    if not result.ok:
        raise StorageError(
            "The artifact was stored but could not be read back intact, so it has not been "
            f"accepted into evidence ({result.status.value}). {result.detail}"
        )


def ingest_evidence(
    db: Session,
    ctx: RequestContext,
    *,
    case_id: uuid.UUID,
    stream: BinaryIO,
    original_filename: str,
    title: str | None = None,
    description: str = "",
    declared_mime: str | None = None,
    evidence_type: EvidenceType | None = None,
    source_category: SourceCategory = SourceCategory.digital_device,
    acquisition_method: AcquisitionMethod = AcquisitionMethod.file_export,
    source_description: str | None = None,
    source_identifier: str | None = None,
    source_location: str | None = None,
    acquired_at: datetime | None = None,
    acquired_by_name: str | None = None,
    acquired_by_id: uuid.UUID | None = None,
    received_at: datetime | None = None,
    collection_notes: str | None = None,
    tags: list[str] | None = None,
) -> Evidence:
    """Register an artifact as evidence on a case and open its chain of custody."""
    case = case_service.get_case(db, ctx, case_id)
    case_service.require_open_case(case)

    if not original_filename.strip():
        raise ValidationFailed("A filename is required to register evidence")

    storage = get_storage()
    staged = storage.stage(stream)

    try:
        stored, deduplicated = _resolve_stored_object(db, staged)
    except Exception:
        storage.discard(staged)
        raise

    if not deduplicated:
        _write_verify(stored)

    identification = filetype.identify(
        staged.head, filename=original_filename, declared_mime=declared_mime
    )

    now = utcnow()
    evidence = Evidence(
        reference=next_evidence_reference(db),
        case_id=case_id,
        title=(title or original_filename).strip()[:240],
        description=description.strip(),
        original_filename=original_filename.strip()[:512],
        # An explicit type from the investigator wins, because they may know the artifact's role
        # better than its bytes reveal; otherwise content decides.
        evidence_type=evidence_type or identification.evidence_type,
        source_category=source_category,
        acquisition_method=acquisition_method,
        source_description=source_description,
        source_identifier=source_identifier,
        source_location=source_location,
        acquired_at=acquired_at,
        acquired_by_name=acquired_by_name or ctx.actor_label,
        acquired_by_id=acquired_by_id,
        received_at=received_at or now,
        uploaded_by_id=ctx.actor_id,
        uploaded_at=now,
        sha256=staged.hashes.sha256,
        size_bytes=staged.hashes.size_bytes,
        mime_type=identification.detected_mime,
        declared_mime_type=declared_mime,
        mime_mismatch=identification.extension_mismatch,
        status=EvidenceStatus.registered,
        integrity_status=IntegrityStatus.verified,
        integrity_note=(
            "Verified at ingestion: the stored object was read back, decrypted and re-hashed, "
            "and matches the digest computed from the received bytes."
        ),
        last_verified_at=now,
        version_count=1,
        extracted_metadata={"type_identification": identification.as_metadata()},
    )
    db.add(evidence)
    db.flush()

    version = EvidenceVersion(
        evidence_id=evidence.id,
        version_number=1,
        stored_object_id=stored.id,
        sha256=staged.hashes.sha256,
        sha1=staged.hashes.sha1,
        md5=staged.hashes.md5,
        size_bytes=staged.hashes.size_bytes,
        mime_type=identification.detected_mime,
        created_by_id=ctx.actor_id,
        reason="initial acquisition",
        is_current=True,
    )
    db.add(version)
    db.flush()
    evidence.current_version_id = version.id
    stored.last_verified_at = now

    db.add(
        IntegrityCheck(
            evidence_id=evidence.id,
            evidence_version_id=version.id,
            status=IntegrityStatus.verified,
            expected_sha256=staged.hashes.sha256,
            computed_sha256=staged.hashes.sha256,
            ciphertext_verified=True,
            trigger="ingest",
            checked_by_id=ctx.actor_id,
            detail=(
                "Write-verify at ingestion: object decrypted and re-hashed successfully."
                if not deduplicated
                else (
                    "Content matched an artifact already held in the store, which was verified "
                    "when first ingested; no new object was written."
                )
            ),
        )
    )

    if tags:
        _apply_tags(db, evidence, tags)

    _open_custody_chain(
        db,
        ctx,
        evidence,
        identification=identification,
        hashes_sha1=staged.hashes.sha1,
        hashes_md5=staged.hashes.md5,
        acquired_at=acquired_at,
        acquired_by_name=acquired_by_name,
        collection_notes=collection_notes,
        deduplicated=deduplicated,
    )

    append_audit(
        db,
        ctx,
        action="evidence.uploaded",
        resource_type="evidence",
        resource_id=evidence.id,
        resource_label=evidence.reference,
        case_id=case_id,
        after_state={
            "filename": evidence.original_filename,
            "sha256": evidence.sha256,
            "size_bytes": evidence.size_bytes,
            "mime_type": evidence.mime_type,
            "evidence_type": evidence.evidence_type.value,
            "deduplicated": deduplicated,
        },
        result=AuditResult.success,
    )

    case_service.touch_activity(db, case_id)
    _flag_mime_mismatch(db, ctx, evidence, identification)
    _queue_analysis(db, evidence)

    logger.info(
        "evidence_ingested",
        evidence=evidence.reference,
        case=case.reference,
        sha256=evidence.sha256[:16],
        size_bytes=evidence.size_bytes,
        mime=evidence.mime_type,
        deduplicated=deduplicated,
    )
    return evidence


def _open_custody_chain(
    db: Session,
    ctx: RequestContext,
    evidence: Evidence,
    *,
    identification: filetype.TypeIdentification,
    hashes_sha1: str,
    hashes_md5: str,
    acquired_at: datetime | None,
    acquired_by_name: str | None,
    collection_notes: str | None,
    deduplicated: bool,
) -> None:
    """Write the genesis events for a new evidence item.

    Collection and upload are recorded separately because they are separate facts. Collection
    often happened earlier, elsewhere, and by someone who is not a platform user; the custody
    chain has to be able to state that plainly rather than implying the uploader seized the
    artifact themselves. ``occurred_at`` therefore carries the acquisition time as reported,
    while ``recorded_at`` remains the server's own authoritative clock.
    """
    if acquired_at is not None or acquired_by_name:
        append_custody(
            db,
            ctx,
            evidence,
            CustodyAction.collected,
            occurred_at=acquired_at,
            new_state={
                "acquired_by": acquired_by_name or ctx.actor_label,
                "acquisition_method": evidence.acquisition_method.value,
                "source_description": evidence.source_description,
                "source_identifier": evidence.source_identifier,
                "source_location": evidence.source_location,
            },
            notes=collection_notes,
            details={
                "reported_acquisition_time": (acquired_at.isoformat() if acquired_at else None),
                "recorded_from": "investigator-supplied acquisition metadata",
            },
        )

    append_custody(
        db,
        ctx,
        evidence,
        CustodyAction.uploaded,
        new_state={
            "reference": evidence.reference,
            "status": evidence.status.value,
            "integrity_status": evidence.integrity_status.value,
        },
        details={
            "original_filename": evidence.original_filename,
            "size_bytes": evidence.size_bytes,
            "sha256": evidence.sha256,
            "sha1": hashes_sha1,
            "md5": hashes_md5,
            "detected_mime": identification.detected_mime,
            "declared_mime": identification.declared_mime,
            "extension_mismatch": identification.extension_mismatch,
            "encryption": "AES-256-GCM envelope",
            "storage_deduplicated": deduplicated,
            "write_verified": True,
        },
    )


def _flag_mime_mismatch(
    db: Session,
    ctx: RequestContext,
    evidence: Evidence,
    identification: filetype.TypeIdentification,
) -> None:
    """Raise an alert when a file's name disagrees with its content.

    Kept here rather than in the analyzer because it is knowable at ingestion, and a
    masquerading artifact is exactly the thing an investigator should not have to wait for a
    background job to be told about.
    """
    if not identification.extension_mismatch:
        return

    from app.models.enums import AlertSource, AlertType
    from app.services import alert_service

    alert_service.raise_alert(
        db,
        ctx,
        alert_type=AlertType.ai_anomaly_detected,
        source=AlertSource.anomaly_detector,
        severity=Severity.medium,
        title=f"File type mismatch on {evidence.reference}",
        description=(
            f"{identification.mismatch_detail} The declared name has been preserved exactly as "
            "supplied; only the detected type is used for analysis."
        ),
        dedupe_key=f"mime_mismatch:{evidence.id}",
        case_id=evidence.case_id,
        evidence_id=evidence.id,
        details={
            "original_filename": evidence.original_filename,
            "declared_extension": identification.declared_extension,
            "declared_mime": identification.declared_mime,
            "detected_mime": identification.detected_mime,
            "magic_description": identification.magic_description,
            "detector": identification.detector,
        },
        recommended_action=(
            "Confirm whether the mismatch is benign (a renamed export) or deliberate "
            "concealment. Treat executable content presented as a document as hostile until "
            "shown otherwise."
        ),
    )


def _queue_analysis(db: Session, evidence: Evidence, *, version_number: int | None = None) -> None:
    """Queue content analysis, which must never block the upload response."""
    from app.jobs.queue import enqueue
    from app.jobs.tasks.analysis import analysis_dedupe_key

    enqueue(
        db,
        "evidence.analyze",
        payload={"evidence_id": str(evidence.id)},
        case_id=evidence.case_id,
        evidence_id=evidence.id,
        # Shared with the periodic sweeps so a swept item cannot be queued twice.
        dedupe_key=analysis_dedupe_key(evidence, version_number),
    )


def add_version(
    db: Session,
    ctx: RequestContext,
    evidence_id: uuid.UUID,
    *,
    stream: BinaryIO,
    reason: str,
    original_filename: str | None = None,
    declared_mime: str | None = None,
) -> EvidenceVersion:
    """Record a re-acquisition of an existing item as a new version.

    Versions are additive. The previous version keeps its own stored object, hashes and place in
    the custody chain, so the history of an item that was re-imaged remains fully reconstructable
    rather than being overwritten by the latest copy.
    """
    evidence = get_evidence(db, ctx, evidence_id)
    case = case_service.get_case(db, ctx, evidence.case_id)
    case_service.require_open_case(case)

    if not reason.strip():
        raise ValidationFailed("A reason is required to add a new version")

    storage = get_storage()
    staged = storage.stage(stream)
    try:
        stored, deduplicated = _resolve_stored_object(db, staged)
    except Exception:
        storage.discard(staged)
        raise

    if staged.hashes.sha256 == evidence.sha256:
        # Not an error: re-acquiring an unchanged artifact and finding it identical is a
        # meaningful forensic result, so it is recorded rather than rejected.
        logger.info("evidence_version_identical", evidence=evidence.reference)

    if not deduplicated:
        _write_verify(stored)

    identification = filetype.identify(
        staged.head,
        filename=original_filename or evidence.original_filename,
        declared_mime=declared_mime,
    )

    next_number = evidence.version_count + 1
    for previous in evidence.versions:
        previous.is_current = False

    version = EvidenceVersion(
        evidence_id=evidence.id,
        version_number=next_number,
        stored_object_id=stored.id,
        sha256=staged.hashes.sha256,
        sha1=staged.hashes.sha1,
        md5=staged.hashes.md5,
        size_bytes=staged.hashes.size_bytes,
        mime_type=identification.detected_mime,
        created_by_id=ctx.actor_id,
        reason=reason.strip()[:240],
        is_current=True,
    )
    db.add(version)
    db.flush()

    previous_sha = evidence.sha256
    evidence.current_version_id = version.id
    evidence.version_count = next_number
    evidence.sha256 = staged.hashes.sha256
    evidence.size_bytes = staged.hashes.size_bytes
    evidence.mime_type = identification.detected_mime
    evidence.mime_mismatch = identification.extension_mismatch
    evidence.integrity_status = IntegrityStatus.verified
    evidence.last_verified_at = utcnow()
    evidence.status = EvidenceStatus.registered

    append_custody(
        db,
        ctx,
        evidence,
        CustodyAction.version_created,
        previous_state={"version": next_number - 1, "sha256": previous_sha},
        new_state={"version": next_number, "sha256": staged.hashes.sha256},
        reason=reason,
        details={
            "size_bytes": staged.hashes.size_bytes,
            "sha1": staged.hashes.sha1,
            "md5": staged.hashes.md5,
            "content_identical_to_previous": staged.hashes.sha256 == previous_sha,
            "storage_deduplicated": deduplicated,
        },
    )
    append_audit(
        db,
        ctx,
        action="evidence.version_created",
        resource_type="evidence",
        resource_id=evidence.id,
        resource_label=evidence.reference,
        case_id=evidence.case_id,
        before_state={"version": next_number - 1, "sha256": previous_sha},
        after_state={"version": next_number, "sha256": staged.hashes.sha256},
        reason=reason,
        result=AuditResult.success,
    )

    case_service.touch_activity(db, evidence.case_id)
    _queue_analysis(db, evidence, version_number=next_number)
    return version


# ------------------------------------------------------------------ retrieval


def _require_reason(reason: str | None) -> str:
    if not reason or len(reason.strip()) < MIN_REASON_LENGTH:
        raise ValidationFailed(
            "Access to raw evidence content must be justified. Provide a reason of at least "
            f"{MIN_REASON_LENGTH} characters; it is recorded permanently in the chain of "
            "custody.",
            details={"min_length": MIN_REASON_LENGTH},
        )
    return reason.strip()


def prepare_download(
    db: Session,
    ctx: RequestContext,
    evidence_id: uuid.UUID,
    *,
    reason: str | None,
    version_number: int | None = None,
) -> tuple[Evidence, EvidenceVersion, StoredObjectRef]:
    """Authorise, justify and verify a download, then hand back the means to stream it.

    Verification happens *before* any content is released. Streaming first and verifying later
    would mean a tampered artifact had already left the platform by the time the failure was
    known, and the audit trail would show a successful download of evidence that was not intact.
    """
    justification = _require_reason(reason)
    evidence = get_evidence(db, ctx, evidence_id)
    version = _resolve_version(db, evidence, version_number)

    stored = db.get(StoredObject, version.stored_object_id)
    if stored is None:
        raise NotFound("Stored object", str(version.stored_object_id))

    scoped_ctx = ctx.with_reason(justification)
    result = verify_evidence(db, evidence, scoped_ctx, trigger="pre_download", version=version)
    if not result.ok:
        # The failure has already been recorded to custody, alerted on, and audited by the
        # verifier; refusing the download is the remaining step.
        append_audit(
            db,
            scoped_ctx,
            action="evidence.download",
            resource_type="evidence",
            resource_id=evidence.id,
            resource_label=evidence.reference,
            case_id=evidence.case_id,
            reason=justification,
            detail=f"Refused: {result.status.value}. {result.detail}",
            result=AuditResult.failure,
        )
        raise IntegrityViolation(
            f"{evidence.reference} failed integrity verification and will not be released. "
            f"{result.detail}",
            details={"integrity_status": result.status.value},
        )

    append_custody(
        db,
        scoped_ctx,
        evidence,
        CustodyAction.downloaded,
        reason=justification,
        details={
            "version_number": version.version_number,
            "sha256": version.sha256,
            "size_bytes": version.size_bytes,
            "verified_before_release": True,
        },
    )
    append_audit(
        db,
        scoped_ctx,
        action="evidence.download",
        resource_type="evidence",
        resource_id=evidence.id,
        resource_label=evidence.reference,
        case_id=evidence.case_id,
        reason=justification,
        after_state={"version": version.version_number, "sha256": version.sha256},
        result=AuditResult.success,
    )
    logger.info(
        "evidence_download_authorised",
        evidence=evidence.reference,
        actor=ctx.actor_label,
        version=version.version_number,
    )
    return evidence, version, ref_for(stored)


def stream_content(ref: StoredObjectRef) -> Iterator[bytes]:
    """Yield decrypted content for an already-verified object.

    Separate from :func:`prepare_download` because the two happen at different times: the
    database work commits while the request is still in hand, and this generator runs afterwards
    as the response body is written, by which point no session is available.
    """
    return get_storage().open_stream(ref)


def read_preview(
    db: Session,
    ctx: RequestContext,
    evidence_id: uuid.UUID,
    *,
    max_bytes: int = 64 * 1024,
    version_number: int | None = None,
) -> tuple[Evidence, bytes]:
    """Return a bounded prefix of an artifact for on-screen preview.

    Preview is a distinct permission from download because it is a different disclosure: a
    bounded, non-executable excerpt rendered in the interface, rather than the artifact itself.
    It is still recorded to the custody chain - looking at evidence is an access event.
    """
    evidence = get_evidence(db, ctx, evidence_id)
    version = _resolve_version(db, evidence, version_number)
    stored = db.get(StoredObject, version.stored_object_id)
    if stored is None:
        raise NotFound("Stored object", str(version.stored_object_id))

    data = get_storage().read_prefix(ref_for(stored), max_bytes)

    append_custody(
        db,
        ctx,
        evidence,
        CustodyAction.previewed,
        details={
            "version_number": version.version_number,
            "bytes_read": len(data),
            "truncated": len(data) < version.size_bytes,
        },
    )
    append_audit(
        db,
        ctx,
        action="evidence.previewed",
        resource_type="evidence",
        resource_id=evidence.id,
        resource_label=evidence.reference,
        case_id=evidence.case_id,
        result=AuditResult.success,
    )
    return evidence, data


def record_access(db: Session, ctx: RequestContext, evidence: Evidence) -> None:
    """Record that an item's metadata was examined.

    Metadata access is logged to the audit trail rather than the custody chain. Custody records
    what happened *to the artifact*; if every detail page view appended a custody event, the
    chain of custody would become a page-view log and the events that matter would be lost in it.
    """
    append_audit(
        db,
        ctx,
        action="evidence.accessed",
        resource_type="evidence",
        resource_id=evidence.id,
        resource_label=evidence.reference,
        case_id=evidence.case_id,
        result=AuditResult.success,
    )


def _resolve_version(
    db: Session, evidence: Evidence, version_number: int | None
) -> EvidenceVersion:
    if version_number is None:
        if evidence.current_version is None:
            raise NotFound("Evidence version", evidence.reference)
        return evidence.current_version
    version = db.execute(
        select(EvidenceVersion)
        .where(EvidenceVersion.evidence_id == evidence.id)
        .where(EvidenceVersion.version_number == version_number)
    ).scalar_one_or_none()
    if version is None:
        raise NotFound("Evidence version", f"{evidence.reference} v{version_number}")
    return version


def verify_now(
    db: Session,
    ctx: RequestContext,
    evidence_id: uuid.UUID,
    *,
    version_number: int | None = None,
    trigger: str = "manual",
) -> tuple[Evidence, Any]:
    """Verify an item on demand, returning the item and the verification result."""
    evidence = get_evidence(db, ctx, evidence_id)
    version = _resolve_version(db, evidence, version_number) if version_number is not None else None
    result = verify_evidence(db, evidence, ctx, trigger=trigger, version=version)
    return evidence, result


def list_versions(
    db: Session, ctx: RequestContext, evidence_id: uuid.UUID
) -> list[EvidenceVersion]:
    evidence = get_evidence(db, ctx, evidence_id)
    return list(
        db.execute(
            select(EvidenceVersion)
            .where(EvidenceVersion.evidence_id == evidence.id)
            .order_by(EvidenceVersion.version_number.desc())
        )
        .scalars()
        .all()
    )


def list_integrity_checks(
    db: Session, ctx: RequestContext, evidence_id: uuid.UUID, limit: int = 50
) -> list[IntegrityCheck]:
    evidence = get_evidence(db, ctx, evidence_id)
    return list(
        db.execute(
            select(IntegrityCheck)
            .where(IntegrityCheck.evidence_id == evidence.id)
            .order_by(IntegrityCheck.created_at.desc())
            .limit(limit)
        )
        .scalars()
        .all()
    )


# ------------------------------------------------------------------ mutation


def update_metadata(
    db: Session, ctx: RequestContext, evidence_id: uuid.UUID, changes: dict[str, Any]
) -> Evidence:
    """Edit descriptive metadata.

    Hashes, sizes, stored objects and integrity state are absent from the editable set by
    design: they are observations about the artifact, not opinions about it, and allowing them
    to be edited would make every integrity claim in the platform meaningless.
    """
    evidence = get_evidence(db, ctx, evidence_id)
    case = case_service.get_case(db, ctx, evidence.case_id)
    case_service.require_open_case(case)

    unknown = set(changes) - _EDITABLE_FIELDS
    if unknown:
        raise ValidationFailed(f"These fields cannot be edited: {', '.join(sorted(unknown))}")

    before: dict[str, Any] = {}
    after: dict[str, Any] = {}
    for field_name, value in changes.items():
        current = getattr(evidence, field_name)
        if current == value:
            continue
        before[field_name] = jsonable(current)
        after[field_name] = jsonable(value)
        setattr(evidence, field_name, value)

    if not after:
        return evidence

    append_custody(
        db,
        ctx,
        evidence,
        CustodyAction.metadata_updated,
        previous_state=before,
        new_state=after,
    )
    append_audit(
        db,
        ctx,
        action="evidence.updated",
        resource_type="evidence",
        resource_id=evidence.id,
        resource_label=evidence.reference,
        case_id=evidence.case_id,
        before_state=before,
        after_state=after,
        result=AuditResult.success,
    )
    case_service.touch_activity(db, evidence.case_id)
    return evidence


def _apply_tags(db: Session, evidence: Evidence, names: list[str]) -> None:
    for raw in names:
        name = raw.strip().lower()[:64]
        if not name:
            continue
        tag = db.execute(select(Tag).where(Tag.name == name)).scalar_one_or_none()
        if tag is None:
            tag = Tag(name=name)
            db.add(tag)
            db.flush()
        if tag not in evidence.tags:
            evidence.tags.append(tag)


def set_tags(
    db: Session, ctx: RequestContext, evidence_id: uuid.UUID, names: list[str]
) -> Evidence:
    evidence = get_evidence(db, ctx, evidence_id)
    before = sorted(tag.name for tag in evidence.tags)
    evidence.tags.clear()
    _apply_tags(db, evidence, names)
    db.flush()
    after = sorted(tag.name for tag in evidence.tags)
    if before != after:
        append_audit(
            db,
            ctx,
            action="evidence.tagged",
            resource_type="evidence",
            resource_id=evidence.id,
            resource_label=evidence.reference,
            case_id=evidence.case_id,
            before_state={"tags": before},
            after_state={"tags": after},
            result=AuditResult.success,
        )
    return evidence


def add_note(
    db: Session, ctx: RequestContext, evidence_id: uuid.UUID, *, body: str
) -> EvidenceNote:
    evidence = get_evidence(db, ctx, evidence_id)
    note = EvidenceNote(evidence_id=evidence.id, author_id=ctx.actor_id, body=body.strip())
    db.add(note)
    db.flush()
    append_audit(
        db,
        ctx,
        action="evidence.note_added",
        resource_type="evidence_note",
        resource_id=note.id,
        resource_label=evidence.reference,
        case_id=evidence.case_id,
        result=AuditResult.success,
    )
    return note


def list_notes(db: Session, ctx: RequestContext, evidence_id: uuid.UUID) -> list[EvidenceNote]:
    evidence = get_evidence(db, ctx, evidence_id)
    return list(
        db.execute(
            select(EvidenceNote)
            .where(EvidenceNote.evidence_id == evidence.id)
            .order_by(EvidenceNote.created_at.desc())
        )
        .scalars()
        .all()
    )


def archive_evidence(
    db: Session, ctx: RequestContext, evidence_id: uuid.UUID, *, reason: str
) -> Evidence:
    """Move an item out of active working state without destroying anything."""
    evidence = get_evidence(db, ctx, evidence_id)
    if evidence.status is EvidenceStatus.archived:
        raise Conflict(f"{evidence.reference} is already archived")

    previous = evidence.status
    evidence.status = EvidenceStatus.archived
    append_custody(
        db,
        ctx,
        evidence,
        CustodyAction.archived,
        previous_state={"status": previous.value},
        new_state={"status": EvidenceStatus.archived.value},
        reason=reason,
    )
    append_audit(
        db,
        ctx,
        action="evidence.archived",
        resource_type="evidence",
        resource_id=evidence.id,
        resource_label=evidence.reference,
        case_id=evidence.case_id,
        before_state={"status": previous.value},
        after_state={"status": EvidenceStatus.archived.value},
        reason=reason,
        result=AuditResult.success,
    )
    return evidence


def set_legal_hold(
    db: Session, ctx: RequestContext, evidence_id: uuid.UUID, *, hold: bool, reason: str
) -> Evidence:
    """Apply or release a legal hold, which overrides retention-driven disposal."""
    evidence = get_evidence(db, ctx, evidence_id)
    if evidence.legal_hold == hold:
        raise Conflict(
            f"{evidence.reference} already has legal hold {'applied' if hold else 'released'}"
        )
    evidence.legal_hold = hold
    action = CustodyAction.legal_hold_applied if hold else CustodyAction.legal_hold_released
    append_custody(
        db,
        ctx,
        evidence,
        action,
        previous_state={"legal_hold": not hold},
        new_state={"legal_hold": hold},
        reason=reason,
    )
    append_audit(
        db,
        ctx,
        action=f"evidence.{action.value}",
        resource_type="evidence",
        resource_id=evidence.id,
        resource_label=evidence.reference,
        case_id=evidence.case_id,
        after_state={"legal_hold": hold},
        reason=reason,
        result=AuditResult.success,
    )
    return evidence


def storage_summary(db: Session) -> dict[str, Any]:
    """Object-store totals for the administration dashboard."""
    row = db.execute(
        select(
            func.count(StoredObject.id),
            func.coalesce(func.sum(StoredObject.size_bytes), 0),
            func.coalesce(func.sum(StoredObject.ciphertext_size), 0),
        )
    ).one()
    logical = db.execute(select(func.coalesce(func.sum(Evidence.size_bytes), 0))).scalar_one()
    object_count, plaintext_bytes, ciphertext_bytes = row
    return {
        "object_count": object_count,
        "unique_bytes": int(plaintext_bytes),
        "encrypted_bytes": int(ciphertext_bytes),
        "logical_bytes": int(logical),
        # What deduplication actually saved, rather than a claim that it works.
        "deduplicated_bytes": max(0, int(logical) - int(plaintext_bytes)),
    }
