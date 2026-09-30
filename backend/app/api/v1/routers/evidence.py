"""Evidence endpoints.

Two decisions here are security-relevant rather than cosmetic.

Downloads always leave as ``application/octet-stream`` with an attachment disposition, never as
the artifact's detected type. Evidence routinely *is* hostile content - that is why it is
evidence - and serving a stored HTML file as ``text/html`` would execute an attacker's script in
the context of the investigator's session.

Uploads are read as a stream rather than buffered. A forensic platform ingests artifacts far
larger than available memory, and the size limit is enforced against bytes actually read, so an
understated ``Content-Length`` cannot be used to slip past it.
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime
from typing import Annotated
from urllib.parse import quote

from fastapi import APIRouter, Depends, File, Form, Query, UploadFile, status
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app.core.clock import utcnow
from app.core.context import RequestContext
from app.core.errors import ValidationFailed
from app.core.pagination import Page, PageParams, page_params
from app.db.session import get_db
from app.models.enums import (
    AcquisitionMethod,
    EvidenceStatus,
    EvidenceType,
    IntegrityStatus,
    Permission,
    SourceCategory,
)
from app.schemas.evidence import (
    AcquisitionMetadata,
    ArchiveRequest,
    ChainBreakOut,
    ChainStatusOut,
    CustodyEventOut,
    EvidenceDetailOut,
    EvidenceNoteCreate,
    EvidenceNoteOut,
    EvidenceSummaryOut,
    EvidenceTagsUpdate,
    EvidenceUpdate,
    EvidenceVersionOut,
    IntegrityCheckOut,
    LegalHoldRequest,
    PreviewOut,
    StorageSummaryOut,
    VerificationOut,
)
from app.security.deps import require
from app.services import custody_service, evidence_service

router = APIRouter(prefix="/evidence", tags=["evidence"])

DbSession = Annotated[Session, Depends(get_db)]

# Preview is capped well below the download path: it exists to orient an investigator, not to
# become an unaudited way of reading an entire artifact.
PREVIEW_MAX_BYTES = 64 * 1024

_UNSAFE_FILENAME = re.compile(r"[^A-Za-z0-9._\- ]")


def _safe_filename(name: str) -> str:
    """Reduce a filename to something safe to put in a header.

    The original name is preserved verbatim in the database - it is evidence in its own right -
    but a name containing quotes, newlines or path separators must never be reflected into a
    ``Content-Disposition`` header, where it could break out of the field.
    """
    stem = name.replace("\\", "/").split("/")[-1]
    cleaned = _UNSAFE_FILENAME.sub("_", stem).strip() or "evidence.bin"
    return cleaned[:180]


@router.get("", response_model=Page[EvidenceSummaryOut], summary="List evidence")
def list_evidence(
    db: DbSession,
    ctx: Annotated[RequestContext, Depends(require(Permission.evidence_read))],
    params: Annotated[PageParams, Depends(page_params)],
    case_id: uuid.UUID | None = None,
    evidence_type: Annotated[list[EvidenceType] | None, Query()] = None,
    status_filter: Annotated[list[EvidenceStatus] | None, Query(alias="status")] = None,
    integrity_status: Annotated[list[IntegrityStatus] | None, Query()] = None,
    source_category: Annotated[list[SourceCategory] | None, Query()] = None,
    acquisition_method: Annotated[list[AcquisitionMethod] | None, Query()] = None,
    uploaded_by_id: uuid.UUID | None = None,
    tag: Annotated[str | None, Query(max_length=64)] = None,
    search: Annotated[str | None, Query(max_length=200)] = None,
    sha256: Annotated[str | None, Query(min_length=64, max_length=64)] = None,
    mime_mismatch: bool | None = None,
    uploaded_after: datetime | None = None,
    uploaded_before: datetime | None = None,
    sort: str = "uploaded",
    descending: bool = True,
) -> Page[EvidenceSummaryOut]:
    items, total = evidence_service.list_evidence(
        db,
        ctx,
        params,
        case_id=case_id,
        evidence_type=evidence_type,
        status=status_filter,
        integrity_status=integrity_status,
        source_category=source_category,
        acquisition_method=acquisition_method,
        uploaded_by_id=uploaded_by_id,
        tag=tag,
        search=search,
        sha256=sha256,
        mime_mismatch=mime_mismatch,
        uploaded_after=uploaded_after,
        uploaded_before=uploaded_before,
        sort=sort,
        descending=descending,
    )
    return Page.build([EvidenceSummaryOut.model_validate(item) for item in items], total, params)


@router.get(
    "/storage-summary",
    response_model=StorageSummaryOut,
    summary="Object store totals",
)
def storage_summary(
    db: DbSession,
    ctx: Annotated[RequestContext, Depends(require(Permission.system_read))],
) -> StorageSummaryOut:
    return StorageSummaryOut.model_validate(evidence_service.storage_summary(db))


@router.post(
    "",
    response_model=EvidenceDetailOut,
    status_code=status.HTTP_201_CREATED,
    summary="Upload and register evidence",
)
def upload_evidence(
    db: DbSession,
    ctx: Annotated[RequestContext, Depends(require(Permission.evidence_upload))],
    case_id: Annotated[uuid.UUID, Form(description="Case to register the artifact against")],
    file: Annotated[UploadFile, File(description="The artifact itself")],
    metadata: Annotated[
        str | None,
        Form(description="Acquisition metadata as a JSON object"),
    ] = None,
) -> EvidenceDetailOut:
    """Register an artifact as evidence, opening its chain of custody.

    Acquisition metadata arrives as a JSON part rather than as many form fields, so the same
    validated model applies whether an artifact is uploaded through the interface or by a script.
    """
    try:
        acquisition = (
            AcquisitionMetadata.model_validate_json(metadata) if metadata else AcquisitionMetadata()
        )
    except ValueError as exc:
        raise ValidationFailed(f"Acquisition metadata is not valid: {exc}") from exc

    evidence = evidence_service.ingest_evidence(
        db,
        ctx,
        case_id=case_id,
        stream=file.file,
        original_filename=file.filename or "unnamed",
        title=acquisition.title,
        description=acquisition.description,
        declared_mime=file.content_type,
        evidence_type=acquisition.evidence_type,
        source_category=acquisition.source_category,
        acquisition_method=acquisition.acquisition_method,
        source_description=acquisition.source_description,
        source_identifier=acquisition.source_identifier,
        source_location=acquisition.source_location,
        acquired_at=acquisition.acquired_at,
        acquired_by_name=acquisition.acquired_by_name,
        acquired_by_id=acquisition.acquired_by_id,
        received_at=acquisition.received_at,
        collection_notes=acquisition.collection_notes,
        tags=acquisition.tags,
    )
    db.commit()
    db.refresh(evidence)
    return EvidenceDetailOut.model_validate(evidence)


@router.get("/{evidence_id}", response_model=EvidenceDetailOut, summary="Evidence detail")
def get_evidence(
    evidence_id: uuid.UUID,
    db: DbSession,
    ctx: Annotated[RequestContext, Depends(require(Permission.evidence_read))],
) -> EvidenceDetailOut:
    evidence = evidence_service.get_evidence(db, ctx, evidence_id)
    evidence_service.record_access(db, ctx, evidence)
    db.commit()
    db.refresh(evidence)
    return EvidenceDetailOut.model_validate(evidence)


@router.patch(
    "/{evidence_id}", response_model=EvidenceDetailOut, summary="Update evidence metadata"
)
def update_evidence(
    evidence_id: uuid.UUID,
    payload: EvidenceUpdate,
    db: DbSession,
    ctx: Annotated[RequestContext, Depends(require(Permission.evidence_update))],
) -> EvidenceDetailOut:
    evidence = evidence_service.update_metadata(
        db, ctx, evidence_id, payload.model_dump(exclude_unset=True)
    )
    db.commit()
    db.refresh(evidence)
    return EvidenceDetailOut.model_validate(evidence)


@router.put("/{evidence_id}/tags", response_model=EvidenceDetailOut, summary="Replace tags")
def set_tags(
    evidence_id: uuid.UUID,
    payload: EvidenceTagsUpdate,
    db: DbSession,
    ctx: Annotated[RequestContext, Depends(require(Permission.evidence_update))],
) -> EvidenceDetailOut:
    evidence = evidence_service.set_tags(db, ctx, evidence_id, payload.tags)
    db.commit()
    db.refresh(evidence)
    return EvidenceDetailOut.model_validate(evidence)


@router.get(
    "/{evidence_id}/versions",
    response_model=list[EvidenceVersionOut],
    summary="Version history",
)
def list_versions(
    evidence_id: uuid.UUID,
    db: DbSession,
    ctx: Annotated[RequestContext, Depends(require(Permission.evidence_read))],
) -> list[EvidenceVersionOut]:
    return [
        EvidenceVersionOut.model_validate(version)
        for version in evidence_service.list_versions(db, ctx, evidence_id)
    ]


@router.post(
    "/{evidence_id}/versions",
    response_model=EvidenceVersionOut,
    status_code=status.HTTP_201_CREATED,
    summary="Record a re-acquisition as a new version",
)
def add_version(
    evidence_id: uuid.UUID,
    db: DbSession,
    ctx: Annotated[RequestContext, Depends(require(Permission.evidence_upload))],
    file: Annotated[UploadFile, File()],
    reason: Annotated[str, Form(min_length=3, max_length=240)],
) -> EvidenceVersionOut:
    version = evidence_service.add_version(
        db,
        ctx,
        evidence_id,
        stream=file.file,
        reason=reason,
        original_filename=file.filename,
        declared_mime=file.content_type,
    )
    db.commit()
    db.refresh(version)
    return EvidenceVersionOut.model_validate(version)


@router.post(
    "/{evidence_id}/verify",
    response_model=VerificationOut,
    summary="Verify integrity now",
)
def verify(
    evidence_id: uuid.UUID,
    db: DbSession,
    ctx: Annotated[RequestContext, Depends(require(Permission.evidence_verify))],
    version_number: int | None = None,
) -> VerificationOut:
    evidence, result = evidence_service.verify_now(
        db, ctx, evidence_id, version_number=version_number
    )
    db.commit()
    return VerificationOut(
        evidence_id=evidence.id,
        evidence_reference=evidence.reference,
        status=result.status,
        verified=result.ok,
        expected_sha256=result.expected_sha256,
        computed_sha256=result.computed_sha256,
        ciphertext_verified=result.ciphertext_verified,
        duration_ms=result.duration_ms,
        detail=result.detail,
        checked_at=evidence.last_verified_at or utcnow(),
    )


@router.get(
    "/{evidence_id}/integrity-checks",
    response_model=list[IntegrityCheckOut],
    summary="Verification history",
)
def integrity_checks(
    evidence_id: uuid.UUID,
    db: DbSession,
    ctx: Annotated[RequestContext, Depends(require(Permission.evidence_read))],
) -> list[IntegrityCheckOut]:
    return [
        IntegrityCheckOut.model_validate(check)
        for check in evidence_service.list_integrity_checks(db, ctx, evidence_id)
    ]


@router.get("/{evidence_id}/download", summary="Download the original artifact")
def download(
    evidence_id: uuid.UUID,
    db: DbSession,
    ctx: Annotated[RequestContext, Depends(require(Permission.evidence_download))],
    reason: Annotated[str, Query(min_length=8, max_length=500)],
    version_number: int | None = None,
) -> StreamingResponse:
    """Release raw content, after verifying it and recording why it was released.

    The custody event, audit entry and verification are all committed *before* the response
    begins, so the record of the release cannot be lost if the transfer is interrupted.
    """
    evidence, version, ref = evidence_service.prepare_download(
        db, ctx, evidence_id, reason=reason, version_number=version_number
    )
    filename = _safe_filename(evidence.original_filename)
    reference = evidence.reference
    sha256 = version.sha256
    size = version.size_bytes
    db.commit()

    return StreamingResponse(
        evidence_service.stream_content(ref),
        # Never the detected type: stored artifacts are frequently hostile, and the browser must
        # not be invited to render or execute one.
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": (
                f"attachment; filename=\"{filename}\"; filename*=UTF-8''{quote(filename)}"
            ),
            "Content-Length": str(size),
            # Lets the recipient verify the artifact independently the moment it lands.
            "X-Cybertrace-SHA256": sha256,
            "X-Cybertrace-Reference": reference,
            "X-Content-Type-Options": "nosniff",
            "Cache-Control": "no-store",
        },
    )


@router.get("/{evidence_id}/preview", response_model=PreviewOut, summary="Preview an artifact")
def preview(
    evidence_id: uuid.UUID,
    db: DbSession,
    ctx: Annotated[RequestContext, Depends(require(Permission.evidence_preview))],
    max_bytes: Annotated[int, Query(ge=256, le=PREVIEW_MAX_BYTES)] = PREVIEW_MAX_BYTES,
    version_number: int | None = None,
) -> PreviewOut:
    evidence, data = evidence_service.read_preview(
        db, ctx, evidence_id, max_bytes=max_bytes, version_number=version_number
    )
    db.commit()

    try:
        content = data.decode("utf-8")
        encoding = "utf-8"
    except UnicodeDecodeError:
        # Hex rather than a lossy decode: an investigator looking at a binary artifact needs the
        # actual bytes, and replacement characters would misrepresent the content.
        content = data.hex()
        encoding = "hex"

    total = evidence.size_bytes
    return PreviewOut(
        evidence_id=evidence.id,
        evidence_reference=evidence.reference,
        mime_type=evidence.mime_type,
        encoding=encoding,
        content=content,
        bytes_returned=len(data),
        total_bytes=total,
        truncated=len(data) < total,
        integrity_status=evidence.integrity_status,
        note=(
            "Preview reads a bounded prefix and does not perform full cryptographic "
            "verification, because authentication is only possible over a complete artifact. "
            "Use the verify endpoint or download to confirm integrity."
        ),
    )


@router.get(
    "/{evidence_id}/custody",
    response_model=list[CustodyEventOut],
    summary="Chain of custody for an item",
)
def custody(
    evidence_id: uuid.UUID,
    db: DbSession,
    ctx: Annotated[RequestContext, Depends(require(Permission.custody_read))],
) -> list[CustodyEventOut]:
    return [
        CustodyEventOut.model_validate(event)
        for event in custody_service.list_for_evidence(db, ctx, evidence_id)
    ]


@router.get(
    "/{evidence_id}/custody/verify",
    response_model=ChainStatusOut,
    summary="Verify an item's custody chain",
)
def verify_custody(
    evidence_id: uuid.UUID,
    db: DbSession,
    ctx: Annotated[RequestContext, Depends(require(Permission.custody_read))],
) -> ChainStatusOut:
    chain = custody_service.verify_chain(db, ctx, evidence_id)
    return ChainStatusOut(
        evidence_id=chain.evidence_id,
        evidence_reference=chain.evidence_reference,
        event_count=chain.event_count,
        intact=chain.intact,
        trustworthy=chain.trustworthy,
        head_hash=chain.head_hash,
        head_matches_record=chain.head_matches_record,
        signatures_checked=chain.signatures_checked,
        signatures_valid=chain.signatures_valid,
        breaks=[ChainBreakOut.model_validate(issue) for issue in chain.breaks],
        summary=chain.summary,
        verified_at=chain.verified_at,
    )


@router.get("/{evidence_id}/notes", response_model=list[EvidenceNoteOut], summary="Item notes")
def list_notes(
    evidence_id: uuid.UUID,
    db: DbSession,
    ctx: Annotated[RequestContext, Depends(require(Permission.evidence_read))],
) -> list[EvidenceNoteOut]:
    return [
        EvidenceNoteOut.model_validate(note)
        for note in evidence_service.list_notes(db, ctx, evidence_id)
    ]


@router.post(
    "/{evidence_id}/notes",
    response_model=EvidenceNoteOut,
    status_code=status.HTTP_201_CREATED,
    summary="Add a note to an item",
)
def add_note(
    evidence_id: uuid.UUID,
    payload: EvidenceNoteCreate,
    db: DbSession,
    ctx: Annotated[RequestContext, Depends(require(Permission.evidence_update))],
) -> EvidenceNoteOut:
    note = evidence_service.add_note(db, ctx, evidence_id, body=payload.body)
    db.commit()
    db.refresh(note)
    return EvidenceNoteOut.model_validate(note)


@router.post("/{evidence_id}/archive", response_model=EvidenceDetailOut, summary="Archive an item")
def archive(
    evidence_id: uuid.UUID,
    payload: ArchiveRequest,
    db: DbSession,
    ctx: Annotated[RequestContext, Depends(require(Permission.evidence_archive))],
) -> EvidenceDetailOut:
    evidence = evidence_service.archive_evidence(db, ctx, evidence_id, reason=payload.reason)
    db.commit()
    db.refresh(evidence)
    return EvidenceDetailOut.model_validate(evidence)


@router.post(
    "/{evidence_id}/legal-hold",
    response_model=EvidenceDetailOut,
    summary="Apply or release a legal hold",
)
def legal_hold(
    evidence_id: uuid.UUID,
    payload: LegalHoldRequest,
    db: DbSession,
    ctx: Annotated[RequestContext, Depends(require(Permission.retention_manage))],
) -> EvidenceDetailOut:
    evidence = evidence_service.set_legal_hold(
        db, ctx, evidence_id, hold=payload.hold, reason=payload.reason
    )
    db.commit()
    db.refresh(evidence)
    return EvidenceDetailOut.model_validate(evidence)
