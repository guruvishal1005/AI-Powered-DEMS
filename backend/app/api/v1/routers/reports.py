"""Forensic report endpoints."""

from __future__ import annotations

import uuid
from typing import Annotated
from urllib.parse import quote

from fastapi import APIRouter, Depends, Query, status
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app.core.context import RequestContext
from app.core.pagination import Page, PageParams, page_params
from app.db.session import get_db
from app.models.enums import Permission, ReportFormat, ReportStatus
from app.schemas.report import (
    ReportCreate,
    ReportDetailOut,
    ReportReviewRequest,
    ReportSubmitRequest,
    ReportSummaryOut,
    ReportUpdate,
    ReportVerifyOut,
)
from app.security.deps import require
from app.services import report_service

router = APIRouter(prefix="/reports", tags=["reports"])

DbSession = Annotated[Session, Depends(get_db)]

_MEDIA = {
    ReportFormat.pdf: "application/pdf",
    ReportFormat.html: "text/html; charset=utf-8",
    ReportFormat.json: "application/json",
    ReportFormat.csv: "text/csv; charset=utf-8",
}


@router.get("", response_model=Page[ReportSummaryOut], summary="List reports")
def list_reports(
    db: DbSession,
    ctx: Annotated[RequestContext, Depends(require(Permission.report_read))],
    params: Annotated[PageParams, Depends(page_params)],
    case_id: uuid.UUID | None = None,
    status_filter: Annotated[list[ReportStatus] | None, Query(alias="status")] = None,
) -> Page[ReportSummaryOut]:
    rows, total = report_service.list_reports(
        db, ctx, params, case_id=case_id, status=status_filter
    )
    return Page.build([ReportSummaryOut.model_validate(row) for row in rows], total, params)


@router.post(
    "",
    response_model=ReportDetailOut,
    status_code=status.HTTP_201_CREATED,
    summary="Capture a report snapshot",
)
def create_report(
    payload: ReportCreate,
    db: DbSession,
    ctx: Annotated[RequestContext, Depends(require(Permission.report_generate))],
    case_id: uuid.UUID = Query(...),
) -> ReportDetailOut:
    report = report_service.create_report(
        db,
        ctx,
        case_id,
        title=payload.title,
        classification=payload.classification,
        executive_summary=payload.executive_summary,
        conclusion=payload.conclusion,
        distribution_list=payload.distribution_list,
        spec=payload.spec.model_dump(),
    )
    db.commit()
    db.refresh(report)
    return ReportDetailOut.model_validate(report)


@router.get("/{report_id}", response_model=ReportDetailOut, summary="Report detail")
def get_report(
    report_id: uuid.UUID,
    db: DbSession,
    ctx: Annotated[RequestContext, Depends(require(Permission.report_read))],
) -> ReportDetailOut:
    return ReportDetailOut.model_validate(report_service.get_report(db, ctx, report_id))


@router.patch("/{report_id}", response_model=ReportDetailOut, summary="Update a draft")
def update_report(
    report_id: uuid.UUID,
    payload: ReportUpdate,
    db: DbSession,
    ctx: Annotated[RequestContext, Depends(require(Permission.report_generate))],
) -> ReportDetailOut:
    report = report_service.update_report(
        db, ctx, report_id, payload.model_dump(exclude_unset=True)
    )
    db.commit()
    db.refresh(report)
    return ReportDetailOut.model_validate(report)


@router.post("/{report_id}/recapture", response_model=ReportDetailOut, summary="Refresh snapshot")
def recapture(
    report_id: uuid.UUID,
    db: DbSession,
    ctx: Annotated[RequestContext, Depends(require(Permission.report_generate))],
) -> ReportDetailOut:
    report = report_service.recapture(db, ctx, report_id)
    db.commit()
    db.refresh(report)
    return ReportDetailOut.model_validate(report)


@router.post("/{report_id}/submit", response_model=ReportDetailOut, summary="Submit for review")
def submit(
    report_id: uuid.UUID,
    payload: ReportSubmitRequest,
    db: DbSession,
    ctx: Annotated[RequestContext, Depends(require(Permission.report_generate))],
) -> ReportDetailOut:
    report = report_service.submit(db, ctx, report_id, note=payload.note)
    db.commit()
    db.refresh(report)
    return ReportDetailOut.model_validate(report)


@router.post("/{report_id}/reject", response_model=ReportDetailOut, summary="Reject a report")
def reject(
    report_id: uuid.UUID,
    payload: ReportReviewRequest,
    db: DbSession,
    ctx: Annotated[RequestContext, Depends(require(Permission.report_sign))],
) -> ReportDetailOut:
    report = report_service.reject(db, ctx, report_id, note=payload.note)
    db.commit()
    db.refresh(report)
    return ReportDetailOut.model_validate(report)


@router.post("/{report_id}/sign", response_model=ReportDetailOut, summary="Approve and sign")
def sign(
    report_id: uuid.UUID,
    payload: ReportReviewRequest,
    db: DbSession,
    ctx: Annotated[RequestContext, Depends(require(Permission.report_sign))],
) -> ReportDetailOut:
    report = report_service.sign(db, ctx, report_id, note=payload.note)
    db.commit()
    db.refresh(report)
    return ReportDetailOut.model_validate(report)


@router.post("/{report_id}/render", response_model=ReportDetailOut, summary="Render an artifact")
def render(
    report_id: uuid.UUID,
    db: DbSession,
    ctx: Annotated[RequestContext, Depends(require(Permission.report_generate))],
    fmt: ReportFormat = ReportFormat.pdf,
) -> ReportDetailOut:
    report_service.render_artifact(db, ctx, report_id, fmt)
    db.commit()
    report = report_service.get_report(db, ctx, report_id)
    return ReportDetailOut.model_validate(report)


@router.get("/{report_id}/download", summary="Download a rendered artifact")
def download(
    report_id: uuid.UUID,
    db: DbSession,
    ctx: Annotated[RequestContext, Depends(require(Permission.report_read))],
    fmt: ReportFormat = ReportFormat.pdf,
) -> StreamingResponse:
    report, artifact, chunks = report_service.open_artifact(db, ctx, report_id, fmt)
    db.commit()
    filename = artifact.filename
    return StreamingResponse(
        chunks,
        media_type=_MEDIA[fmt],
        headers={
            "Content-Disposition": (
                f"attachment; filename=\"{filename}\"; filename*=UTF-8''{quote(filename)}"
            ),
            "X-Cybertrace-SHA256": artifact.sha256,
            "X-Cybertrace-Reference": report.reference,
            "Cache-Control": "no-store",
        },
    )


@router.get("/{report_id}/verify", response_model=ReportVerifyOut, summary="Verify signature")
def verify(
    report_id: uuid.UUID,
    db: DbSession,
    ctx: Annotated[RequestContext, Depends(require(Permission.report_read))],
) -> ReportVerifyOut:
    return ReportVerifyOut.model_validate(report_service.verify(db, ctx, report_id))
