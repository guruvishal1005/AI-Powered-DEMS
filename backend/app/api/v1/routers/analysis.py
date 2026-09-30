"""Analyzer run and technical-finding endpoints."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.context import RequestContext
from app.core.pagination import Page, PageParams, page_params, paginate
from app.db.session import get_db
from app.jobs.queue import enqueue
from app.models.analysis import AnalysisFinding, AnalysisRun
from app.models.enums import Permission
from app.schemas.analysis import AnalysisFindingOut, AnalysisRunOut
from app.schemas.common import OperationResult
from app.security.deps import require
from app.security.scoping import scope_case_ids
from app.services import case_service, evidence_service

router = APIRouter(prefix="/analysis", tags=["analysis"])

DbSession = Annotated[Session, Depends(get_db)]


@router.get("/runs", response_model=Page[AnalysisRunOut], summary="Analyzer runs")
def list_runs(
    db: DbSession,
    ctx: Annotated[RequestContext, Depends(require(Permission.analysis_read))],
    params: Annotated[PageParams, Depends(page_params)],
    case_id: uuid.UUID | None = None,
    evidence_id: uuid.UUID | None = None,
) -> Page[AnalysisRunOut]:
    stmt = scope_case_ids(select(AnalysisRun), ctx, AnalysisRun.case_id)
    if case_id:
        case_service.require_case_access(db, ctx, case_id)
        stmt = stmt.where(AnalysisRun.case_id == case_id)
    if evidence_id:
        stmt = stmt.where(AnalysisRun.evidence_id == evidence_id)
    stmt = stmt.order_by(AnalysisRun.created_at.desc())
    rows, total = paginate(db, stmt, params)
    return Page.build([AnalysisRunOut.model_validate(row) for row in rows], total, params)


@router.get("/findings", response_model=Page[AnalysisFindingOut], summary="Analyzer findings")
def list_findings(
    db: DbSession,
    ctx: Annotated[RequestContext, Depends(require(Permission.analysis_read))],
    params: Annotated[PageParams, Depends(page_params)],
    case_id: uuid.UUID | None = None,
    evidence_id: uuid.UUID | None = None,
) -> Page[AnalysisFindingOut]:
    stmt = scope_case_ids(select(AnalysisFinding), ctx, AnalysisFinding.case_id)
    if case_id:
        case_service.require_case_access(db, ctx, case_id)
        stmt = stmt.where(AnalysisFinding.case_id == case_id)
    if evidence_id:
        stmt = stmt.where(AnalysisFinding.evidence_id == evidence_id)
    stmt = stmt.order_by(AnalysisFinding.created_at.desc())
    rows, total = paginate(db, stmt, params)
    return Page.build([AnalysisFindingOut.model_validate(row) for row in rows], total, params)


@router.post(
    "/evidence/{evidence_id}/run",
    response_model=OperationResult,
    summary="Queue analysis for an item",
)
def run_analysis(
    evidence_id: uuid.UUID,
    db: DbSession,
    ctx: Annotated[RequestContext, Depends(require(Permission.analysis_run))],
) -> OperationResult:
    evidence = evidence_service.get_evidence(db, ctx, evidence_id)
    job = enqueue(
        db,
        "evidence.analyze",
        payload={"evidence_id": str(evidence.id)},
        case_id=evidence.case_id,
        evidence_id=evidence.id,
        requested_by_id=ctx.actor_id,
    )
    db.commit()
    if job is None:
        return OperationResult(message="Analysis is already queued or running for this item")
    return OperationResult(message=f"Analysis queued as job {job.id}")
