"""Human-authored findings, nested under a case."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from app.core.context import RequestContext
from app.db.session import get_db
from app.models.enums import Permission
from app.schemas.common import OperationResult
from app.schemas.finding import FindingCreate, FindingOut, FindingUpdate
from app.security.deps import require
from app.services import finding_service

router = APIRouter(prefix="/cases/{case_id}/findings", tags=["findings"])

DbSession = Annotated[Session, Depends(get_db)]


@router.get("", response_model=list[FindingOut], summary="List findings")
def list_findings(
    case_id: uuid.UUID,
    db: DbSession,
    ctx: Annotated[RequestContext, Depends(require(Permission.analysis_read))],
) -> list[FindingOut]:
    return [
        FindingOut.model_validate(row) for row in finding_service.list_findings(db, ctx, case_id)
    ]


@router.post(
    "",
    response_model=FindingOut,
    status_code=status.HTTP_201_CREATED,
    summary="Record a finding",
)
def create_finding(
    case_id: uuid.UUID,
    payload: FindingCreate,
    db: DbSession,
    ctx: Annotated[RequestContext, Depends(require(Permission.finding_create))],
) -> FindingOut:
    finding = finding_service.create_finding(
        db,
        ctx,
        case_id,
        kind=payload.kind,
        title=payload.title,
        description=payload.description,
        confidence=payload.confidence,
        severity=payload.severity,
        evidence_ids=payload.evidence_ids,
        is_included_in_report=payload.is_included_in_report,
    )
    db.commit()
    db.refresh(finding)
    return FindingOut.model_validate(finding)


@router.patch("/{finding_id}", response_model=FindingOut, summary="Update a finding")
def update_finding(
    case_id: uuid.UUID,
    finding_id: uuid.UUID,
    payload: FindingUpdate,
    db: DbSession,
    ctx: Annotated[RequestContext, Depends(require(Permission.finding_update))],
) -> FindingOut:
    finding = finding_service.update_finding(
        db, ctx, finding_id, payload.model_dump(exclude_unset=True)
    )
    db.commit()
    db.refresh(finding)
    return FindingOut.model_validate(finding)


@router.delete("/{finding_id}", response_model=OperationResult, summary="Delete a finding")
def delete_finding(
    case_id: uuid.UUID,
    finding_id: uuid.UUID,
    db: DbSession,
    ctx: Annotated[RequestContext, Depends(require(Permission.finding_delete))],
) -> OperationResult:
    finding_service.delete_finding(db, ctx, finding_id)
    db.commit()
    return OperationResult(message="Finding removed")
