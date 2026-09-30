"""Audit log explorer and global search."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.core.context import RequestContext
from app.core.pagination import Page, PageParams, page_params
from app.db.session import get_db
from app.models.enums import Permission
from app.schemas.audit import AuditChainStatusOut, AuditEntryOut, SearchResultsOut
from app.security.deps import require
from app.services import audit_service

router = APIRouter(tags=["audit"])

DbSession = Annotated[Session, Depends(get_db)]


@router.get("/audit", response_model=Page[AuditEntryOut], summary="Query the audit log")
def list_audit(
    db: DbSession,
    ctx: Annotated[RequestContext, Depends(require(Permission.audit_read))],
    params: Annotated[PageParams, Depends(page_params)],
    action: Annotated[str | None, Query(max_length=64)] = None,
    actor_id: uuid.UUID | None = None,
    resource_type: Annotated[str | None, Query(max_length=48)] = None,
    case_id: uuid.UUID | None = None,
    result: Annotated[str | None, Query(max_length=16)] = None,
    recorded_after: datetime | None = None,
    recorded_before: datetime | None = None,
    search: Annotated[str | None, Query(max_length=200)] = None,
) -> Page[AuditEntryOut]:
    rows, total = audit_service.list_entries(
        db,
        ctx,
        params,
        action=action,
        actor_id=actor_id,
        resource_type=resource_type,
        case_id=case_id,
        result=result,
        recorded_after=recorded_after,
        recorded_before=recorded_before,
        search=search,
    )
    return Page.build([AuditEntryOut.model_validate(row) for row in rows], total, params)


@router.get("/audit/verify", response_model=AuditChainStatusOut, summary="Verify the audit chain")
def verify_audit(
    db: DbSession,
    ctx: Annotated[RequestContext, Depends(require(Permission.audit_read))],
    start_sequence: int | None = None,
    limit: Annotated[int, Query(ge=10, le=20000)] = 2000,
) -> AuditChainStatusOut:
    return AuditChainStatusOut.model_validate(
        audit_service.verify_window(db, start_sequence=start_sequence, limit=limit)
    )


@router.get("/search", response_model=SearchResultsOut, summary="Global search")
def search(
    db: DbSession,
    ctx: Annotated[RequestContext, Depends(require(Permission.case_read))],
    q: Annotated[str, Query(min_length=2, max_length=200)],
) -> SearchResultsOut:
    return SearchResultsOut.model_validate(audit_service.search(db, ctx, q))
