"""Timeline and extracted-observation endpoints."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.core.context import RequestContext
from app.core.pagination import Page, PageParams, page_params
from app.db.session import get_db
from app.models.enums import ObservationKind, Permission
from app.schemas.timeline import ObservationOut, TimelineOut
from app.security.deps import require
from app.services import timeline_service

router = APIRouter(tags=["timeline"])

DbSession = Annotated[Session, Depends(get_db)]


@router.get("/timeline", response_model=TimelineOut, summary="Reconstructed timeline")
def get_timeline(
    db: DbSession,
    ctx: Annotated[RequestContext, Depends(require(Permission.analysis_read))],
    case_id: uuid.UUID | None = None,
    evidence_id: uuid.UUID | None = None,
    window_start: datetime | None = None,
    window_end: datetime | None = None,
    sources: Annotated[list[str] | None, Query()] = None,
    kinds: Annotated[list[str] | None, Query()] = None,
    resolution: Literal["raw", "minute", "hour", "day"] | None = None,
    limit: Annotated[int, Query(ge=50, le=5000)] = 1500,
) -> TimelineOut:
    return TimelineOut.model_validate(
        timeline_service.assemble(
            db,
            ctx,
            case_id=case_id,
            evidence_id=evidence_id,
            window_start=window_start,
            window_end=window_end,
            sources=sources,
            kinds=kinds,
            resolution=resolution,
            limit=limit,
        )
    )


@router.get("/observations", response_model=Page[ObservationOut], summary="Extracted observations")
def list_observations(
    db: DbSession,
    ctx: Annotated[RequestContext, Depends(require(Permission.analysis_read))],
    params: Annotated[PageParams, Depends(page_params)],
    case_id: uuid.UUID | None = None,
    evidence_id: uuid.UUID | None = None,
    kind: Annotated[list[ObservationKind] | None, Query()] = None,
) -> Page[ObservationOut]:
    rows, total = timeline_service.list_observations(
        db, ctx, params, case_id=case_id, evidence_id=evidence_id, kinds=kind
    )
    return Page.build([ObservationOut.model_validate(row) for row in rows], total, params)
