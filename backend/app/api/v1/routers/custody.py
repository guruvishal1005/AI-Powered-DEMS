"""Chain-of-custody endpoints.

Read-only by design. Custody events are written only as a side effect of the actions they
describe, so there is no endpoint that creates one directly - an API that let a client post an
arbitrary custody event would make the entire chain worthless.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.core.context import RequestContext
from app.core.pagination import Page, PageParams, page_params
from app.db.session import get_db
from app.models.enums import CustodyAction, Permission
from app.schemas.evidence import CustodyEventOut
from app.security.deps import require
from app.services import custody_service

router = APIRouter(prefix="/custody", tags=["custody"])

DbSession = Annotated[Session, Depends(get_db)]


@router.get("/events", response_model=Page[CustodyEventOut], summary="Custody activity")
def list_events(
    db: DbSession,
    ctx: Annotated[RequestContext, Depends(require(Permission.custody_read))],
    params: Annotated[PageParams, Depends(page_params)],
    case_id: uuid.UUID | None = None,
    evidence_id: uuid.UUID | None = None,
    actions: Annotated[list[CustodyAction] | None, Query()] = None,
    actor_id: uuid.UUID | None = None,
    occurred_after: datetime | None = None,
    occurred_before: datetime | None = None,
    search: Annotated[str | None, Query(max_length=200)] = None,
) -> Page[CustodyEventOut]:
    events, total = custody_service.list_for_case(
        db,
        ctx,
        params,
        case_id=case_id,
        evidence_id=evidence_id,
        actions=actions,
        actor_id=actor_id,
        occurred_after=occurred_after,
        occurred_before=occurred_before,
        search=search,
    )
    return Page.build([CustodyEventOut.model_validate(event) for event in events], total, params)


@router.get("/action-counts", summary="Custody event totals by action")
def action_counts(
    db: DbSession,
    ctx: Annotated[RequestContext, Depends(require(Permission.custody_read))],
    case_id: uuid.UUID | None = None,
) -> dict[str, int]:
    return custody_service.action_counts(db, ctx, case_id=case_id)
