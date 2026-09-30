"""Command Center dashboard."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.context import RequestContext
from app.db.session import get_db
from app.models.enums import Permission
from app.schemas.dashboard import DashboardOut
from app.security.deps import require
from app.services import dashboard_service

router = APIRouter(tags=["dashboard"])

DbSession = Annotated[Session, Depends(get_db)]


@router.get("/dashboard", response_model=DashboardOut, summary="Command Center aggregates")
def dashboard(
    db: DbSession,
    ctx: Annotated[RequestContext, Depends(require(Permission.case_read))],
) -> DashboardOut:
    data = dashboard_service.build(db, ctx)
    return DashboardOut.model_validate(data)
