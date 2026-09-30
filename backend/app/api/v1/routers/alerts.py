"""Alert triage and in-app notifications."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.core.context import RequestContext
from app.core.pagination import Page, PageParams, page_params
from app.db.session import get_db
from app.models.enums import AlertStatus, AlertType, Permission, Severity
from app.schemas.alert import (
    AlertAssignRequest,
    AlertDetailOut,
    AlertNoteRequest,
    AlertResolveRequest,
    AlertSummaryOut,
)
from app.security.deps import require
from app.services import alert_service

router = APIRouter(prefix="/alerts", tags=["alerts"])

DbSession = Annotated[Session, Depends(get_db)]


@router.get("", response_model=Page[AlertSummaryOut], summary="List alerts")
def list_alerts(
    db: DbSession,
    ctx: Annotated[RequestContext, Depends(require(Permission.alert_read))],
    params: Annotated[PageParams, Depends(page_params)],
    status_filter: Annotated[list[AlertStatus] | None, Query(alias="status")] = None,
    severity: Annotated[list[Severity] | None, Query()] = None,
    alert_type: Annotated[list[AlertType] | None, Query(alias="type")] = None,
    case_id: uuid.UUID | None = None,
    assigned_to_id: uuid.UUID | None = None,
) -> Page[AlertSummaryOut]:
    rows, total = alert_service.list_alerts(
        db,
        ctx,
        params,
        status=status_filter,
        severity=severity,
        alert_type=alert_type,
        case_id=case_id,
        assigned_to_id=assigned_to_id,
    )
    return Page.build([AlertSummaryOut.model_validate(row) for row in rows], total, params)


@router.get("/counts", summary="Open alert totals by severity")
def counts(
    db: DbSession,
    ctx: Annotated[RequestContext, Depends(require(Permission.alert_read))],
) -> dict[str, int]:
    return alert_service.open_alert_counts(db)


@router.get("/{alert_id}", response_model=AlertDetailOut, summary="Alert detail")
def get_alert(
    alert_id: uuid.UUID,
    db: DbSession,
    ctx: Annotated[RequestContext, Depends(require(Permission.alert_read))],
) -> AlertDetailOut:
    return AlertDetailOut.model_validate(alert_service.get_alert(db, ctx, alert_id))


@router.post("/{alert_id}/acknowledge", response_model=AlertDetailOut, summary="Acknowledge")
def acknowledge(
    alert_id: uuid.UUID,
    payload: AlertNoteRequest,
    db: DbSession,
    ctx: Annotated[RequestContext, Depends(require(Permission.alert_manage))],
) -> AlertDetailOut:
    return AlertDetailOut.model_validate(
        alert_service.acknowledge(db, ctx, alert_id, note=payload.note)
    )


@router.post("/{alert_id}/resolve", response_model=AlertDetailOut, summary="Resolve")
def resolve(
    alert_id: uuid.UUID,
    payload: AlertResolveRequest,
    db: DbSession,
    ctx: Annotated[RequestContext, Depends(require(Permission.alert_manage))],
) -> AlertDetailOut:
    return AlertDetailOut.model_validate(
        alert_service.resolve(db, ctx, alert_id, note=payload.note)
    )


@router.post("/{alert_id}/suppress", response_model=AlertDetailOut, summary="Suppress")
def suppress(
    alert_id: uuid.UUID,
    payload: AlertResolveRequest,
    db: DbSession,
    ctx: Annotated[RequestContext, Depends(require(Permission.alert_manage))],
) -> AlertDetailOut:
    return AlertDetailOut.model_validate(
        alert_service.suppress(db, ctx, alert_id, note=payload.note)
    )


@router.post("/{alert_id}/assign", response_model=AlertDetailOut, summary="Assign")
def assign(
    alert_id: uuid.UUID,
    payload: AlertAssignRequest,
    db: DbSession,
    ctx: Annotated[RequestContext, Depends(require(Permission.alert_manage))],
) -> AlertDetailOut:
    return AlertDetailOut.model_validate(
        alert_service.assign(db, ctx, alert_id, assignee_id=payload.assignee_id)
    )
