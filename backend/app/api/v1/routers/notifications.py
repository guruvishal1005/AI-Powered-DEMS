"""In-app notifications."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.context import RequestContext
from app.db.session import get_db
from app.models.enums import Permission
from app.schemas.alert import NotificationOut
from app.security.deps import require
from app.services import alert_service

router = APIRouter(prefix="/notifications", tags=["notifications"])

DbSession = Annotated[Session, Depends(get_db)]


@router.get("", response_model=list[NotificationOut], summary="Current user's notifications")
def list_notifications(
    db: DbSession,
    ctx: Annotated[RequestContext, Depends(require(Permission.alert_read))],
) -> list[NotificationOut]:
    return [
        NotificationOut.model_validate(row) for row in alert_service.list_notifications(db, ctx)
    ]


@router.post("/{notification_id}/read", response_model=NotificationOut, summary="Mark read")
def read_notification(
    notification_id: uuid.UUID,
    db: DbSession,
    ctx: Annotated[RequestContext, Depends(require(Permission.alert_read))],
) -> NotificationOut:
    row = alert_service.mark_notification_read(db, ctx, notification_id)
    db.commit()
    return NotificationOut.model_validate(row)
