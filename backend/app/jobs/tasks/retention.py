"""Retention scanning.

Disposition never deletes silently. Items approaching expiry raise an alert; items past
expiry are flagged for review unless a legal hold is in force. Destruction, when it
eventually happens, is a separate explicit action that writes a custody event.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.clock import utcnow
from app.core.context import RequestContext
from app.jobs.registry import task
from app.models.enums import AlertSource, AlertType, Severity
from app.models.evidence import Evidence
from app.models.ops import LegalHold
from app.services import alert_service


@task(
    "retention.scan",
    max_attempts=1,
    priority=160,
    description="Flag material approaching its retention limit and honour legal holds.",
)
def scan_retention(
    session: Session, ctx: RequestContext, payload: dict[str, Any]
) -> dict[str, Any]:
    now = utcnow()
    warn_before = now + timedelta(days=int(payload.get("warn_days", 30)))
    items = list(
        session.execute(
            select(Evidence)
            .where(Evidence.retention_expires_at.is_not(None))
            .where(Evidence.retention_expires_at <= warn_before)
        )
        .scalars()
        .all()
    )
    held = {
        row.evidence_id
        for row in session.execute(
            select(LegalHold)
            .where(LegalHold.released_at.is_(None))
            .where(LegalHold.evidence_id.is_not(None))
        ).scalars()
        if row.evidence_id is not None
    }
    warned = 0
    skipped_hold = 0
    for item in items:
        if item.id in held or item.legal_hold:
            skipped_hold += 1
            continue
        expired = item.retention_expires_at is not None and item.retention_expires_at <= now
        alert_service.raise_alert(
            session,
            ctx,
            alert_type=AlertType.retention_expiry_approaching,
            source=AlertSource.retention_engine,
            severity=Severity.high if expired else Severity.medium,
            title=(
                f"Retention expired for {item.reference}"
                if expired
                else f"Retention expiry approaching for {item.reference}"
            ),
            description=(
                f"{item.reference} reaches the end of its retention period at "
                f"{item.retention_expires_at.isoformat() if item.retention_expires_at else 'unknown'}."
                " No legal hold is in force. Review before any disposition."
            ),
            dedupe_key=f"retention:{item.id}",
            case_id=item.case_id,
            evidence_id=item.id,
            recommended_action=(
                "Review the item, apply a legal hold, or record a disposition decision."
            ),
        )
        warned += 1
    return {"scanned": len(items), "warned": warned, "held": skipped_hold}
