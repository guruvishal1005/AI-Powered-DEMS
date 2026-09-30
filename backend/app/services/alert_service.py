"""Alert creation and triage.

Deduplication is the feature that decides whether an alert list is usable. A nightly
integrity sweep that keeps failing must not produce a new alert every night, because a queue
of three hundred identical alerts is functionally the same as no alerts at all. Instead
:func:`raise_alert` collapses recurrences onto the existing *open* alert, raising its
``occurrence_count`` and ``last_seen_at``, and escalating its severity if the recurrence is
worse than the original.

Once an alert is resolved, a later recurrence legitimately opens a fresh one: the condition
was believed fixed, and its return is new information.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import Select, func, or_, select
from sqlalchemy.orm import Session, joinedload

from app.audit.writer import append_audit
from app.core.clock import utcnow
from app.core.context import RequestContext
from app.core.errors import Conflict, NotFound
from app.core.logging import get_logger
from app.core.pagination import PageParams, paginate
from app.models.alert import Alert, AlertEvent, Notification
from app.models.case import Case, CaseAssignment
from app.models.enums import (
    SEVERITY_WEIGHT,
    AlertSource,
    AlertStatus,
    AlertType,
    AuditResult,
    Severity,
)
from app.models.user import User
from app.security.scoping import accessible_case_ids, has_global_case_access
from app.services.reference_service import next_alert_reference

logger = get_logger(__name__)


def raise_alert(
    session: Session,
    ctx: RequestContext,
    *,
    alert_type: AlertType,
    source: AlertSource,
    severity: Severity,
    title: str,
    description: str,
    dedupe_key: str,
    case_id: uuid.UUID | None = None,
    evidence_id: uuid.UUID | None = None,
    subject_user_id: uuid.UUID | None = None,
    anomaly_id: uuid.UUID | None = None,
    details: dict[str, Any] | None = None,
    recommended_action: str | None = None,
    notify_case_team: bool = True,
) -> Alert:
    """Create an alert, or fold this occurrence into the existing open one."""
    now = utcnow()
    existing = session.execute(
        select(Alert).where(Alert.dedupe_key == dedupe_key).where(Alert.status == AlertStatus.open)
    ).scalar_one_or_none()

    if existing is not None:
        existing.occurrence_count += 1
        existing.last_seen_at = now
        if SEVERITY_WEIGHT[severity] > SEVERITY_WEIGHT[existing.severity]:
            existing.severity = severity
            existing.description = description
        if details:
            existing.details = {**existing.details, **details}
        session.flush()
        return existing

    alert = Alert(
        reference=next_alert_reference(session),
        type=alert_type,
        source=source,
        severity=severity,
        status=AlertStatus.open,
        title=title[:240],
        description=description,
        recommended_action=recommended_action,
        dedupe_key=dedupe_key[:160],
        occurrence_count=1,
        first_seen_at=now,
        last_seen_at=now,
        case_id=case_id,
        evidence_id=evidence_id,
        subject_user_id=subject_user_id,
        anomaly_id=anomaly_id,
        details=details or {},
    )
    session.add(alert)
    session.flush()

    session.add(
        AlertEvent(
            alert_id=alert.id,
            action="created",
            actor_id=ctx.actor_id,
            actor_label=ctx.actor_label,
            to_status=AlertStatus.open,
            note=f"raised by {source.value}",
        )
    )

    if notify_case_team and case_id is not None:
        _notify_case_team(session, alert, case_id)

    logger.info(
        "alert_raised",
        alert=alert.reference,
        type=alert_type.value,
        severity=severity.value,
        dedupe_key=dedupe_key,
    )
    session.flush()
    return alert


def _notify_case_team(session: Session, alert: Alert, case_id: uuid.UUID) -> None:
    """Notify the people responsible for the case, not everyone.

    Broadcasting security alerts to every account would train users to ignore them, so
    delivery is limited to the lead investigator and current assignees.
    """
    case = session.get(Case, case_id)
    if case is None:
        return

    recipients: set[uuid.UUID] = set()
    if case.lead_investigator_id:
        recipients.add(case.lead_investigator_id)
    assignee_ids = session.execute(
        select(CaseAssignment.user_id)
        .where(CaseAssignment.case_id == case_id)
        .where(CaseAssignment.unassigned_at.is_(None))
    ).scalars()
    recipients.update(assignee_ids)

    link = f"/cases/{case.reference}/alerts"
    for user_id in recipients:
        session.add(
            Notification(
                user_id=user_id,
                kind="alert",
                title=alert.title,
                body=alert.description[:500],
                severity=alert.severity,
                link=link,
                alert_id=alert.id,
            )
        )


def _transition(
    session: Session,
    ctx: RequestContext,
    alert: Alert,
    *,
    action: str,
    to_status: AlertStatus,
    note: str | None,
) -> Alert:
    from_status = alert.status
    now = utcnow()

    alert.status = to_status
    if to_status is AlertStatus.acknowledged:
        alert.acknowledged_at = now
        alert.acknowledged_by_id = ctx.actor_id
    elif to_status in (AlertStatus.resolved, AlertStatus.suppressed):
        alert.resolved_at = now
        alert.resolved_by_id = ctx.actor_id
        alert.resolution_note = note

    session.add(
        AlertEvent(
            alert_id=alert.id,
            action=action,
            actor_id=ctx.actor_id,
            actor_label=ctx.actor_label,
            from_status=from_status,
            to_status=to_status,
            note=note,
        )
    )
    append_audit(
        session,
        ctx,
        action=f"alert.{action}",
        resource_type="alert",
        resource_id=alert.id,
        resource_label=alert.reference,
        case_id=alert.case_id,
        before_state={"status": from_status.value},
        after_state={"status": to_status.value},
        reason=note,
        result=AuditResult.success,
    )
    session.commit()
    return alert


def _scope_query[T: Select[Any]](stmt: T, ctx: RequestContext) -> T:
    """Alerts without a case (platform security) are visible to anyone who can read alerts.

    Case-scoped alerts follow the same object-level rule as everything else: if you cannot
    see the case, you cannot see the alert it raised.
    """
    if has_global_case_access(ctx):
        return stmt
    return stmt.where(or_(Alert.case_id.is_(None), Alert.case_id.in_(accessible_case_ids(ctx))))


def list_alerts(
    session: Session,
    ctx: RequestContext,
    params: PageParams,
    *,
    status: list[AlertStatus] | None = None,
    severity: list[Severity] | None = None,
    alert_type: list[AlertType] | None = None,
    case_id: uuid.UUID | None = None,
    assigned_to_id: uuid.UUID | None = None,
) -> tuple[list[Alert], int]:
    stmt = _scope_query(
        select(Alert).options(joinedload(Alert.assigned_to), joinedload(Alert.case)),
        ctx,
    )
    if status:
        stmt = stmt.where(Alert.status.in_(status))
    if severity:
        stmt = stmt.where(Alert.severity.in_(severity))
    if alert_type:
        stmt = stmt.where(Alert.type.in_(alert_type))
    if case_id:
        stmt = stmt.where(Alert.case_id == case_id)
    if assigned_to_id:
        stmt = stmt.where(Alert.assigned_to_id == assigned_to_id)
    stmt = stmt.order_by(Alert.last_seen_at.desc())
    return paginate(session, stmt, params)


def get_alert(session: Session, ctx: RequestContext, alert_id: uuid.UUID) -> Alert:
    alert = (
        session.execute(
            _scope_query(
                select(Alert).options(
                    joinedload(Alert.assigned_to),
                    joinedload(Alert.case),
                    joinedload(Alert.evidence),
                    joinedload(Alert.events),
                ),
                ctx,
            ).where(Alert.id == alert_id)
        )
        .unique()
        .scalar_one_or_none()
    )
    if alert is None:
        raise NotFound("Alert", str(alert_id))
    return alert


def list_notifications(session: Session, ctx: RequestContext) -> list[Notification]:
    if ctx.actor_id is None:
        return []
    return list(
        session.execute(
            select(Notification)
            .where(Notification.user_id == ctx.actor_id)
            .where(Notification.is_dismissed.is_(False))
            .order_by(Notification.created_at.desc())
            .limit(50)
        )
        .scalars()
        .all()
    )


def mark_notification_read(
    session: Session, ctx: RequestContext, notification_id: uuid.UUID
) -> Notification:
    row = session.get(Notification, notification_id)
    if row is None or row.user_id != ctx.actor_id:
        raise NotFound("Notification", str(notification_id))
    row.read_at = utcnow()
    return row


def acknowledge(
    session: Session, ctx: RequestContext, alert_id: uuid.UUID, *, note: str | None = None
) -> Alert:
    alert = get_alert(session, ctx, alert_id)
    if alert.status is not AlertStatus.open:
        raise Conflict(f"Only open alerts can be acknowledged; this one is {alert.status.value}")
    if alert.assigned_to_id is None:
        alert.assigned_to_id = ctx.actor_id
    return _transition(
        session, ctx, alert, action="acknowledged", to_status=AlertStatus.acknowledged, note=note
    )


def resolve(session: Session, ctx: RequestContext, alert_id: uuid.UUID, *, note: str) -> Alert:
    alert = get_alert(session, ctx, alert_id)
    if alert.status in (AlertStatus.resolved, AlertStatus.suppressed):
        raise Conflict("This alert is already closed")
    return _transition(
        session, ctx, alert, action="resolved", to_status=AlertStatus.resolved, note=note
    )


def suppress(session: Session, ctx: RequestContext, alert_id: uuid.UUID, *, note: str) -> Alert:
    """Close an alert as a known, accepted condition.

    Kept distinct from ``resolved`` because "we fixed it" and "we have decided this is
    expected" are different statements, and conflating them loses the reason a condition
    stopped being reported.
    """
    alert = get_alert(session, ctx, alert_id)
    if alert.status in (AlertStatus.resolved, AlertStatus.suppressed):
        raise Conflict("This alert is already closed")
    return _transition(
        session, ctx, alert, action="suppressed", to_status=AlertStatus.suppressed, note=note
    )


def assign(
    session: Session, ctx: RequestContext, alert_id: uuid.UUID, *, assignee_id: uuid.UUID
) -> Alert:
    alert = get_alert(session, ctx, alert_id)
    assignee = session.get(User, assignee_id)
    if assignee is None:
        raise NotFound("User", str(assignee_id))
    alert.assigned_to_id = assignee_id
    session.add(
        AlertEvent(
            alert_id=alert.id,
            action="assigned",
            actor_id=ctx.actor_id,
            actor_label=ctx.actor_label,
            note=f"assigned to {assignee.full_name}",
        )
    )
    append_audit(
        session,
        ctx,
        action="alert.assigned",
        resource_type="alert",
        resource_id=alert.id,
        resource_label=alert.reference,
        after_state={"assigned_to": assignee.email},
        result=AuditResult.success,
    )
    session.commit()
    return alert


def open_alert_counts(session: Session) -> dict[str, int]:
    """Open alert totals by severity, for the dashboard and the header indicator."""
    rows = session.execute(
        select(Alert.severity, func.count())
        .where(Alert.status.in_([AlertStatus.open, AlertStatus.acknowledged]))
        .group_by(Alert.severity)
    ).all()
    counts = {severity.value: 0 for severity in Severity}
    for severity, count in rows:
        counts[severity.value] = count
    counts["total"] = sum(counts[severity.value] for severity in Severity)
    return counts
