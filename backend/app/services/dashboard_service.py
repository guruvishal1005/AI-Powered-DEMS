"""Command Center aggregates.

Every count is scoped the same way list endpoints are. A dashboard that showed platform-wide
totals to an investigator assigned to two cases would be a disclosure, so the queries here
go through ``apply_case_scope`` / ``scope_case_ids`` rather than counting the raw tables.
"""

from __future__ import annotations

from datetime import timedelta

from sqlalchemy import func, literal_column, select
from sqlalchemy.orm import Session, joinedload

from app.core.clock import utcnow
from app.core.context import RequestContext
from app.jobs.queue import DbTaskQueue
from app.models.alert import Alert
from app.models.case import Case
from app.models.enums import SEVERITY_WEIGHT, AlertStatus, CaseStatus, IntegrityStatus, Severity
from app.models.evidence import Evidence, StoredObject
from app.security.scoping import apply_case_scope, scope_case_ids
from app.services.alert_service import _scope_query as scope_alerts


def build(db: Session, ctx: RequestContext) -> dict:
    now = utcnow()
    since = now - timedelta(days=14)

    case_rows = db.execute(
        apply_case_scope(select(Case.status, func.count()).group_by(Case.status), ctx)
    ).all()
    cases_by_status = {status.value: 0 for status in CaseStatus}
    for status, count in case_rows:
        cases_by_status[status.value] = count
    cases_total = sum(cases_by_status.values())
    cases_open = sum(
        cases_by_status[status.value]
        for status in (
            CaseStatus.draft,
            CaseStatus.active,
            CaseStatus.pending_review,
            CaseStatus.on_hold,
        )
    )

    evidence_total = db.execute(
        scope_case_ids(select(func.count()).select_from(Evidence), ctx, Evidence.case_id)
    ).scalar_one()
    type_rows = db.execute(
        scope_case_ids(
            select(Evidence.evidence_type, func.count()).group_by(Evidence.evidence_type),
            ctx,
            Evidence.case_id,
        )
    ).all()
    evidence_by_type = [
        {"label": evidence_type.value, "count": count} for evidence_type, count in type_rows
    ]

    integrity_rows = db.execute(
        scope_case_ids(
            select(Evidence.integrity_status, func.count()).group_by(Evidence.integrity_status),
            ctx,
            Evidence.case_id,
        )
    ).all()
    by_status = {status.value: 0 for status in IntegrityStatus}
    for status, count in integrity_rows:
        by_status[status.value] = count
    failed = (
        by_status[IntegrityStatus.hash_mismatch.value]
        + by_status[IntegrityStatus.decryption_failed.value]
        + by_status[IntegrityStatus.object_missing.value]
    )

    last_failure = db.execute(
        scope_case_ids(
            select(func.max(Evidence.last_verified_at)).where(
                Evidence.integrity_status.in_(
                    [
                        IntegrityStatus.hash_mismatch,
                        IntegrityStatus.decryption_failed,
                        IntegrityStatus.object_missing,
                    ]
                )
            ),
            ctx,
            Evidence.case_id,
        )
    ).scalar()

    alert_stmt = scope_alerts(
        select(Alert.severity, func.count())
        .where(Alert.status.in_([AlertStatus.open, AlertStatus.acknowledged]))
        .group_by(Alert.severity),
        ctx,
    )
    alert_rows = db.execute(alert_stmt).all()
    open_alerts = {severity.value: 0 for severity in Severity}
    for severity, count in alert_rows:
        open_alerts[severity.value] = count
    open_alerts["total"] = sum(open_alerts[severity.value] for severity in Severity)
    worst = None
    for severity in Severity:
        if open_alerts[severity.value]:
            if worst is None or SEVERITY_WEIGHT[severity] > SEVERITY_WEIGHT[worst]:
                worst = severity

    stats = DbTaskQueue().stats(db)
    storage_bytes = db.execute(
        select(func.coalesce(func.sum(StoredObject.ciphertext_size), 0))
    ).scalar_one()

    recent_cases = list(
        db.execute(
            apply_case_scope(
                select(Case)
                .options(joinedload(Case.lead_investigator))
                .order_by(Case.last_activity_at.desc().nullslast(), Case.updated_at.desc())
                .limit(8),
                ctx,
            )
        )
        .unique()
        .scalars()
        .all()
    )
    attention = list(
        db.execute(
            apply_case_scope(
                select(Case)
                .options(joinedload(Case.lead_investigator))
                .where(Case.status.in_([CaseStatus.active, CaseStatus.pending_review]))
                .where(Case.severity.in_([Severity.high, Severity.critical]))
                .order_by(Case.last_activity_at.desc().nullslast())
                .limit(6),
                ctx,
            )
        )
        .unique()
        .scalars()
        .all()
    )
    recent_evidence = list(
        db.execute(
            scope_case_ids(
                select(Evidence)
                .options(joinedload(Evidence.uploaded_by))
                .order_by(Evidence.uploaded_at.desc())
                .limit(8),
                ctx,
                Evidence.case_id,
            )
        )
        .unique()
        .scalars()
        .all()
    )
    recent_alerts = list(
        db.execute(scope_alerts(select(Alert).order_by(Alert.last_seen_at.desc()).limit(8), ctx))
        .scalars()
        .all()
    )

    # Inline the truncation unit. Binding ``'day'`` as a parameter makes PostgreSQL treat
    # SELECT / GROUP BY / ORDER BY as three different expressions and reject the query.
    uploaded_day = func.date_trunc(literal_column("'day'"), Evidence.uploaded_at)
    activity_rows = db.execute(
        scope_case_ids(
            select(uploaded_day, func.count())
            .where(Evidence.uploaded_at >= since)
            .group_by(uploaded_day)
            .order_by(uploaded_day),
            ctx,
            Evidence.case_id,
        )
    ).all()

    return {
        "generated_at": now,
        "cases_by_status": cases_by_status,
        "cases_open": cases_open,
        "cases_total": cases_total,
        "evidence_total": evidence_total,
        "evidence_by_type": evidence_by_type,
        "integrity": {
            "by_status": by_status,
            "verified": by_status[IntegrityStatus.verified.value],
            "failed": failed,
            "pending": by_status[IntegrityStatus.pending.value],
            "last_failure_at": last_failure,
        },
        "open_alerts": open_alerts,
        "queue_depth": stats["queue_depth"],
        "jobs_failed_24h": stats["failed_24h"],
        "storage_bytes": int(storage_bytes or 0),
        "recent_cases": recent_cases,
        "attention_cases": attention,
        "recent_evidence": recent_evidence,
        "recent_alerts": recent_alerts,
        "activity": [{"bucket_start": start, "count": count} for start, count in activity_rows],
        "worst_alert_severity": worst,
    }
