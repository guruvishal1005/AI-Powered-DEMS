"""Platform maintenance tasks."""

from __future__ import annotations

from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.context import RequestContext
from app.jobs.queue import DbTaskQueue
from app.jobs.registry import task
from app.models.alert import Alert
from app.models.enums import SEVERITY_WEIGHT, AlertStatus, IntegrityStatus, Severity
from app.models.evidence import Evidence, StoredObject
from app.models.ops import SystemHealthSample


@task(
    "system.health_sample",
    max_attempts=1,
    priority=200,
    description="Record a platform health snapshot for trend display.",
)
def health_sample(session: Session, ctx: RequestContext, payload: dict[str, Any]) -> dict[str, Any]:
    """Capture current platform counters.

    Written as history rather than computed on demand so the administration dashboard can
    show a trend line. A single instantaneous number cannot distinguish a queue that is
    briefly busy from one that has been backing up for hours.
    """
    stats = DbTaskQueue().stats(session)

    evidence_count = session.execute(select(func.count()).select_from(Evidence)).scalar_one()
    storage_bytes = session.execute(
        select(func.coalesce(func.sum(StoredObject.ciphertext_size), 0))
    ).scalar_one()
    integrity_failures = session.execute(
        select(func.count())
        .select_from(Evidence)
        .where(
            Evidence.integrity_status.in_(
                [
                    IntegrityStatus.hash_mismatch,
                    IntegrityStatus.decryption_failed,
                    IntegrityStatus.object_missing,
                ]
            )
        )
    ).scalar_one()

    open_alert_rows = (
        session.execute(
            select(Alert.severity).where(
                Alert.status.in_([AlertStatus.open, AlertStatus.acknowledged])
            )
        )
        .scalars()
        .all()
    )
    worst: Severity | None = None
    for severity in open_alert_rows:
        if worst is None or SEVERITY_WEIGHT[severity] > SEVERITY_WEIGHT[worst]:
            worst = severity

    sample = SystemHealthSample(
        queue_depth=stats["queue_depth"],
        jobs_running=stats["running"],
        jobs_failed_24h=stats["failed_24h"],
        evidence_count=evidence_count,
        storage_bytes=int(storage_bytes or 0),
        integrity_failures=integrity_failures,
        open_alerts=len(open_alert_rows),
        worst_alert_severity=worst,
        details={"by_status": stats["by_status"]},
    )
    session.add(sample)

    return {
        "queue_depth": sample.queue_depth,
        "evidence_count": sample.evidence_count,
        "integrity_failures": sample.integrity_failures,
        "open_alerts": sample.open_alerts,
    }
