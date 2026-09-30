"""Recurring work.

Schedules live in the ``periodic_tasks`` table rather than in cron so they are visible and
adjustable in the administration interface, and so ``next_run_at`` survives a restart instead
of every schedule firing at once on boot.

:func:`register_default_schedule` only creates entries for tasks that are actually registered.
That keeps the schedule honest as the platform grows: a schedule entry always corresponds to
something the worker can really run, rather than to a name that will fail on first execution.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.clock import utcnow
from app.core.logging import get_logger
from app.jobs.queue import DbTaskQueue
from app.jobs.registry import is_registered, load_tasks
from app.models.ops import PeriodicTask

logger = get_logger(__name__)

MINUTE = 60
HOUR = 60 * MINUTE


@dataclass(frozen=True, slots=True)
class ScheduleEntry:
    name: str
    task: str
    interval_seconds: int
    description: str
    # Spread first runs out so a fresh deployment does not fire everything simultaneously.
    initial_delay_seconds: int = 30


DEFAULT_SCHEDULE: tuple[ScheduleEntry, ...] = (
    ScheduleEntry(
        name="Platform health sample",
        task="system.health_sample",
        interval_seconds=5 * MINUTE,
        description="Record queue depth, storage usage and integrity counters for trend display.",
        initial_delay_seconds=15,
    ),
    ScheduleEntry(
        name="Evidence integrity sweep",
        task="integrity.sweep",
        interval_seconds=6 * HOUR,
        description=(
            "Re-verify stored evidence against its acquisition fingerprint, oldest checked first."
        ),
        initial_delay_seconds=2 * MINUTE,
    ),
    ScheduleEntry(
        name="Correlation refresh",
        task="intelligence.rebuild_correlations",
        interval_seconds=6 * HOUR,
        description=(
            "Recompute correlation edges corpus-wide. Rarity weights depend on the whole corpus, "
            "so every ingestion slightly ages the scores computed before it."
        ),
        initial_delay_seconds=90,
    ),
    ScheduleEntry(
        name="Case intelligence refresh",
        task="intelligence.refresh_active_cases",
        interval_seconds=HOUR,
        description=(
            "Regenerate anomalies, intelligence matches, insights and risk scores for open cases. "
            "Catches the older side of a new cross-case link, which gets no ingestion event of "
            "its own."
        ),
        initial_delay_seconds=2 * MINUTE,
    ),
    ScheduleEntry(
        name="Uncorrelated evidence sweep",
        task="intelligence.correlate_pending",
        interval_seconds=30 * MINUTE,
        description=(
            "Queue correlation for analysed items that never got it, covering handoffs lost "
            "between the analysis and correlation jobs."
        ),
        initial_delay_seconds=3 * MINUTE,
    ),
    ScheduleEntry(
        name="Retention review",
        task="retention.scan",
        interval_seconds=24 * HOUR,
        description="Flag material approaching its retention limit and honour legal holds.",
        initial_delay_seconds=5 * MINUTE,
    ),
    ScheduleEntry(
        name="Audit chain verification",
        task="integrity.verify_chains",
        interval_seconds=24 * HOUR,
        description="Replay the audit and custody hash chains and alert on any break.",
        initial_delay_seconds=4 * MINUTE,
    ),
    ScheduleEntry(
        name="Nightly backup",
        task="backup.run",
        interval_seconds=24 * HOUR,
        description="Capture an encrypted backup and verify it can be read back.",
        initial_delay_seconds=10 * MINUTE,
    ),
    ScheduleEntry(
        name="Unanalysed evidence sweep",
        task="evidence.analyze_pending",
        interval_seconds=15 * MINUTE,
        description=(
            "Queue analysis for items that have never been analysed, covering jobs lost to a "
            "restart between ingestion and queueing."
        ),
        initial_delay_seconds=MINUTE,
    ),
    ScheduleEntry(
        name="Failed analysis retry",
        task="evidence.retry_failed_analysis",
        interval_seconds=6 * HOUR,
        description=(
            "Re-queue items with failed analyzer runs, since many failures are environmental "
            "and clear on a second attempt."
        ),
        initial_delay_seconds=8 * MINUTE,
    ),
)


def register_default_schedule(session: Session) -> int:
    """Create any missing schedule entries. Existing entries are never overwritten."""
    load_tasks()
    now = utcnow()
    existing = {row.name for row in session.execute(select(PeriodicTask)).scalars().all()}
    created = 0

    for entry in DEFAULT_SCHEDULE:
        if entry.name in existing:
            continue
        if not is_registered(entry.task):
            logger.debug("schedule_skipped_unregistered_task", task=entry.task)
            continue
        session.add(
            PeriodicTask(
                name=entry.name,
                task=entry.task,
                payload={},
                description=entry.description,
                interval_seconds=entry.interval_seconds,
                enabled=True,
                next_run_at=now + timedelta(seconds=entry.initial_delay_seconds),
            )
        )
        created += 1

    if created:
        session.flush()
        logger.info("schedule_registered", created=created)
    return created


def tick(session: Session, queue: DbTaskQueue) -> int:
    """Enqueue every schedule entry that has come due.

    Due rows are locked with ``SKIP LOCKED`` so that if several processes run a scheduler,
    each entry is still claimed exactly once per interval.
    """
    now = utcnow()
    due = (
        session.execute(
            select(PeriodicTask)
            .where(PeriodicTask.enabled.is_(True))
            .where(PeriodicTask.next_run_at <= now)
            .with_for_update(skip_locked=True)
        )
        .scalars()
        .all()
    )

    enqueued = 0
    for entry in due:
        if not is_registered(entry.task):
            entry.last_status = "unregistered"
            entry.last_error = f"task '{entry.task}' is not registered in this build"
            entry.next_run_at = now + timedelta(seconds=entry.interval_seconds)
            continue

        job = queue.enqueue(
            session,
            entry.task,
            dict(entry.payload),
            dedupe_key=f"periodic:{entry.task}",
        )
        entry.last_run_at = now
        entry.run_count += 1
        entry.next_run_at = now + timedelta(seconds=entry.interval_seconds)
        if job is None:
            # The previous run is still pending; skipping is correct rather than piling up.
            entry.last_status = "skipped_already_pending"
        else:
            entry.last_status = "enqueued"
            entry.last_error = None
            enqueued += 1

    return enqueued
