"""Database-backed task queue.

Claiming uses ``SELECT ... FOR UPDATE SKIP LOCKED``, which is the mechanism that makes a
table usable as a queue: each worker takes rows that no other worker holds, without blocking
and without a broker. Semantics match a real queue closely enough that replacing this with
Celery or RQ later means writing one new class behind :class:`TaskQueue`, and nothing else.

Failure handling is exponential backoff up to ``max_attempts``, then the job moves to
``dead``. Dead jobs are kept, not deleted: "what stopped working, and when" is operational
evidence, and an alert is raised so a dead job is not discovered by accident.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta
from typing import Any, Protocol

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.clock import utcnow
from app.core.config import settings
from app.core.logging import get_logger
from app.jobs.registry import get_task, is_registered
from app.models.enums import JobStatus
from app.models.ops import Job

logger = get_logger(__name__)

# Retry delay = BACKOFF_BASE_SECONDS * 2 ** (attempts - 1), capped.
BACKOFF_BASE_SECONDS = 15
BACKOFF_CAP_SECONDS = 3600


class TaskQueue(Protocol):
    """The boundary a different queue implementation would need to satisfy.

    Declared with the full keyword set rather than ``**kwargs`` so that call sites are type
    checked: queueing analysis for the wrong keyword should be a static error, not a job that
    silently loses its case association.
    """

    def enqueue(
        self,
        session: Session,
        task_name: str,
        payload: dict[str, Any] | None = None,
        *,
        priority: int | None = ...,
        delay_seconds: float = ...,
        run_at: datetime | None = ...,
        dedupe_key: str | None = ...,
        case_id: uuid.UUID | None = ...,
        evidence_id: uuid.UUID | None = ...,
        requested_by_id: uuid.UUID | None = ...,
        max_attempts: int | None = ...,
        parent_job_id: uuid.UUID | None = ...,
    ) -> Job | None: ...

    def claim(self, session: Session, worker_id: str, *, limit: int = 1) -> list[Job]: ...


class DbTaskQueue:
    def enqueue(
        self,
        session: Session,
        task_name: str,
        payload: dict[str, Any] | None = None,
        *,
        priority: int | None = None,
        delay_seconds: float = 0,
        run_at: datetime | None = None,
        dedupe_key: str | None = None,
        case_id: uuid.UUID | None = None,
        evidence_id: uuid.UUID | None = None,
        requested_by_id: uuid.UUID | None = None,
        max_attempts: int | None = None,
        parent_job_id: uuid.UUID | None = None,
    ) -> Job | None:
        """Queue a job. Returns ``None`` when an identical job is already pending.

        Dedupe is enforced by a partial unique index rather than by this read, so two workers
        racing to queue the same work cannot both succeed; the loser simply gets ``None``.
        """
        spec = get_task(task_name)

        if dedupe_key is None and spec.dedupe_template:
            try:
                dedupe_key = spec.dedupe_template.format(**(payload or {}))
            except KeyError:
                dedupe_key = None

        if dedupe_key is not None:
            existing = session.execute(
                select(Job)
                .where(Job.dedupe_key == dedupe_key)
                .where(Job.status.in_([JobStatus.queued, JobStatus.running]))
            ).scalar_one_or_none()
            if existing is not None:
                return None

        now = utcnow()
        job = Job(
            task=task_name,
            payload=payload or {},
            status=JobStatus.queued,
            priority=priority if priority is not None else spec.priority,
            max_attempts=max_attempts if max_attempts is not None else spec.max_attempts,
            created_at=now,
            run_at=run_at or (now + timedelta(seconds=delay_seconds)),
            dedupe_key=dedupe_key,
            case_id=case_id,
            evidence_id=evidence_id,
            requested_by_id=requested_by_id,
            parent_job_id=parent_job_id,
        )
        try:
            # A SAVEPOINT, not the outer transaction: enqueue is nearly always called as part of
            # a larger unit of work (registering evidence, then queueing its analysis), and
            # losing a dedupe race must not discard that work.
            with session.begin_nested():
                session.add(job)
                session.flush()
        except IntegrityError:
            # Lost the dedupe race; the other writer's job will do the work.
            logger.debug("job_dedupe_race", task=task_name, dedupe_key=dedupe_key)
            return None
        return job

    def claim(self, session: Session, worker_id: str, *, limit: int = 1) -> list[Job]:
        """Atomically take up to ``limit`` due jobs for this worker."""
        now = utcnow()
        candidates = (
            session.execute(
                select(Job)
                .where(Job.status == JobStatus.queued)
                .where(Job.run_at <= now)
                .order_by(Job.priority, Job.run_at)
                .limit(limit)
                .with_for_update(skip_locked=True)
            )
            .scalars()
            .all()
        )

        claimed: list[Job] = []
        for job in candidates:
            job.status = JobStatus.running
            job.attempts += 1
            job.started_at = now
            job.locked_by = worker_id
            job.locked_at = now
            job.heartbeat_at = now
            job.lease_expires_at = now + timedelta(seconds=settings.job_lease_seconds)
            claimed.append(job)

        if claimed:
            session.flush()
        return claimed

    def complete(self, session: Session, job: Job, result: dict[str, Any] | None = None) -> None:
        now = utcnow()
        job.status = JobStatus.succeeded
        job.finished_at = now
        job.result = result
        job.last_error = None
        job.locked_by = None
        job.lease_expires_at = None
        if job.started_at is not None:
            job.duration_ms = int((now - job.started_at).total_seconds() * 1000)

    def fail(self, session: Session, job: Job, error: str) -> None:
        """Record a failure and either schedule a retry or bury the job."""
        now = utcnow()
        job.last_error = error[:4000]
        job.locked_by = None
        job.lease_expires_at = None
        if job.started_at is not None:
            job.duration_ms = int((now - job.started_at).total_seconds() * 1000)

        if job.attempts < job.max_attempts:
            delay = min(BACKOFF_BASE_SECONDS * (2 ** max(0, job.attempts - 1)), BACKOFF_CAP_SECONDS)
            job.status = JobStatus.queued
            job.run_at = now + timedelta(seconds=delay)
            job.started_at = None
            logger.warning(
                "job_retry_scheduled",
                job_id=str(job.id),
                task=job.task,
                attempt=job.attempts,
                retry_in_seconds=delay,
            )
        else:
            job.status = JobStatus.dead
            job.finished_at = now
            logger.error(
                "job_dead", job_id=str(job.id), task=job.task, attempts=job.attempts, error=error
            )

    def heartbeat(self, session: Session, job: Job) -> None:
        """Extend a running job's lease so the reaper does not reclaim live work."""
        now = utcnow()
        job.heartbeat_at = now
        job.lease_expires_at = now + timedelta(seconds=settings.job_lease_seconds)

    def reap_expired(self, session: Session) -> int:
        """Requeue jobs whose worker died without releasing them.

        Without this, a process killed mid-task leaves rows stuck in ``running`` forever and
        the work silently never happens - the worst kind of failure, because nothing reports it.
        """
        now = utcnow()
        stale = (
            session.execute(
                select(Job)
                .where(Job.status == JobStatus.running)
                .where(Job.lease_expires_at.is_not(None))
                .where(Job.lease_expires_at < now)
                .with_for_update(skip_locked=True)
            )
            .scalars()
            .all()
        )

        for job in stale:
            logger.warning(
                "job_lease_expired", job_id=str(job.id), task=job.task, worker=job.locked_by
            )
            if job.attempts < job.max_attempts:
                job.status = JobStatus.queued
                job.run_at = now
                job.started_at = None
            else:
                job.status = JobStatus.dead
                job.finished_at = now
                job.last_error = "worker lease expired without completion"
            job.locked_by = None
            job.lease_expires_at = None
        return len(stale)

    def cancel(self, session: Session, job: Job) -> None:
        if job.status not in (JobStatus.queued, JobStatus.running):
            return
        job.status = JobStatus.cancelled
        job.finished_at = utcnow()
        job.locked_by = None
        job.lease_expires_at = None

    def retry(self, session: Session, job: Job) -> None:
        """Put a failed or dead job back on the queue, resetting its attempt budget."""
        job.status = JobStatus.queued
        job.attempts = 0
        job.run_at = utcnow()
        job.started_at = None
        job.finished_at = None
        job.locked_by = None
        job.lease_expires_at = None

    def stats(self, session: Session) -> dict[str, Any]:
        rows = session.execute(select(Job.status, func.count()).group_by(Job.status)).all()
        by_status = {status.value: count for status, count in rows}
        since = utcnow() - timedelta(hours=24)
        failed_24h = session.execute(
            select(func.count())
            .select_from(Job)
            .where(Job.status.in_([JobStatus.failed, JobStatus.dead]))
            .where(Job.created_at >= since)
        ).scalar_one()
        oldest_queued = session.execute(
            select(func.min(Job.run_at)).where(Job.status == JobStatus.queued)
        ).scalar()
        return {
            "by_status": by_status,
            "queue_depth": by_status.get(JobStatus.queued.value, 0),
            "running": by_status.get(JobStatus.running.value, 0),
            "failed_24h": failed_24h,
            "oldest_queued_at": oldest_queued,
        }


queue: TaskQueue = DbTaskQueue()


def enqueue(
    session: Session,
    task_name: str,
    payload: dict[str, Any] | None = None,
    *,
    priority: int | None = None,
    delay_seconds: float = 0,
    run_at: datetime | None = None,
    dedupe_key: str | None = None,
    case_id: uuid.UUID | None = None,
    evidence_id: uuid.UUID | None = None,
    requested_by_id: uuid.UUID | None = None,
    max_attempts: int | None = None,
    parent_job_id: uuid.UUID | None = None,
) -> Job | None:
    """Queue a job on the configured queue.

    Call sites use this rather than the instance, so swapping the implementation is a one-line
    change here instead of an edit to every caller.
    """
    return queue.enqueue(
        session,
        task_name,
        payload,
        priority=priority,
        delay_seconds=delay_seconds,
        run_at=run_at,
        dedupe_key=dedupe_key,
        case_id=case_id,
        evidence_id=evidence_id,
        requested_by_id=requested_by_id,
        max_attempts=max_attempts,
        parent_job_id=parent_job_id,
    )


def enqueue_if_available(
    session: Session,
    task_name: str,
    payload: dict[str, Any] | None = None,
    **kwargs: Any,
) -> Job | None:
    """Queue a job only when the named task exists, returning ``None`` when it does not.

    Used for optional downstream work: a task that hands off to a capability the deployment does
    not have should carry on rather than fail. Writing a job row for an unregistered task would
    instead guarantee a dead job on every single run, which buries real failures in noise.
    """
    if not is_registered(task_name):
        logger.debug("task_not_registered_skipped", task=task_name)
        return None
    return enqueue(session, task_name, payload, **kwargs)
