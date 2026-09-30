"""In-process worker pool.

Threads rather than asyncio, because the work is CPU- and IO-bound in ways that suit threads:
hashing, AES-GCM and parsing all spend their time inside C extensions that release the GIL,
and every database call is synchronous. An event loop would have to hand all of it to a
thread pool anyway.

Each worker owns its own session and its own transaction per job. A task that raises leaves
nothing behind: the transaction rolls back, then the failure is recorded in a *separate*
transaction, so a poisoned task cannot also destroy the record of its own failure.
"""

from __future__ import annotations

import os
import socket
import threading
import time
import traceback
from typing import Any

from app.core.clock import utcnow
from app.core.config import settings
from app.core.context import system_context
from app.core.logging import get_logger
from app.db.session import SessionLocal
from app.jobs.queue import DbTaskQueue
from app.jobs.registry import get_task, load_tasks
from app.models.ops import Job

logger = get_logger(__name__)

REAP_INTERVAL_SECONDS = 60
SCHEDULER_INTERVAL_SECONDS = 10


def worker_identity(index: int) -> str:
    return f"{socket.gethostname()}:{os.getpid()}:w{index}"


class Worker(threading.Thread):
    """Claims and executes jobs until asked to stop."""

    def __init__(self, index: int, stop_event: threading.Event) -> None:
        super().__init__(name=f"cybertrace-worker-{index}", daemon=True)
        self.identity = worker_identity(index)
        self._stop = stop_event
        self._queue = DbTaskQueue()

    def run(self) -> None:
        logger.info("worker_loop_started", worker=self.identity)
        while not self._stop.is_set():
            try:
                executed = self._run_once()
            except Exception as exc:
                # The loop itself must survive anything, including database unavailability.
                logger.exception("worker_loop_error", worker=self.identity, error=str(exc))
                executed = False
            if not executed:
                self._stop.wait(settings.worker_poll_interval_seconds)
        logger.info("worker_loop_stopped", worker=self.identity)

    def _run_once(self) -> bool:
        with SessionLocal() as session:
            jobs = self._queue.claim(session, self.identity, limit=1)
            if not jobs:
                session.rollback()
                return False
            job = jobs[0]
            # Commit the claim immediately so the job is visibly owned even if execution is
            # long; otherwise another worker could see it as unclaimed after a lease reap.
            session.commit()
            job_id = job.id
            task_name = job.task
            payload = dict(job.payload)
            attempt = job.attempts

        self._execute(job_id, task_name, payload, attempt)
        return True

    def _execute(self, job_id: Any, task_name: str, payload: dict[str, Any], attempt: int) -> None:
        started = time.perf_counter()
        logger.info("job_started", job_id=str(job_id), task=task_name, attempt=attempt)

        try:
            spec = get_task(task_name)
        except Exception:
            self._record_failure(job_id, f"task '{task_name}' is not registered")
            return

        ctx = system_context(f"background task {task_name}", request_id=str(job_id))

        try:
            with SessionLocal() as session:
                result = spec.func(session, ctx, payload)
                session.commit()
        except Exception as exc:
            detail = f"{type(exc).__name__}: {exc}\n{traceback.format_exc(limit=8)}"
            logger.error("job_failed", job_id=str(job_id), task=task_name, error=str(exc))
            self._record_failure(job_id, detail)
            return

        duration_ms = (time.perf_counter() - started) * 1000
        with SessionLocal() as session:
            job = session.get(Job, job_id)
            if job is not None:
                self._queue.complete(session, job, result if isinstance(result, dict) else None)
                session.commit()
        logger.info(
            "job_succeeded",
            job_id=str(job_id),
            task=task_name,
            duration_ms=round(duration_ms, 2),
        )

    def _record_failure(self, job_id: Any, error: str) -> None:
        with SessionLocal() as session:
            job = session.get(Job, job_id)
            if job is None:
                return
            self._queue.fail(session, job, error)
            should_alert = job.status.value == "dead"
            task_name = job.task
            session.commit()

        if should_alert:
            self._raise_dead_job_alert(job_id, task_name, error)

    def _raise_dead_job_alert(self, job_id: Any, task_name: str, error: str) -> None:
        """A job that exhausted its retries is an operational failure someone must see."""
        from app.models.enums import AlertSource, AlertType, Severity
        from app.services.alert_service import raise_alert

        try:
            with SessionLocal() as session:
                raise_alert(
                    session,
                    system_context("background job exhausted its retries"),
                    alert_type=AlertType.job_failure,
                    source=AlertSource.platform_monitor,
                    severity=Severity.high,
                    title=f"Background task failed: {task_name}",
                    description=(
                        f"Task '{task_name}' failed on every attempt and has been buried. "
                        f"Last error: {error.splitlines()[0][:300]}"
                    ),
                    dedupe_key=f"job_dead:{task_name}",
                    details={"job_id": str(job_id), "task": task_name},
                    recommended_action="Inspect the job in Administration then retry it.",
                    notify_case_team=False,
                )
                session.commit()
        except Exception as exc:
            logger.exception("dead_job_alert_failed", error=str(exc))


class MaintenanceThread(threading.Thread):
    """Runs the scheduler tick and the lease reaper.

    Kept separate from the job workers so that saturating the pool with long analyses can
    never starve scheduling or leave expired leases unreclaimed.
    """

    def __init__(self, stop_event: threading.Event) -> None:
        super().__init__(name="cybertrace-maintenance", daemon=True)
        self._stop = stop_event
        self._queue = DbTaskQueue()
        self._last_reap = 0.0

    def run(self) -> None:
        from app.jobs.scheduler import tick

        while not self._stop.is_set():
            try:
                with SessionLocal() as session:
                    enqueued = tick(session, self._queue)
                    session.commit()
                    if enqueued:
                        logger.info("scheduler_enqueued", count=enqueued)

                now = time.monotonic()
                if now - self._last_reap >= REAP_INTERVAL_SECONDS:
                    self._last_reap = now
                    with SessionLocal() as session:
                        reaped = self._queue.reap_expired(session)
                        session.commit()
                        if reaped:
                            logger.warning("jobs_reaped", count=reaped)
            except Exception as exc:
                logger.exception("maintenance_error", error=str(exc))

            self._stop.wait(SCHEDULER_INTERVAL_SECONDS)


class WorkerPool:
    def __init__(self, *, concurrency: int = 2) -> None:
        self.concurrency = max(1, concurrency)
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []

    def start(self) -> None:
        load_tasks()
        self._stop.clear()
        for index in range(self.concurrency):
            worker = Worker(index, self._stop)
            worker.start()
            self._threads.append(worker)
        maintenance = MaintenanceThread(self._stop)
        maintenance.start()
        self._threads.append(maintenance)

    def stop(self, timeout: float = 10.0) -> None:
        self._stop.set()
        deadline = time.monotonic() + timeout
        for thread in self._threads:
            thread.join(timeout=max(0.1, deadline - time.monotonic()))
        self._threads.clear()


def run_pending_jobs(limit: int = 100) -> int:
    """Drain the queue synchronously.

    Used by the seeder and by tests, where deterministic completion matters more than
    concurrency: work is executed inline so that by the time this returns, the pipeline has
    genuinely finished and assertions can rely on it.
    """
    load_tasks()
    task_queue = DbTaskQueue()
    identity = f"inline:{os.getpid()}"
    processed = 0

    while processed < limit:
        with SessionLocal() as session:
            jobs = task_queue.claim(session, identity, limit=1)
            if not jobs:
                session.rollback()
                break
            job = jobs[0]
            session.commit()
            job_id, task_name, payload = job.id, job.task, dict(job.payload)

        ctx = system_context(f"inline task {task_name}", request_id=str(job_id))
        try:
            spec = get_task(task_name)
            with SessionLocal() as session:
                result = spec.func(session, ctx, payload)
                session.commit()
            with SessionLocal() as session:
                completed = session.get(Job, job_id)
                if completed is not None:
                    task_queue.complete(
                        session, completed, result if isinstance(result, dict) else None
                    )
                    session.commit()
        except Exception as exc:
            logger.error("inline_job_failed", task=task_name, error=str(exc))
            with SessionLocal() as session:
                failed = session.get(Job, job_id)
                if failed is not None:
                    task_queue.fail(session, failed, f"{type(exc).__name__}: {exc}")
                    session.commit()
        processed += 1

    return processed


def worker_status() -> dict[str, Any]:
    return {"checked_at": utcnow(), "concurrency": settings.worker_concurrency}
