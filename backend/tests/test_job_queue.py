"""Job queue mechanics.

The queue is the platform's reliability boundary: analysis, integrity verification and reporting
all run through it, so a job that is silently dropped becomes evidence that was silently never
examined. These tests cover the properties that make that not happen - exclusive claiming, bounded
retries with backoff, dead-lettering, and reclaiming work from a worker that died.

Concurrency is exercised with two real database sessions rather than by mocking, because
``FOR UPDATE SKIP LOCKED`` is precisely the behaviour under test and it only exists in the database.
"""

from __future__ import annotations

from datetime import timedelta

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker

from app.core.clock import utcnow
from app.core.config import settings
from app.core.context import RequestContext
from app.jobs.queue import DbTaskQueue, enqueue, enqueue_if_available
from app.jobs.registry import get_task, load_tasks, task
from app.models.enums import JobStatus
from app.models.ops import Job
from app.models.user import User
from tests.conftest import context_for

QUEUE = DbTaskQueue()


@pytest.fixture(autouse=True)
def _tasks_loaded() -> None:
    load_tasks()


def queue_job(db: Session, *, task_name: str = "system.health_sample", **kwargs: object) -> Job:
    job = enqueue(db, task_name, {}, **kwargs)  # type: ignore[arg-type]
    assert job is not None
    db.flush()
    return job


class TestClaiming:
    def test_claim_marks_the_job_running_and_records_the_worker(self, db: Session) -> None:
        job = queue_job(db)

        claimed = QUEUE.claim(db, "worker-1", limit=5)

        assert [item.id for item in claimed] == [job.id]
        assert job.status is JobStatus.running
        assert job.attempts == 1
        assert job.locked_by == "worker-1"
        assert job.lease_expires_at is not None

    def test_jobs_scheduled_for_later_are_not_claimed(self, db: Session) -> None:
        queue_job(db, delay_seconds=3600)
        assert QUEUE.claim(db, "worker-1", limit=5) == []

    def test_jobs_are_claimed_in_priority_then_age_order(self, db: Session) -> None:
        low = queue_job(db, priority=200)
        high = queue_job(db, priority=10)

        claimed = QUEUE.claim(db, "worker-1", limit=2)

        assert [item.id for item in claimed] == [high.id, low.id]

    def test_a_claimed_job_is_invisible_to_another_worker(self, db: Session, engine) -> None:
        """Two workers must never run the same job.

        This uses a second independent connection because the guarantee comes from row locks:
        within one session the rows would simply be visible again.
        """
        job = enqueue(db, "system.health_sample", {})
        assert job is not None
        db.commit()

        other_factory = sessionmaker(bind=engine, expire_on_commit=False)
        with other_factory() as other:
            first = QUEUE.claim(db, "worker-1", limit=5)
            assert [item.id for item in first] == [job.id]

            # The first claim holds a row lock and has not committed, so a second worker must skip
            # the row rather than block on it.
            second = QUEUE.claim(other, "worker-2", limit=5)
            assert [item.id for item in second] == []
            other.rollback()

        db.rollback()
        # Clean up the committed row, since it escaped the test transaction.
        with other_factory() as cleanup:
            cleanup.query(Job).filter(Job.id == job.id).delete()
            cleanup.commit()


class TestRetryAndDeadLetter:
    def test_failure_reschedules_with_growing_backoff(self, db: Session) -> None:
        job = queue_job(db, max_attempts=5)

        delays: list[float] = []
        for attempt in (1, 2, 3):
            # Set the attempt count directly. Re-claiming between failures would not work, because
            # a failed job's run_at is pushed into the future and so is not yet claimable.
            job.attempts = attempt
            job.started_at = utcnow()
            before = utcnow()
            QUEUE.fail(db, job, f"transient error on attempt {attempt}")
            delays.append((job.run_at - before).total_seconds())

        assert job.status is JobStatus.queued
        assert job.last_error == "transient error on attempt 3"
        # Backoff must grow, or a task failing against an overloaded dependency keeps hammering it.
        assert delays[0] < delays[1] < delays[2]

    def test_exhausting_attempts_buries_the_job(self, db: Session) -> None:
        job = queue_job(db, max_attempts=1)
        QUEUE.claim(db, "worker-1")

        QUEUE.fail(db, job, "permanent parse failure")

        # Dead rather than deleted: a job that could not be completed has to remain visible for an
        # operator to see, otherwise the work vanishes with no record.
        assert job.status is JobStatus.dead
        assert job.finished_at is not None
        assert job.last_error == "permanent parse failure"

    def test_retry_restores_a_dead_job_with_a_fresh_budget(self, db: Session) -> None:
        job = queue_job(db, max_attempts=1)
        QUEUE.claim(db, "worker-1")
        QUEUE.fail(db, job, "gave up")

        QUEUE.retry(db, job)

        assert job.status is JobStatus.queued
        assert job.attempts == 0
        assert job.finished_at is None

    def test_completion_records_result_and_duration(self, db: Session) -> None:
        job = queue_job(db)
        QUEUE.claim(db, "worker-1")

        QUEUE.complete(db, job, {"examined": 4})

        assert job.status is JobStatus.succeeded
        assert job.result == {"examined": 4}
        assert job.duration_ms is not None
        assert job.last_error is None


class TestLeaseReaping:
    def test_expired_leases_are_requeued(self, db: Session) -> None:
        job = queue_job(db, max_attempts=3)
        QUEUE.claim(db, "worker-1")
        # Simulate a worker killed mid-task: the lease lapses with the row still marked running.
        job.lease_expires_at = utcnow() - timedelta(seconds=1)
        db.flush()

        reaped = QUEUE.reap_expired(db)

        assert reaped == 1
        assert job.status is JobStatus.queued
        assert job.locked_by is None

    def test_expired_lease_on_a_final_attempt_is_buried(self, db: Session) -> None:
        job = queue_job(db, max_attempts=1)
        QUEUE.claim(db, "worker-1")
        job.lease_expires_at = utcnow() - timedelta(seconds=1)
        db.flush()

        QUEUE.reap_expired(db)

        assert job.status is JobStatus.dead
        assert job.last_error is not None
        assert "lease expired" in job.last_error

    def test_heartbeat_extends_the_lease(self, db: Session) -> None:
        job = queue_job(db)
        QUEUE.claim(db, "worker-1")
        original = job.lease_expires_at
        assert original is not None

        job.lease_expires_at = original - timedelta(seconds=30)
        QUEUE.heartbeat(db, job)

        # A long-running task must be able to keep its claim, or the reaper would take work away
        # from a worker that is still making progress.
        assert job.lease_expires_at is not None
        assert job.lease_expires_at > original - timedelta(seconds=30)


class TestDeduplication:
    def test_an_identical_pending_job_is_not_queued_twice(self, db: Session) -> None:
        first = enqueue(db, "system.health_sample", {}, dedupe_key="health:1")
        db.flush()
        second = enqueue(db, "system.health_sample", {}, dedupe_key="health:1")

        assert first is not None
        assert second is None

    def test_dedupe_no_longer_applies_once_the_job_finishes(self, db: Session) -> None:
        first = enqueue(db, "system.health_sample", {}, dedupe_key="health:2")
        db.flush()
        assert first is not None
        QUEUE.claim(db, "worker-1")
        QUEUE.complete(db, first, None)
        db.flush()

        # Otherwise a recurring task would run exactly once for the lifetime of the deployment.
        second = enqueue(db, "system.health_sample", {}, dedupe_key="health:2")
        assert second is not None

    def test_unregistered_tasks_are_skipped_rather_than_queued(self, db: Session) -> None:
        result = enqueue_if_available(db, "nonexistent.task", {})

        assert result is None
        # Writing the row anyway would guarantee a dead job on every run and bury real failures.
        assert db.scalars(select(Job).where(Job.task == "nonexistent.task")).all() == []


class TestTaskExecution:
    def test_registered_tasks_expose_their_metadata(self, db: Session) -> None:
        spec = get_task("evidence.analyze")

        assert spec.max_attempts >= 1
        assert spec.description
        assert callable(spec.func)

    def test_lookup_primes_the_registry_on_first_use(self) -> None:
        """A lookup must succeed without the caller having primed the registry first.

        Checked in a subprocess with a cold interpreter, because the registry is populated by
        import side effects: clearing it in-process cannot be undone, since re-importing modules
        already in ``sys.modules`` does not re-run their decorators.
        """
        import subprocess
        import sys

        result = subprocess.run(
            [
                sys.executable,
                "-c",
                "from app.jobs.registry import is_registered;"
                "print(is_registered('evidence.analyze'))",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.stdout.strip().endswith("True"), result.stderr

    def test_duplicate_task_names_are_rejected_at_registration(self) -> None:
        with pytest.raises(RuntimeError, match="already registered"):

            @task("evidence.analyze")
            def _duplicate(
                db: Session, ctx: RequestContext, payload: dict[str, object]
            ) -> None: ...


class TestStats:
    def test_stats_report_queue_depth_by_status(self, db: Session) -> None:
        queue_job(db)
        running = queue_job(db)
        QUEUE.claim(db, "worker-1", limit=1)
        db.flush()

        stats = QUEUE.stats(db)

        assert stats["queue_depth"] >= 1
        assert stats["running"] >= 1
        assert "by_status" in stats
        del running
