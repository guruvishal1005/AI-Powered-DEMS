"""Task registry.

Tasks are referenced by a stable string name, never by an import path, because a queued job
outlives the process that queued it: a job row written before a refactor must still resolve
after it. The registry is the indirection that makes that safe, and it also gives the admin
interface a list of what the platform can actually run.

Every task receives an explicit ``Session`` and ``RequestContext``. The worker owns the
transaction, so a task body never commits: either the task and all of its audit and custody
records land together, or none of them do.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from sqlalchemy.orm import Session

from app.core.context import RequestContext
from app.core.errors import NotFound

TaskFunction = Callable[[Session, RequestContext, dict[str, Any]], dict[str, Any] | None]


@dataclass(frozen=True, slots=True)
class TaskSpec:
    name: str
    func: TaskFunction
    max_attempts: int
    priority: int
    description: str
    # Tasks that must never run twice concurrently for the same subject supply a dedupe key
    # template, e.g. "analysis:{evidence_id}".
    dedupe_template: str | None = None


REGISTRY: dict[str, TaskSpec] = {}


def task(
    name: str,
    *,
    max_attempts: int = 3,
    priority: int = 100,
    description: str = "",
    dedupe_template: str | None = None,
) -> Callable[[TaskFunction], TaskFunction]:
    def decorator(func: TaskFunction) -> TaskFunction:
        if name in REGISTRY:
            raise RuntimeError(f"task '{name}' is already registered")
        REGISTRY[name] = TaskSpec(
            name=name,
            func=func,
            max_attempts=max_attempts,
            priority=priority,
            description=description or (func.__doc__ or "").strip().split("\n")[0],
            dedupe_template=dedupe_template,
        )
        return func

    return decorator


def get_task(name: str) -> TaskSpec:
    load_tasks()
    try:
        return REGISTRY[name]
    except KeyError as exc:
        raise NotFound("Task", name) from exc


def is_registered(name: str) -> bool:
    load_tasks()
    return name in REGISTRY


def all_tasks() -> tuple[TaskSpec, ...]:
    return tuple(sorted(REGISTRY.values(), key=lambda spec: spec.name))


_loading = False


def load_tasks() -> None:
    """Import every task module so decorators run.

    Idempotent and safe to call from any lookup, so callers never have to remember to prime the
    registry. The recursion guard matters: task modules import the queue, which looks tasks up, so
    a lookup during loading must not re-enter this function and import the modules twice - the
    second pass would hit the decorator's duplicate-name check and fail at import time.
    """
    global _loading
    if REGISTRY or _loading:
        return

    _loading = True
    try:
        from app.jobs.tasks import (  # noqa: F401
            analysis,
            backup,
            integrity,
            intelligence,
            maintenance,
            retention,
        )
    finally:
        _loading = False
