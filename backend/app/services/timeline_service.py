"""Unified timeline assembly.

The reconstructed timeline is not a separate store. It is a projection of records that already
exist for other reasons - custody events, extracted observations, analyzer findings, human
findings, case lifecycle and alerts - so it cannot drift from the case record. Server-side
bucketing exists because a month of syslog observations is unplottable as raw points; the
buckets are counts, never a substitute for the events themselves.
"""

from __future__ import annotations

import uuid
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from typing import Any, Literal

from sqlalchemy import Select, or_, select
from sqlalchemy.orm import Session, joinedload

from app.core.clock import ensure_utc, utcnow
from app.core.context import RequestContext
from app.core.pagination import PageParams, paginate
from app.models.alert import Alert
from app.models.analysis import AnalysisFinding, Observation
from app.models.case import CaseStatusHistory, Finding
from app.models.custody import CustodyEvent
from app.models.enums import ObservationKind, Severity
from app.models.evidence import Evidence, IntegrityCheck
from app.security.scoping import scope_case_ids
from app.services import case_service

Resolution = Literal["raw", "minute", "hour", "day"]

_SEVERITY_ORDER = {
    Severity.informational: 0,
    Severity.low: 1,
    Severity.medium: 2,
    Severity.high: 3,
    Severity.critical: 4,
}


def _choose_resolution(window_start: datetime, window_end: datetime, total: int) -> Resolution:
    span = window_end - window_start
    if total <= 400 and span <= timedelta(hours=12):
        return "raw"
    if span <= timedelta(days=2):
        return "minute" if total <= 800 else "hour"
    if span <= timedelta(days=45):
        return "hour"
    return "day"


def _bucket_start(moment: datetime, resolution: Resolution) -> datetime:
    moment = ensure_utc(moment)
    if resolution == "minute":
        return moment.replace(second=0, microsecond=0)
    if resolution == "hour":
        return moment.replace(minute=0, second=0, microsecond=0)
    return moment.replace(hour=0, minute=0, second=0, microsecond=0)


def _bucket_end(start: datetime, resolution: Resolution) -> datetime:
    if resolution == "minute":
        return start + timedelta(minutes=1)
    if resolution == "hour":
        return start + timedelta(hours=1)
    return start + timedelta(days=1)


def _peak(current: Severity | None, candidate: Severity | None) -> Severity | None:
    if candidate is None:
        return current
    if current is None:
        return candidate
    return candidate if _SEVERITY_ORDER[candidate] > _SEVERITY_ORDER[current] else current


def assemble(
    db: Session,
    ctx: RequestContext,
    *,
    case_id: uuid.UUID | None = None,
    evidence_id: uuid.UUID | None = None,
    window_start: datetime | None = None,
    window_end: datetime | None = None,
    sources: list[str] | None = None,
    kinds: list[str] | None = None,
    resolution: Resolution | None = None,
    limit: int = 1500,
) -> dict[str, Any]:
    """Build a timeline window, optionally bucketed for the requested zoom."""
    if case_id is not None:
        case_service.require_case_access(db, ctx, case_id)

    wanted = (
        set(sources)
        if sources
        else {
            "custody",
            "observation",
            "analysis_finding",
            "finding",
            "lifecycle",
            "alert",
            "integrity",
        }
    )
    events: list[dict[str, Any]] = []

    if "custody" in wanted:
        events.extend(_custody(db, ctx, case_id, evidence_id, window_start, window_end))
    if "observation" in wanted:
        events.extend(_observations(db, ctx, case_id, evidence_id, window_start, window_end, kinds))
    if "analysis_finding" in wanted:
        events.extend(_analysis_findings(db, ctx, case_id, evidence_id, window_start, window_end))
    if "finding" in wanted and evidence_id is None:
        events.extend(_findings(db, ctx, case_id, window_start, window_end))
    if "lifecycle" in wanted and evidence_id is None:
        events.extend(_lifecycle(db, ctx, case_id, window_start, window_end))
    if "alert" in wanted:
        events.extend(_alerts(db, ctx, case_id, evidence_id, window_start, window_end))
    if "integrity" in wanted:
        events.extend(_integrity(db, ctx, case_id, evidence_id, window_start, window_end))

    events.sort(key=lambda item: (item["occurred_at"], item["id"]))
    source_counts = Counter(event["source"] for event in events)
    total = len(events)

    if not events:
        now = utcnow()
        return {
            "case_id": case_id,
            "window_start": window_start,
            "window_end": window_end,
            "resolution": "raw",
            "total": 0,
            "events": [],
            "buckets": [],
            "sources": dict(source_counts),
            "generated_at": now,
        }

    first = events[0]["occurred_at"]
    last = events[-1]["occurred_at"]
    chosen = resolution or _choose_resolution(first, last, total)

    if chosen == "raw":
        return {
            "case_id": case_id,
            "window_start": window_start or first,
            "window_end": window_end or last,
            "resolution": "raw",
            "total": total,
            "events": events[:limit],
            "buckets": [],
            "sources": dict(source_counts),
        }

    buckets: dict[datetime, dict[str, Any]] = {}
    for event in events:
        start = _bucket_start(event["occurred_at"], chosen)
        bucket = buckets.get(start)
        if bucket is None:
            bucket = {
                "bucket_start": start,
                "bucket_end": _bucket_end(start, chosen),
                "count": 0,
                "by_source": defaultdict(int),
                "by_kind": defaultdict(int),
                "peak_severity": None,
            }
            buckets[start] = bucket
        bucket["count"] += 1
        bucket["by_source"][event["source"]] += 1
        bucket["by_kind"][event["kind"]] += 1
        bucket["peak_severity"] = _peak(bucket["peak_severity"], event.get("severity"))

    ordered = []
    for start in sorted(buckets):
        bucket = buckets[start]
        ordered.append(
            {
                "bucket_start": bucket["bucket_start"],
                "bucket_end": bucket["bucket_end"],
                "count": bucket["count"],
                "by_source": dict(bucket["by_source"]),
                "by_kind": dict(bucket["by_kind"]),
                "peak_severity": bucket["peak_severity"],
            }
        )

    return {
        "case_id": case_id,
        "window_start": window_start or first,
        "window_end": window_end or last,
        "resolution": chosen,
        "total": total,
        "events": events[: min(limit, 200)] if chosen != "raw" else events[:limit],
        "buckets": ordered,
        "sources": dict(source_counts),
    }


def list_observations(
    db: Session,
    ctx: RequestContext,
    params: PageParams,
    *,
    case_id: uuid.UUID | None = None,
    evidence_id: uuid.UUID | None = None,
    kinds: list[ObservationKind] | None = None,
) -> tuple[list[Observation], int]:
    stmt: Select[tuple[Observation]] = scope_case_ids(select(Observation), ctx, Observation.case_id)
    if case_id:
        case_service.require_case_access(db, ctx, case_id)
        stmt = stmt.where(Observation.case_id == case_id)
    if evidence_id:
        stmt = stmt.where(Observation.evidence_id == evidence_id)
    if kinds:
        stmt = stmt.where(Observation.kind.in_(kinds))
    stmt = stmt.order_by(Observation.occurred_at.desc())
    return paginate(db, stmt, params)


def _apply_window(
    stmt: Any,
    column: Any,
    window_start: datetime | None,
    window_end: datetime | None,
) -> Any:
    if window_start is not None:
        stmt = stmt.where(column >= window_start)
    if window_end is not None:
        stmt = stmt.where(column <= window_end)
    return stmt


def _custody(
    db: Session,
    ctx: RequestContext,
    case_id: uuid.UUID | None,
    evidence_id: uuid.UUID | None,
    window_start: datetime | None,
    window_end: datetime | None,
) -> list[dict[str, Any]]:
    stmt = scope_case_ids(select(CustodyEvent), ctx, CustodyEvent.case_id)
    if case_id:
        stmt = stmt.where(CustodyEvent.case_id == case_id)
    if evidence_id:
        stmt = stmt.where(CustodyEvent.evidence_id == evidence_id)
    stmt = _apply_window(stmt, CustodyEvent.occurred_at, window_start, window_end)
    rows = db.execute(stmt).scalars().all()
    refs = _evidence_refs(db, {row.evidence_id for row in rows})
    return [
        {
            "id": f"custody:{row.id}",
            "source": "custody",
            "occurred_at": row.occurred_at,
            "recorded_at": row.recorded_at,
            "kind": row.action.value,
            "title": row.action.value.replace("_", " "),
            "summary": row.reason or row.notes,
            "severity": None,
            "case_id": row.case_id,
            "evidence_id": row.evidence_id,
            "evidence_reference": refs.get(row.evidence_id),
            "actor_label": row.actor_label,
            "locator": {},
            "excerpt": None,
            "attributes": {"sequence": row.sequence, "entry_hash": row.entry_hash},
        }
        for row in rows
    ]


def _observations(
    db: Session,
    ctx: RequestContext,
    case_id: uuid.UUID | None,
    evidence_id: uuid.UUID | None,
    window_start: datetime | None,
    window_end: datetime | None,
    kinds: list[str] | None,
) -> list[dict[str, Any]]:
    stmt = scope_case_ids(select(Observation), ctx, Observation.case_id)
    if case_id:
        stmt = stmt.where(Observation.case_id == case_id)
    if evidence_id:
        stmt = stmt.where(Observation.evidence_id == evidence_id)
    if kinds:
        stmt = stmt.where(Observation.kind.in_(kinds))
    stmt = _apply_window(stmt, Observation.occurred_at, window_start, window_end)
    rows = db.execute(stmt).scalars().all()
    refs = _evidence_refs(db, {row.evidence_id for row in rows})
    return [
        {
            "id": f"observation:{row.id}",
            "source": "observation",
            "occurred_at": row.occurred_at,
            "recorded_at": row.created_at,
            "time_confidence": row.time_confidence.value,
            "timezone_assumed": row.timezone_assumed,
            "kind": row.kind.value,
            "title": row.summary,
            "summary": row.excerpt,
            "severity": None,
            "case_id": row.case_id,
            "evidence_id": row.evidence_id,
            "evidence_reference": refs.get(row.evidence_id),
            "actor_label": row.actor_value,
            "locator": row.locator or {},
            "excerpt": row.excerpt,
            "attributes": row.attributes or {},
        }
        for row in rows
    ]


def _analysis_findings(
    db: Session,
    ctx: RequestContext,
    case_id: uuid.UUID | None,
    evidence_id: uuid.UUID | None,
    window_start: datetime | None,
    window_end: datetime | None,
) -> list[dict[str, Any]]:
    stmt = scope_case_ids(select(AnalysisFinding), ctx, AnalysisFinding.case_id)
    if case_id:
        stmt = stmt.where(AnalysisFinding.case_id == case_id)
    if evidence_id:
        stmt = stmt.where(AnalysisFinding.evidence_id == evidence_id)
    stmt = _apply_window(stmt, AnalysisFinding.created_at, window_start, window_end)
    rows = db.execute(stmt).scalars().all()
    refs = _evidence_refs(db, {row.evidence_id for row in rows})
    return [
        {
            "id": f"analysis_finding:{row.id}",
            "source": "analysis_finding",
            "occurred_at": row.created_at,
            "recorded_at": row.created_at,
            "kind": row.code,
            "title": row.title,
            "summary": row.description,
            "severity": row.severity,
            "case_id": row.case_id,
            "evidence_id": row.evidence_id,
            "evidence_reference": refs.get(row.evidence_id),
            "actor_label": row.analyzer,
            "locator": row.locator or {},
            "excerpt": row.excerpt,
            "attributes": row.attributes or {},
        }
        for row in rows
    ]


def _findings(
    db: Session,
    ctx: RequestContext,
    case_id: uuid.UUID | None,
    window_start: datetime | None,
    window_end: datetime | None,
) -> list[dict[str, Any]]:
    stmt = scope_case_ids(select(Finding).options(joinedload(Finding.author)), ctx, Finding.case_id)
    if case_id:
        stmt = stmt.where(Finding.case_id == case_id)
    stmt = _apply_window(stmt, Finding.created_at, window_start, window_end)
    rows = db.execute(stmt).unique().scalars().all()
    return [
        {
            "id": f"finding:{row.id}",
            "source": "finding",
            "occurred_at": row.created_at,
            "recorded_at": row.created_at,
            "kind": row.kind.value,
            "title": row.title,
            "summary": row.description[:400],
            "severity": row.severity,
            "case_id": row.case_id,
            "evidence_id": None,
            "evidence_reference": None,
            "actor_label": row.author.full_name if row.author else None,
            "locator": {},
            "excerpt": None,
            "attributes": {"sequence": row.sequence, "confidence": row.confidence.value},
        }
        for row in rows
    ]


def _lifecycle(
    db: Session,
    ctx: RequestContext,
    case_id: uuid.UUID | None,
    window_start: datetime | None,
    window_end: datetime | None,
) -> list[dict[str, Any]]:
    stmt = scope_case_ids(
        select(CaseStatusHistory).options(joinedload(CaseStatusHistory.changed_by)),
        ctx,
        CaseStatusHistory.case_id,
    )
    if case_id:
        stmt = stmt.where(CaseStatusHistory.case_id == case_id)
    stmt = _apply_window(stmt, CaseStatusHistory.created_at, window_start, window_end)
    rows = db.execute(stmt).unique().scalars().all()
    return [
        {
            "id": f"lifecycle:{row.id}",
            "source": "lifecycle",
            "occurred_at": row.created_at,
            "recorded_at": row.created_at,
            "kind": f"status.{row.to_status.value}",
            "title": (
                f"Status changed to {row.to_status.value}"
                if row.from_status is None
                else f"Status {row.from_status.value} → {row.to_status.value}"
            ),
            "summary": row.reason,
            "severity": None,
            "case_id": row.case_id,
            "evidence_id": None,
            "evidence_reference": None,
            "actor_label": row.changed_by.full_name if row.changed_by else None,
            "locator": {},
            "excerpt": None,
            "attributes": {},
        }
        for row in rows
    ]


def _alerts(
    db: Session,
    ctx: RequestContext,
    case_id: uuid.UUID | None,
    evidence_id: uuid.UUID | None,
    window_start: datetime | None,
    window_end: datetime | None,
) -> list[dict[str, Any]]:
    stmt = _scope_alerts(select(Alert), ctx)
    if case_id:
        stmt = stmt.where(Alert.case_id == case_id)
    if evidence_id:
        stmt = stmt.where(Alert.evidence_id == evidence_id)
    stmt = _apply_window(stmt, Alert.first_seen_at, window_start, window_end)
    rows = db.execute(stmt).scalars().all()
    return [
        {
            "id": f"alert:{row.id}",
            "source": "alert",
            "occurred_at": row.first_seen_at,
            "recorded_at": row.created_at,
            "kind": row.type.value,
            "title": row.title,
            "summary": row.description[:400],
            "severity": row.severity,
            "case_id": row.case_id,
            "evidence_id": row.evidence_id,
            "evidence_reference": None,
            "actor_label": row.source.value,
            "locator": {},
            "excerpt": None,
            "attributes": {"reference": row.reference, "status": row.status.value},
        }
        for row in rows
    ]


def _integrity(
    db: Session,
    ctx: RequestContext,
    case_id: uuid.UUID | None,
    evidence_id: uuid.UUID | None,
    window_start: datetime | None,
    window_end: datetime | None,
) -> list[dict[str, Any]]:
    stmt = select(IntegrityCheck, Evidence).join(
        Evidence, Evidence.id == IntegrityCheck.evidence_id
    )
    stmt = scope_case_ids(stmt, ctx, Evidence.case_id)
    if case_id:
        stmt = stmt.where(Evidence.case_id == case_id)
    if evidence_id:
        stmt = stmt.where(IntegrityCheck.evidence_id == evidence_id)
    stmt = _apply_window(stmt, IntegrityCheck.created_at, window_start, window_end)
    rows = db.execute(stmt).all()
    return [
        {
            "id": f"integrity:{check.id}",
            "source": "integrity",
            "occurred_at": check.created_at,
            "recorded_at": check.created_at,
            "kind": check.status.value,
            "title": f"Integrity {check.status.value.replace('_', ' ')}",
            "summary": check.detail,
            "severity": (
                Severity.critical
                if check.status.value in {"hash_mismatch", "decryption_failed", "object_missing"}
                else Severity.informational
            ),
            "case_id": evidence.case_id,
            "evidence_id": evidence.id,
            "evidence_reference": evidence.reference,
            "actor_label": None,
            "locator": {},
            "excerpt": None,
            "attributes": {
                "expected_sha256": check.expected_sha256,
                "computed_sha256": check.computed_sha256,
            },
        }
        for check, evidence in rows
    ]


def _evidence_refs(db: Session, ids: set[uuid.UUID]) -> dict[uuid.UUID, str]:
    if not ids:
        return {}
    rows = db.execute(select(Evidence.id, Evidence.reference).where(Evidence.id.in_(ids))).all()
    return {row.id: row.reference for row in rows}


def _scope_alerts(stmt: Any, ctx: RequestContext) -> Any:
    from app.security.scoping import accessible_case_ids, has_global_case_access

    if has_global_case_access(ctx):
        return stmt
    return stmt.where(or_(Alert.case_id.is_(None), Alert.case_id.in_(accessible_case_ids(ctx))))
