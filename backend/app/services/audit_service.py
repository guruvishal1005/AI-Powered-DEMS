"""Audit-log query and chain verification for the explorer UI."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.audit.chain import verify_audit_chain
from app.core.clock import utcnow
from app.core.context import RequestContext
from app.core.pagination import PageParams, paginate
from app.models.analysis import Entity
from app.models.case import Case
from app.models.custody import AuditLogEntry
from app.models.evidence import Evidence
from app.security.scoping import apply_case_scope, scope_case_ids


def list_entries(
    db: Session,
    ctx: RequestContext,
    params: PageParams,
    *,
    action: str | None = None,
    actor_id: uuid.UUID | None = None,
    resource_type: str | None = None,
    case_id: uuid.UUID | None = None,
    result: str | None = None,
    recorded_after: datetime | None = None,
    recorded_before: datetime | None = None,
    search: str | None = None,
) -> tuple[list[AuditLogEntry], int]:
    stmt = select(AuditLogEntry)
    # Case-scoped entries follow object scope; platform-level entries (no case) are visible
    # to anyone holding audit:read, which the router already required.
    if case_id is not None:
        stmt = scope_case_ids(
            stmt.where(AuditLogEntry.case_id == case_id), ctx, AuditLogEntry.case_id
        )
    if action:
        stmt = stmt.where(AuditLogEntry.action == action)
    if actor_id:
        stmt = stmt.where(AuditLogEntry.actor_id == actor_id)
    if resource_type:
        stmt = stmt.where(AuditLogEntry.resource_type == resource_type)
    if result:
        stmt = stmt.where(AuditLogEntry.result == result)
    if recorded_after:
        stmt = stmt.where(AuditLogEntry.recorded_at >= recorded_after)
    if recorded_before:
        stmt = stmt.where(AuditLogEntry.recorded_at <= recorded_before)
    if search:
        pattern = f"%{search.strip()}%"
        stmt = stmt.where(
            or_(
                AuditLogEntry.actor_label.ilike(pattern),
                AuditLogEntry.resource_label.ilike(pattern),
                AuditLogEntry.detail.ilike(pattern),
                AuditLogEntry.action.ilike(pattern),
            )
        )
    stmt = stmt.order_by(AuditLogEntry.sequence.desc())
    return paginate(db, stmt, params)


def verify_window(
    db: Session,
    *,
    start_sequence: int | None = None,
    limit: int = 2000,
) -> dict[str, object]:
    result = verify_audit_chain(db, start_sequence=start_sequence, limit=limit)
    return {
        "entries_checked": result.entries_checked,
        "intact": result.intact,
        "summary": result.summary,
        "head_hash": result.head_hash,
        "first_sequence": result.first_sequence,
        "last_sequence": result.last_sequence,
        "signatures_checked": result.signatures_checked,
        "signatures_valid": result.signatures_valid,
        "breaks": [
            {
                "kind": item.kind,
                "sequence": item.sequence,
                "record_id": item.record_id,
                "detail": item.detail,
            }
            for item in result.breaks
        ],
        "verified_at": utcnow(),
    }


def search(
    db: Session,
    ctx: RequestContext,
    query: str,
    *,
    limit: int = 8,
) -> dict[str, list[dict[str, object]]]:
    q = query.strip()
    if len(q) < 2:
        return {"query": q, "cases": [], "evidence": [], "entities": [], "hashes": []}
    pattern = f"%{q}%"
    cases = list(
        db.execute(
            apply_case_scope(
                select(Case)
                .where(or_(Case.reference.ilike(pattern), Case.title.ilike(pattern)))
                .order_by(Case.updated_at.desc())
                .limit(limit),
                ctx,
            )
        )
        .scalars()
        .all()
    )
    evidence = list(
        db.execute(
            scope_case_ids(
                select(Evidence)
                .where(
                    or_(
                        Evidence.reference.ilike(pattern),
                        Evidence.title.ilike(pattern),
                        Evidence.original_filename.ilike(pattern),
                        Evidence.sha256.ilike(f"{q.lower()}%"),
                    )
                )
                .order_by(Evidence.uploaded_at.desc())
                .limit(limit),
                ctx,
                Evidence.case_id,
            )
        )
        .scalars()
        .all()
    )
    entities = list(
        db.execute(
            select(Entity)
            .where(
                or_(
                    Entity.canonical_value.ilike(pattern),
                    Entity.display_value.ilike(pattern),
                )
            )
            .order_by(Entity.document_frequency.desc())
            .limit(limit)
        )
        .scalars()
        .all()
    )
    hash_hits = [
        item for item in evidence if item.sha256.startswith(q.lower()) or q.lower() in item.sha256
    ]
    return {
        "query": q,
        "cases": [
            {
                "kind": "case",
                "id": row.id,
                "reference": row.reference,
                "title": row.title,
                "subtitle": row.status.value,
                "href": f"/cases/{row.id}",
            }
            for row in cases
        ],
        "evidence": [
            {
                "kind": "evidence",
                "id": row.id,
                "reference": row.reference,
                "title": row.title,
                "subtitle": row.original_filename,
                "href": f"/evidence/{row.id}",
            }
            for row in evidence
        ],
        "entities": [
            {
                "kind": "entity",
                "id": row.id,
                "reference": None,
                "title": row.display_value,
                "subtitle": row.type.value,
                "href": f"/intelligence/entities/{row.id}",
            }
            for row in entities
        ],
        "hashes": [
            {
                "kind": "hash",
                "id": row.id,
                "reference": row.reference,
                "title": row.sha256,
                "subtitle": row.title,
                "href": f"/evidence/{row.id}",
            }
            for row in hash_hits
        ],
    }
