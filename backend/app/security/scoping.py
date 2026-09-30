"""Object-level authorization.

Permission checks answer "may this actor download evidence at all?". They cannot answer "may
this actor download *this* item?", which is the question that actually protects a case from a
colleague on an unrelated investigation.

That second question is answered here, and it is answered **in SQL**. Every list and detail
query is narrowed by :func:`scope_case_ids`, so rows outside the actor's remit are never
selected. This matters more than it might appear: if authorization were a post-filter in
Python, then every ``count(*)``, aggregate, export and dashboard metric would need to
remember to apply it, and one forgotten call site becomes a disclosure. Pushing the predicate
into the statement means the database enforces it uniformly, and a missing scope shows up as
an obviously unscoped query rather than as silently leaked data.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import ColumnElement, Select, or_, select
from sqlalchemy.orm import InstrumentedAttribute
from sqlalchemy.sql.elements import BinaryExpression

from app.core.context import RequestContext
from app.models.case import Case, CaseAssignment
from app.models.enums import Permission


def has_global_case_access(ctx: RequestContext) -> bool:
    """Auditors and administrators oversee every case; everyone else sees their own work."""
    return ctx.is_system or ctx.has(Permission.case_read_all)


def accessible_case_ids(ctx: RequestContext) -> Select[Any]:
    """Subquery of the case ids this actor may see.

    Membership is either leading the case or holding a live assignment on it. An assignment
    that has been withdrawn (``unassigned_at`` set) confers nothing, so removing someone from
    a case takes effect on their next request.
    """
    assigned = (
        select(CaseAssignment.case_id)
        .where(CaseAssignment.user_id == ctx.actor_id)
        .where(CaseAssignment.unassigned_at.is_(None))
    )
    return select(Case.id).where(
        or_(Case.lead_investigator_id == ctx.actor_id, Case.id.in_(assigned))
    )


# Any case-id-bearing column: ``Case.id`` itself, or the denormalised ``case_id`` carried by
# evidence, custody events, observations and alerts.
type CaseIdColumn = ColumnElement[Any] | InstrumentedAttribute[Any]


def scope_case_ids[T: Select[Any]](stmt: T, ctx: RequestContext, column: CaseIdColumn) -> T:
    """Narrow ``stmt`` so ``column`` (a case id) is one the actor may see."""
    if has_global_case_access(ctx):
        return stmt
    return stmt.where(column.in_(accessible_case_ids(ctx)))


def apply_case_scope[T: Select[Any]](stmt: T, ctx: RequestContext) -> T:
    """Narrow a statement selecting from ``cases``."""
    return scope_case_ids(stmt, ctx, Case.id)


def case_access_predicate(ctx: RequestContext) -> BinaryExpression[bool] | ColumnElement[bool]:
    """Standalone predicate, for use inside a larger boolean expression."""
    if has_global_case_access(ctx):
        return Case.id.is_not(None)
    return Case.id.in_(accessible_case_ids(ctx))
