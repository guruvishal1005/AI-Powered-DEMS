"""Case lifecycle.

A case is the container every other record hangs from, and it is also the unit of
authorization: who may see a case decides who may see its evidence, custody, findings and
reports. Two consequences run through this module.

First, every read goes through :func:`get_case`, which applies the same SQL scoping as the list
query. An out-of-scope case is reported as *not found* rather than *forbidden*, because
confirming a case exists is itself a disclosure - "CT-2026-0042 exists but you may not see it"
tells an unauthorised user that an investigation is running.

Second, status is a state machine rather than a free-text field, because closure has meaning:
a closed case has been signed off, and reopening it is an event a reviewer must be able to see.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import Select, func, or_, select
from sqlalchemy.orm import Session, selectinload

from app.audit.writer import append_audit
from app.core.canonical import jsonable
from app.core.clock import utcnow
from app.core.context import RequestContext
from app.core.errors import Conflict, NotFound, PermissionDenied, ValidationFailed
from app.core.logging import get_logger
from app.core.pagination import PageParams, paginate
from app.models.case import Case, CaseAssignment, CaseNote, CasePerson, CaseStatusHistory
from app.models.enums import (
    AuditResult,
    CasePersonRole,
    CaseStatus,
    IncidentType,
    Permission,
    Severity,
)
from app.models.user import User
from app.security.scoping import apply_case_scope, has_global_case_access
from app.services.reference_service import next_case_reference

logger = get_logger(__name__)

# Which transitions are permitted. Anything absent is rejected, so an invalid lifecycle move
# fails loudly instead of quietly corrupting the case's history.
_ALLOWED_TRANSITIONS: dict[CaseStatus, frozenset[CaseStatus]] = {
    CaseStatus.draft: frozenset({CaseStatus.active, CaseStatus.archived}),
    CaseStatus.active: frozenset(
        {CaseStatus.pending_review, CaseStatus.on_hold, CaseStatus.closed}
    ),
    CaseStatus.pending_review: frozenset({CaseStatus.active, CaseStatus.closed}),
    CaseStatus.on_hold: frozenset({CaseStatus.active, CaseStatus.closed}),
    CaseStatus.closed: frozenset({CaseStatus.active, CaseStatus.archived}),
    CaseStatus.archived: frozenset({CaseStatus.active}),
}

# Fields an investigator may edit directly. Anything derived (risk, activity, counts) or
# lifecycle-bearing (status, closure) is deliberately excluded and handled by its own function.
_EDITABLE_FIELDS = frozenset(
    {
        "title",
        "summary",
        "incident_type",
        "severity",
        "incident_occurred_at",
        "reported_at",
        "jurisdiction",
        "organization",
        "external_reference",
        "classification",
        "tags",
    }
)


def _base_query() -> Select[tuple[Case]]:
    return select(Case).options(selectinload(Case.assignments).selectinload(CaseAssignment.user))


def get_case(db: Session, ctx: RequestContext, case_id: uuid.UUID) -> Case:
    """Load a case the actor is allowed to see, or report it as missing."""
    stmt = apply_case_scope(_base_query().where(Case.id == case_id), ctx)
    case = db.execute(stmt).unique().scalar_one_or_none()
    if case is None:
        raise NotFound("Case", str(case_id))
    return case


def get_case_by_reference(db: Session, ctx: RequestContext, reference: str) -> Case:
    stmt = apply_case_scope(_base_query().where(Case.reference == reference), ctx)
    case = db.execute(stmt).unique().scalar_one_or_none()
    if case is None:
        raise NotFound("Case", reference)
    return case


def require_case_access(db: Session, ctx: RequestContext, case_id: uuid.UUID) -> Case:
    """Assert access to a case before acting on something inside it."""
    return get_case(db, ctx, case_id)


def require_open_case(case: Case) -> None:
    """Reject writes to a case that has been closed or archived.

    Evidence and findings cannot be added to a concluded investigation without reopening it,
    otherwise a signed report's underlying record could change after the fact.
    """
    if not case.is_open:
        raise Conflict(
            f"Case {case.reference} is {case.status.value} and cannot be modified. "
            "Reopen the case first if further work is required."
        )


def list_cases(
    db: Session,
    ctx: RequestContext,
    params: PageParams,
    *,
    status: list[CaseStatus] | None = None,
    severity: list[Severity] | None = None,
    incident_type: list[IncidentType] | None = None,
    lead_investigator_id: uuid.UUID | None = None,
    assigned_to_id: uuid.UUID | None = None,
    search: str | None = None,
    legal_hold: bool | None = None,
    opened_after: datetime | None = None,
    opened_before: datetime | None = None,
    sort: str = "last_activity",
    descending: bool = True,
) -> tuple[list[Case], int]:
    stmt = apply_case_scope(_base_query(), ctx)

    if status:
        stmt = stmt.where(Case.status.in_(status))
    if severity:
        stmt = stmt.where(Case.severity.in_(severity))
    if incident_type:
        stmt = stmt.where(Case.incident_type.in_(incident_type))
    if lead_investigator_id:
        stmt = stmt.where(Case.lead_investigator_id == lead_investigator_id)
    if assigned_to_id:
        member_of = (
            select(CaseAssignment.case_id)
            .where(CaseAssignment.user_id == assigned_to_id)
            .where(CaseAssignment.unassigned_at.is_(None))
        )
        stmt = stmt.where(or_(Case.lead_investigator_id == assigned_to_id, Case.id.in_(member_of)))
    if legal_hold is not None:
        stmt = stmt.where(Case.legal_hold.is_(legal_hold))
    if opened_after:
        stmt = stmt.where(Case.opened_at >= opened_after)
    if opened_before:
        stmt = stmt.where(Case.opened_at <= opened_before)
    if search:
        # Trigram indexes back reference and title; ILIKE on the summary is acceptable because
        # it only ever runs alongside the indexed predicates.
        pattern = f"%{search.strip()}%"
        stmt = stmt.where(
            or_(
                Case.reference.ilike(pattern),
                Case.title.ilike(pattern),
                Case.summary.ilike(pattern),
                Case.external_reference.ilike(pattern),
            )
        )

    sort_columns = {
        "last_activity": Case.last_activity_at,
        "opened": Case.opened_at,
        "created": Case.created_at,
        "severity": Case.severity,
        "risk": Case.risk_score,
        "reference": Case.reference,
        "title": Case.title,
    }
    column = sort_columns.get(sort, Case.last_activity_at)
    order = column.desc().nullslast() if descending else column.asc().nullsfirst()
    # Reference is a stable tiebreaker, so pagination cannot repeat or skip rows when the
    # primary sort key has ties.
    stmt = stmt.order_by(order, Case.reference.desc())

    return paginate(db, stmt, params)


def create_case(
    db: Session,
    ctx: RequestContext,
    *,
    title: str,
    summary: str,
    incident_type: IncidentType,
    severity: Severity,
    incident_occurred_at: datetime | None = None,
    reported_at: datetime | None = None,
    lead_investigator_id: uuid.UUID | None = None,
    jurisdiction: str | None = None,
    organization: str | None = None,
    external_reference: str | None = None,
    classification: str = "RESTRICTED",
    tags: list[str] | None = None,
    status: CaseStatus = CaseStatus.active,
) -> Case:
    """Register a new case and make its creator a member of it."""
    if status not in (CaseStatus.draft, CaseStatus.active):
        raise ValidationFailed("A new case may only be created as a draft or active")

    now = utcnow()
    lead_id = lead_investigator_id or ctx.actor_id
    if lead_id is not None and db.get(User, lead_id) is None:
        raise NotFound("User", str(lead_id))

    case = Case(
        reference=next_case_reference(db),
        title=title.strip(),
        summary=summary.strip(),
        incident_type=incident_type,
        severity=severity,
        status=status,
        incident_occurred_at=incident_occurred_at,
        reported_at=reported_at or now,
        opened_at=now if status is CaseStatus.active else None,
        lead_investigator_id=lead_id,
        created_by_id=ctx.actor_id,
        jurisdiction=jurisdiction,
        organization=organization,
        external_reference=external_reference,
        classification=classification,
        tags=tags or [],
        last_activity_at=now,
    )
    db.add(case)
    db.flush()

    db.add(
        CaseStatusHistory(
            case_id=case.id,
            from_status=None,
            to_status=status,
            changed_by_id=ctx.actor_id,
            reason="case registered",
        )
    )

    # Without this the creator could immediately lose sight of their own case, since scoping is
    # by lead or assignment rather than by who created the row.
    if lead_id is not None:
        db.add(
            CaseAssignment(
                case_id=case.id,
                user_id=lead_id,
                role_on_case="lead_investigator",
                assigned_at=now,
                assigned_by_id=ctx.actor_id,
            )
        )

    append_audit(
        db,
        ctx,
        action="case.created",
        resource_type="case",
        resource_id=case.id,
        resource_label=case.reference,
        case_id=case.id,
        after_state={
            "title": case.title,
            "incident_type": incident_type.value,
            "severity": severity.value,
            "status": status.value,
        },
        result=AuditResult.success,
    )
    logger.info("case_created", case=case.reference, actor=ctx.actor_label)
    return case


def update_case(
    db: Session, ctx: RequestContext, case_id: uuid.UUID, changes: dict[str, Any]
) -> Case:
    """Apply field updates, recording only what genuinely changed."""
    case = get_case(db, ctx, case_id)
    require_open_case(case)

    unknown = set(changes) - _EDITABLE_FIELDS
    if unknown:
        raise ValidationFailed(
            f"These fields cannot be edited directly: {', '.join(sorted(unknown))}"
        )

    before: dict[str, Any] = {}
    after: dict[str, Any] = {}
    for field_name, value in changes.items():
        current = getattr(case, field_name)
        if current == value:
            continue
        before[field_name] = jsonable(current)
        after[field_name] = jsonable(value)
        setattr(case, field_name, value)

    if not after:
        # No-op updates are not recorded: an audit trail full of empty edits obscures the real
        # ones, which is the opposite of what it exists for.
        return case

    case.last_activity_at = utcnow()
    append_audit(
        db,
        ctx,
        action="case.updated",
        resource_type="case",
        resource_id=case.id,
        resource_label=case.reference,
        case_id=case.id,
        before_state=before,
        after_state=after,
        result=AuditResult.success,
    )
    return case


def change_status(
    db: Session,
    ctx: RequestContext,
    case_id: uuid.UUID,
    *,
    to_status: CaseStatus,
    reason: str | None = None,
    closure_summary: str | None = None,
) -> Case:
    """Move a case through its lifecycle, enforcing the permitted transitions."""
    case = get_case(db, ctx, case_id)
    from_status = case.status

    if to_status is from_status:
        raise Conflict(f"Case {case.reference} is already {to_status.value}")
    if to_status not in _ALLOWED_TRANSITIONS.get(from_status, frozenset()):
        raise Conflict(f"A case cannot move from {from_status.value} to {to_status.value}")

    # Closing and reopening are separately permissioned, because "may edit a case" and "may
    # declare an investigation concluded" are different levels of authority.
    if to_status is CaseStatus.closed and not ctx.has(Permission.case_close):
        raise PermissionDenied("You do not have permission to close cases")
    if from_status is CaseStatus.closed and not ctx.has(Permission.case_reopen):
        raise PermissionDenied("You do not have permission to reopen a closed case")

    if to_status is CaseStatus.closed:
        if not closure_summary or not closure_summary.strip():
            raise ValidationFailed(
                "A closure summary is required so the case record states why it was concluded"
            )
        case.closure_summary = closure_summary.strip()
        case.closed_at = utcnow()
        case.closed_by_id = ctx.actor_id
    elif from_status is CaseStatus.closed:
        # Reopening clears the closure so a stale sign-off cannot be mistaken for a current one,
        # while the status history retains the fact that it was closed and by whom.
        case.closed_at = None
        case.closed_by_id = None
        case.closure_summary = None

    if to_status is CaseStatus.active and case.opened_at is None:
        case.opened_at = utcnow()

    case.status = to_status
    case.last_activity_at = utcnow()

    db.add(
        CaseStatusHistory(
            case_id=case.id,
            from_status=from_status,
            to_status=to_status,
            changed_by_id=ctx.actor_id,
            reason=reason,
        )
    )
    append_audit(
        db,
        ctx,
        action=f"case.{to_status.value}",
        resource_type="case",
        resource_id=case.id,
        resource_label=case.reference,
        case_id=case.id,
        before_state={"status": from_status.value},
        after_state={"status": to_status.value},
        reason=reason,
        result=AuditResult.success,
    )
    logger.info(
        "case_status_changed",
        case=case.reference,
        **{"from": from_status.value, "to": to_status.value},
    )
    return case


def assign_user(
    db: Session,
    ctx: RequestContext,
    case_id: uuid.UUID,
    *,
    user_id: uuid.UUID,
    role_on_case: str = "forensic_analyst",
) -> CaseAssignment:
    """Grant a user access to a case, reactivating a withdrawn assignment if one exists."""
    case = get_case(db, ctx, case_id)
    require_open_case(case)

    user = db.get(User, user_id)
    if user is None:
        raise NotFound("User", str(user_id))

    existing = db.execute(
        select(CaseAssignment)
        .where(CaseAssignment.case_id == case_id)
        .where(CaseAssignment.user_id == user_id)
    ).scalar_one_or_none()

    now = utcnow()
    if existing is not None:
        if existing.unassigned_at is None:
            raise Conflict(f"{user.full_name} is already assigned to {case.reference}")
        # Reuse the row rather than inserting a second one, so the unique constraint holds and
        # the case has one assignment record per person.
        existing.unassigned_at = None
        existing.assigned_at = now
        existing.assigned_by_id = ctx.actor_id
        existing.role_on_case = role_on_case
        assignment = existing
    else:
        assignment = CaseAssignment(
            case_id=case_id,
            user_id=user_id,
            role_on_case=role_on_case,
            assigned_at=now,
            assigned_by_id=ctx.actor_id,
        )
        db.add(assignment)

    case.last_activity_at = now
    db.flush()

    append_audit(
        db,
        ctx,
        action="case.assigned",
        resource_type="case",
        resource_id=case.id,
        resource_label=case.reference,
        case_id=case.id,
        after_state={"user": user.email, "role_on_case": role_on_case},
        result=AuditResult.success,
    )
    return assignment


def unassign_user(
    db: Session, ctx: RequestContext, case_id: uuid.UUID, *, user_id: uuid.UUID
) -> None:
    """Withdraw a user's access, keeping the record that they once had it."""
    case = get_case(db, ctx, case_id)
    assignment = db.execute(
        select(CaseAssignment)
        .where(CaseAssignment.case_id == case_id)
        .where(CaseAssignment.user_id == user_id)
        .where(CaseAssignment.unassigned_at.is_(None))
    ).scalar_one_or_none()
    if assignment is None:
        raise NotFound("Case assignment")

    if case.lead_investigator_id == user_id:
        raise Conflict("The lead investigator cannot be unassigned. Reassign the case lead first.")

    assignment.unassigned_at = utcnow()
    case.last_activity_at = utcnow()

    user = db.get(User, user_id)
    append_audit(
        db,
        ctx,
        action="case.unassigned",
        resource_type="case",
        resource_id=case.id,
        resource_label=case.reference,
        case_id=case.id,
        before_state={"user": user.email if user else str(user_id)},
        result=AuditResult.success,
    )


def set_lead_investigator(
    db: Session, ctx: RequestContext, case_id: uuid.UUID, *, user_id: uuid.UUID
) -> Case:
    case = get_case(db, ctx, case_id)
    require_open_case(case)
    user = db.get(User, user_id)
    if user is None:
        raise NotFound("User", str(user_id))

    previous_id = case.lead_investigator_id
    case.lead_investigator_id = user_id
    case.last_activity_at = utcnow()

    # The new lead must be able to reach the case, so ensure a live assignment exists.
    existing = db.execute(
        select(CaseAssignment)
        .where(CaseAssignment.case_id == case_id)
        .where(CaseAssignment.user_id == user_id)
    ).scalar_one_or_none()
    if existing is None:
        db.add(
            CaseAssignment(
                case_id=case_id,
                user_id=user_id,
                role_on_case="lead_investigator",
                assigned_at=utcnow(),
                assigned_by_id=ctx.actor_id,
            )
        )
    else:
        existing.unassigned_at = None
        existing.role_on_case = "lead_investigator"

    previous = db.get(User, previous_id) if previous_id else None
    append_audit(
        db,
        ctx,
        action="case.lead_changed",
        resource_type="case",
        resource_id=case.id,
        resource_label=case.reference,
        case_id=case.id,
        before_state={"lead_investigator": previous.email if previous else None},
        after_state={"lead_investigator": user.email},
        result=AuditResult.success,
    )
    return case


def add_note(
    db: Session, ctx: RequestContext, case_id: uuid.UUID, *, body: str, is_pinned: bool = False
) -> CaseNote:
    case = get_case(db, ctx, case_id)
    require_open_case(case)
    note = CaseNote(case_id=case_id, author_id=ctx.actor_id, body=body.strip(), is_pinned=is_pinned)
    db.add(note)
    case.last_activity_at = utcnow()
    db.flush()
    append_audit(
        db,
        ctx,
        action="case.note_added",
        resource_type="case_note",
        resource_id=note.id,
        resource_label=case.reference,
        case_id=case_id,
        result=AuditResult.success,
    )
    return note


def list_notes(db: Session, ctx: RequestContext, case_id: uuid.UUID) -> list[CaseNote]:
    get_case(db, ctx, case_id)
    return list(
        db.execute(
            select(CaseNote)
            .where(CaseNote.case_id == case_id)
            .order_by(CaseNote.is_pinned.desc(), CaseNote.created_at.desc())
        )
        .scalars()
        .all()
    )


def add_person(
    db: Session,
    ctx: RequestContext,
    case_id: uuid.UUID,
    *,
    role: CasePersonRole,
    full_name: str,
    aliases: list[str] | None = None,
    organization: str | None = None,
    email: str | None = None,
    phone: str | None = None,
    address: str | None = None,
    national_id: str | None = None,
    notes: str | None = None,
) -> CasePerson:
    case = get_case(db, ctx, case_id)
    require_open_case(case)
    person = CasePerson(
        case_id=case_id,
        role=role,
        full_name=full_name.strip(),
        aliases=aliases or [],
        organization=organization,
        email=email,
        phone=phone,
        address=address,
        national_id=national_id,
        notes=notes,
    )
    db.add(person)
    case.last_activity_at = utcnow()
    db.flush()
    append_audit(
        db,
        ctx,
        action="case.person_added",
        resource_type="case_person",
        resource_id=person.id,
        resource_label=f"{case.reference}: {person.full_name}",
        case_id=case_id,
        after_state={"role": role.value, "full_name": person.full_name},
        result=AuditResult.success,
    )
    return person


def list_persons(db: Session, ctx: RequestContext, case_id: uuid.UUID) -> list[CasePerson]:
    get_case(db, ctx, case_id)
    return list(
        db.execute(
            select(CasePerson)
            .where(CasePerson.case_id == case_id)
            .order_by(CasePerson.role, CasePerson.full_name)
        )
        .scalars()
        .all()
    )


def remove_person(
    db: Session, ctx: RequestContext, case_id: uuid.UUID, person_id: uuid.UUID
) -> None:
    case = get_case(db, ctx, case_id)
    require_open_case(case)
    person = db.get(CasePerson, person_id)
    if person is None or person.case_id != case_id:
        raise NotFound("Case person", str(person_id))
    label = person.full_name
    db.delete(person)
    append_audit(
        db,
        ctx,
        action="case.person_removed",
        resource_type="case_person",
        resource_id=person_id,
        resource_label=f"{case.reference}: {label}",
        case_id=case_id,
        before_state={"full_name": label, "role": person.role.value},
        result=AuditResult.success,
    )


def list_status_history(
    db: Session, ctx: RequestContext, case_id: uuid.UUID
) -> list[CaseStatusHistory]:
    get_case(db, ctx, case_id)
    return list(
        db.execute(
            select(CaseStatusHistory)
            .where(CaseStatusHistory.case_id == case_id)
            .order_by(CaseStatusHistory.created_at)
        )
        .scalars()
        .all()
    )


def touch_activity(db: Session, case_id: uuid.UUID) -> None:
    """Mark a case as recently active.

    Called by any operation that constitutes work on the case, so the dashboard can order
    cases by genuine activity rather than by when their row was last written.
    """
    case = db.get(Case, case_id)
    if case is not None:
        case.last_activity_at = utcnow()


def status_counts(db: Session, ctx: RequestContext) -> dict[str, int]:
    """Case totals by status, scoped to what the actor may see."""
    stmt = scope_counts(select(Case.status, func.count()).group_by(Case.status), ctx)
    counts = {status.value: 0 for status in CaseStatus}
    for status, count in db.execute(stmt).all():
        counts[status.value] = count
    counts["total"] = sum(counts[status.value] for status in CaseStatus)
    return counts


def scope_counts[T: Select[Any]](stmt: T, ctx: RequestContext) -> T:
    """Apply case scoping to an aggregate over ``cases``.

    Aggregates are the easiest place to leak: a dashboard count computed without scoping tells
    an unauthorised user how many cases exist, so the same predicate is applied here as to the
    list queries.
    """
    if has_global_case_access(ctx):
        return stmt
    return apply_case_scope(stmt, ctx)
