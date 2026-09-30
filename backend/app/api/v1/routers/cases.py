"""Case endpoints."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session

from app.core.context import RequestContext
from app.core.pagination import Page, PageParams, page_params
from app.db.session import get_db
from app.models.enums import CaseStatus, IncidentType, Permission, Severity
from app.schemas.case import (
    CaseAssignmentOut,
    CaseAssignRequest,
    CaseCreate,
    CaseDetailOut,
    CaseNoteCreate,
    CaseNoteOut,
    CasePersonCreate,
    CasePersonOut,
    CaseStatusChange,
    CaseStatusHistoryOut,
    CaseSummaryOut,
    CaseUpdate,
    SetLeadRequest,
)
from app.schemas.common import OperationResult
from app.security.deps import require
from app.services import case_service

router = APIRouter(prefix="/cases", tags=["cases"])

DbSession = Annotated[Session, Depends(get_db)]


@router.get("", response_model=Page[CaseSummaryOut], summary="List cases")
def list_cases(
    db: DbSession,
    ctx: Annotated[RequestContext, Depends(require(Permission.case_read))],
    params: Annotated[PageParams, Depends(page_params)],
    status_filter: Annotated[list[CaseStatus] | None, Query(alias="status")] = None,
    severity: Annotated[list[Severity] | None, Query()] = None,
    incident_type: Annotated[list[IncidentType] | None, Query()] = None,
    lead_investigator_id: uuid.UUID | None = None,
    assigned_to_id: uuid.UUID | None = None,
    search: Annotated[str | None, Query(max_length=200)] = None,
    legal_hold: bool | None = None,
    opened_after: datetime | None = None,
    opened_before: datetime | None = None,
    sort: str = "last_activity",
    descending: bool = True,
) -> Page[CaseSummaryOut]:
    cases, total = case_service.list_cases(
        db,
        ctx,
        params,
        status=status_filter,
        severity=severity,
        incident_type=incident_type,
        lead_investigator_id=lead_investigator_id,
        assigned_to_id=assigned_to_id,
        search=search,
        legal_hold=legal_hold,
        opened_after=opened_after,
        opened_before=opened_before,
        sort=sort,
        descending=descending,
    )
    return Page.build([CaseSummaryOut.model_validate(case) for case in cases], total, params)


@router.get("/status-counts", summary="Case totals by status")
def status_counts(
    db: DbSession,
    ctx: Annotated[RequestContext, Depends(require(Permission.case_read))],
) -> dict[str, int]:
    return case_service.status_counts(db, ctx)


@router.post(
    "",
    response_model=CaseDetailOut,
    status_code=status.HTTP_201_CREATED,
    summary="Register a case",
)
def create_case(
    payload: CaseCreate,
    db: DbSession,
    ctx: Annotated[RequestContext, Depends(require(Permission.case_create))],
) -> CaseDetailOut:
    case = case_service.create_case(
        db,
        ctx,
        title=payload.title,
        summary=payload.summary,
        incident_type=payload.incident_type,
        severity=payload.severity,
        incident_occurred_at=payload.incident_occurred_at,
        reported_at=payload.reported_at,
        lead_investigator_id=payload.lead_investigator_id,
        jurisdiction=payload.jurisdiction,
        organization=payload.organization,
        external_reference=payload.external_reference,
        classification=payload.classification,
        tags=payload.tags,
        status=payload.status,
    )
    db.commit()
    db.refresh(case)
    return CaseDetailOut.model_validate(case)


@router.get("/{case_id}", response_model=CaseDetailOut, summary="Case detail")
def get_case(
    case_id: uuid.UUID,
    db: DbSession,
    ctx: Annotated[RequestContext, Depends(require(Permission.case_read))],
) -> CaseDetailOut:
    case = case_service.get_case(db, ctx, case_id)
    return CaseDetailOut.model_validate(case)


@router.patch("/{case_id}", response_model=CaseDetailOut, summary="Update a case")
def update_case(
    case_id: uuid.UUID,
    payload: CaseUpdate,
    db: DbSession,
    ctx: Annotated[RequestContext, Depends(require(Permission.case_update))],
) -> CaseDetailOut:
    # ``exclude_unset`` is what makes this a genuine partial update: a field absent from the
    # request body is left alone, rather than being overwritten with null.
    case = case_service.update_case(db, ctx, case_id, payload.model_dump(exclude_unset=True))
    db.commit()
    db.refresh(case)
    return CaseDetailOut.model_validate(case)


@router.post("/{case_id}/status", response_model=CaseDetailOut, summary="Change case status")
def change_status(
    case_id: uuid.UUID,
    payload: CaseStatusChange,
    db: DbSession,
    ctx: Annotated[RequestContext, Depends(require(Permission.case_update))],
) -> CaseDetailOut:
    case = case_service.change_status(
        db,
        ctx,
        case_id,
        to_status=payload.status,
        reason=payload.reason,
        closure_summary=payload.closure_summary,
    )
    db.commit()
    db.refresh(case)
    return CaseDetailOut.model_validate(case)


@router.get(
    "/{case_id}/status-history",
    response_model=list[CaseStatusHistoryOut],
    summary="Case status history",
)
def status_history(
    case_id: uuid.UUID,
    db: DbSession,
    ctx: Annotated[RequestContext, Depends(require(Permission.case_read))],
) -> list[CaseStatusHistoryOut]:
    return [
        CaseStatusHistoryOut.model_validate(row)
        for row in case_service.list_status_history(db, ctx, case_id)
    ]


@router.post(
    "/{case_id}/assignments",
    response_model=CaseAssignmentOut,
    status_code=status.HTTP_201_CREATED,
    summary="Assign a user to a case",
)
def assign_user(
    case_id: uuid.UUID,
    payload: CaseAssignRequest,
    db: DbSession,
    ctx: Annotated[RequestContext, Depends(require(Permission.case_assign))],
) -> CaseAssignmentOut:
    assignment = case_service.assign_user(
        db, ctx, case_id, user_id=payload.user_id, role_on_case=payload.role_on_case
    )
    db.commit()
    db.refresh(assignment)
    return CaseAssignmentOut.model_validate(assignment)


@router.delete(
    "/{case_id}/assignments/{user_id}",
    response_model=OperationResult,
    summary="Remove a user from a case",
)
def unassign_user(
    case_id: uuid.UUID,
    user_id: uuid.UUID,
    db: DbSession,
    ctx: Annotated[RequestContext, Depends(require(Permission.case_assign))],
) -> OperationResult:
    case_service.unassign_user(db, ctx, case_id, user_id=user_id)
    db.commit()
    return OperationResult(message="Assignment withdrawn")


@router.put("/{case_id}/lead", response_model=CaseDetailOut, summary="Set the case lead")
def set_lead(
    case_id: uuid.UUID,
    payload: SetLeadRequest,
    db: DbSession,
    ctx: Annotated[RequestContext, Depends(require(Permission.case_assign))],
) -> CaseDetailOut:
    case = case_service.set_lead_investigator(db, ctx, case_id, user_id=payload.user_id)
    db.commit()
    db.refresh(case)
    return CaseDetailOut.model_validate(case)


@router.get("/{case_id}/notes", response_model=list[CaseNoteOut], summary="Case notes")
def list_notes(
    case_id: uuid.UUID,
    db: DbSession,
    ctx: Annotated[RequestContext, Depends(require(Permission.case_read))],
) -> list[CaseNoteOut]:
    return [CaseNoteOut.model_validate(note) for note in case_service.list_notes(db, ctx, case_id)]


@router.post(
    "/{case_id}/notes",
    response_model=CaseNoteOut,
    status_code=status.HTTP_201_CREATED,
    summary="Add a case note",
)
def add_note(
    case_id: uuid.UUID,
    payload: CaseNoteCreate,
    db: DbSession,
    ctx: Annotated[RequestContext, Depends(require(Permission.case_update))],
) -> CaseNoteOut:
    note = case_service.add_note(db, ctx, case_id, body=payload.body, is_pinned=payload.is_pinned)
    db.commit()
    db.refresh(note)
    return CaseNoteOut.model_validate(note)


@router.get(
    "/{case_id}/persons",
    response_model=list[CasePersonOut],
    summary="People and organisations linked to a case",
)
def list_persons(
    case_id: uuid.UUID,
    db: DbSession,
    ctx: Annotated[RequestContext, Depends(require(Permission.case_read))],
) -> list[CasePersonOut]:
    return [
        CasePersonOut.model_validate(person)
        for person in case_service.list_persons(db, ctx, case_id)
    ]


@router.post(
    "/{case_id}/persons",
    response_model=CasePersonOut,
    status_code=status.HTTP_201_CREATED,
    summary="Add a person to a case",
)
def add_person(
    case_id: uuid.UUID,
    payload: CasePersonCreate,
    db: DbSession,
    ctx: Annotated[RequestContext, Depends(require(Permission.case_update))],
) -> CasePersonOut:
    person = case_service.add_person(
        db,
        ctx,
        case_id,
        role=payload.role,
        full_name=payload.full_name,
        aliases=payload.aliases,
        organization=payload.organization,
        email=payload.email,
        phone=payload.phone,
        address=payload.address,
        national_id=payload.national_id,
        notes=payload.notes,
    )
    db.commit()
    db.refresh(person)
    return CasePersonOut.model_validate(person)


@router.delete(
    "/{case_id}/persons/{person_id}",
    response_model=OperationResult,
    summary="Remove a person from a case",
)
def remove_person(
    case_id: uuid.UUID,
    person_id: uuid.UUID,
    db: DbSession,
    ctx: Annotated[RequestContext, Depends(require(Permission.case_update))],
) -> OperationResult:
    case_service.remove_person(db, ctx, case_id, person_id)
    db.commit()
    return OperationResult(message="Person removed from case")
