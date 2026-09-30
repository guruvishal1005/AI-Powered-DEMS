"""Administration and compliance endpoints."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session

from app.core.context import RequestContext
from app.core.pagination import Page, PageParams, page_params
from app.db.session import get_db
from app.jobs.queue import DbTaskQueue
from app.models.enums import JobStatus, Permission, UserStatus
from app.schemas.admin import (
    ApiTokenCreate,
    ApiTokenCreatedOut,
    ApiTokenOut,
    BackupOut,
    JobOut,
    JobStatsOut,
    LegalHoldCreate,
    LegalHoldOut,
    LegalHoldRelease,
    PeriodicTaskOut,
    PeriodicTaskUpdate,
    PermissionOut,
    ResetPasswordRequest,
    RetentionPolicyCreate,
    RetentionPolicyOut,
    RoleDetailOut,
    RoleUpdate,
    SystemHealthOut,
    SystemSettingOut,
    SystemSettingUpdate,
    UserCreate,
    UserDetailOut,
    UserSummaryOut,
    UserUpdate,
)
from app.schemas.common import OperationResult
from app.security.deps import CurrentUser, require
from app.services import admin_service

router = APIRouter(prefix="/admin", tags=["administration"])

DbSession = Annotated[Session, Depends(get_db)]


@router.get("/users", response_model=Page[UserSummaryOut], summary="List users")
def list_users(
    db: DbSession,
    ctx: Annotated[RequestContext, Depends(require(Permission.user_read))],
    params: Annotated[PageParams, Depends(page_params)],
    status_filter: Annotated[list[UserStatus] | None, Query(alias="status")] = None,
    search: Annotated[str | None, Query(max_length=200)] = None,
) -> Page[UserSummaryOut]:
    rows, total = admin_service.list_users(db, ctx, params, status=status_filter, search=search)
    return Page.build([UserSummaryOut.model_validate(row) for row in rows], total, params)


@router.post(
    "/users",
    response_model=UserDetailOut,
    status_code=status.HTTP_201_CREATED,
    summary="Create a user",
)
def create_user(
    payload: UserCreate,
    db: DbSession,
    ctx: Annotated[RequestContext, Depends(require(Permission.user_manage))],
) -> UserDetailOut:
    user = admin_service.create_user(
        db,
        ctx,
        email=str(payload.email),
        full_name=payload.full_name,
        password=payload.password,
        role_slugs=payload.role_slugs,
        job_title=payload.job_title,
        department=payload.department,
        badge_number=payload.badge_number,
        phone=payload.phone,
        must_change_password=payload.must_change_password,
    )
    db.commit()
    db.refresh(user)
    return UserDetailOut.model_validate(user)


@router.get("/users/{user_id}", response_model=UserDetailOut, summary="User detail")
def get_user(
    user_id: uuid.UUID,
    db: DbSession,
    ctx: Annotated[RequestContext, Depends(require(Permission.user_read))],
) -> UserDetailOut:
    return UserDetailOut.model_validate(admin_service.get_user(db, user_id))


@router.patch("/users/{user_id}", response_model=UserDetailOut, summary="Update a user")
def update_user(
    user_id: uuid.UUID,
    payload: UserUpdate,
    db: DbSession,
    ctx: Annotated[RequestContext, Depends(require(Permission.user_manage))],
) -> UserDetailOut:
    user = admin_service.update_user(db, ctx, user_id, payload.model_dump(exclude_unset=True))
    db.commit()
    db.refresh(user)
    return UserDetailOut.model_validate(user)


@router.post(
    "/users/{user_id}/password",
    response_model=OperationResult,
    summary="Reset a user's password",
)
def reset_password(
    user_id: uuid.UUID,
    payload: ResetPasswordRequest,
    db: DbSession,
    ctx: Annotated[RequestContext, Depends(require(Permission.user_manage))],
) -> OperationResult:
    admin_service.reset_password(
        db,
        ctx,
        user_id,
        new_password=payload.new_password,
        must_change_password=payload.must_change_password,
    )
    db.commit()
    return OperationResult(message="Password reset; existing sessions have been revoked")


@router.get("/roles", response_model=list[RoleDetailOut], summary="List roles")
def list_roles(
    db: DbSession,
    ctx: Annotated[RequestContext, Depends(require(Permission.user_read))],
) -> list[RoleDetailOut]:
    return [
        RoleDetailOut.model_validate(role).model_copy(update={"user_count": count})
        for role, count in admin_service.list_roles(db)
    ]


@router.patch("/roles/{role_id}", response_model=RoleDetailOut, summary="Update a role")
def update_role(
    role_id: uuid.UUID,
    payload: RoleUpdate,
    db: DbSession,
    ctx: Annotated[RequestContext, Depends(require(Permission.role_manage))],
) -> RoleDetailOut:
    role = admin_service.update_role(db, ctx, role_id, payload.model_dump(exclude_unset=True))
    db.commit()
    db.refresh(role)
    return RoleDetailOut.model_validate(role).model_copy(update={"user_count": 0})


@router.get("/permissions", response_model=list[PermissionOut], summary="Permission catalogue")
def list_permissions(
    db: DbSession,
    ctx: Annotated[RequestContext, Depends(require(Permission.user_read))],
) -> list[PermissionOut]:
    return [PermissionOut.model_validate(row) for row in admin_service.list_permissions(db)]


@router.get("/settings", response_model=list[SystemSettingOut], summary="System settings")
def list_settings(
    db: DbSession,
    ctx: Annotated[RequestContext, Depends(require(Permission.system_read))],
) -> list[SystemSettingOut]:
    return [SystemSettingOut.model_validate(row) for row in admin_service.list_settings(db)]


@router.patch("/settings/{key}", response_model=SystemSettingOut, summary="Update a setting")
def update_setting(
    key: str,
    payload: SystemSettingUpdate,
    db: DbSession,
    ctx: Annotated[RequestContext, Depends(require(Permission.system_configure))],
) -> SystemSettingOut:
    row = admin_service.update_setting(db, ctx, key, payload.value)
    db.commit()
    return SystemSettingOut.model_validate(row)


@router.get("/retention", response_model=list[RetentionPolicyOut], summary="Retention policies")
def list_retention(
    db: DbSession,
    ctx: Annotated[RequestContext, Depends(require(Permission.retention_manage))],
) -> list[RetentionPolicyOut]:
    return [
        RetentionPolicyOut.model_validate(row) for row in admin_service.list_retention_policies(db)
    ]


@router.post(
    "/retention",
    response_model=RetentionPolicyOut,
    status_code=status.HTTP_201_CREATED,
    summary="Create a retention policy",
)
def create_retention(
    payload: RetentionPolicyCreate,
    db: DbSession,
    ctx: Annotated[RequestContext, Depends(require(Permission.retention_manage))],
) -> RetentionPolicyOut:
    policy = admin_service.create_retention_policy(db, ctx, payload.model_dump())
    db.commit()
    db.refresh(policy)
    return RetentionPolicyOut.model_validate(policy)


@router.get("/legal-holds", response_model=list[LegalHoldOut], summary="Legal holds")
def list_holds(
    db: DbSession,
    ctx: Annotated[RequestContext, Depends(require(Permission.retention_manage))],
    active_only: bool = True,
) -> list[LegalHoldOut]:
    return [
        LegalHoldOut.model_validate(row)
        for row in admin_service.list_legal_holds(db, active_only=active_only)
    ]


@router.post(
    "/legal-holds",
    response_model=LegalHoldOut,
    status_code=status.HTTP_201_CREATED,
    summary="Apply a legal hold",
)
def apply_hold(
    payload: LegalHoldCreate,
    db: DbSession,
    ctx: Annotated[RequestContext, Depends(require(Permission.retention_manage))],
) -> LegalHoldOut:
    hold = admin_service.apply_legal_hold(
        db,
        ctx,
        case_id=payload.case_id,
        evidence_id=payload.evidence_id,
        reason=payload.reason,
        authority=payload.authority,
        reference=payload.reference,
    )
    db.commit()
    db.refresh(hold)
    return LegalHoldOut.model_validate(hold)


@router.post(
    "/legal-holds/{hold_id}/release", response_model=LegalHoldOut, summary="Release a hold"
)
def release_hold(
    hold_id: uuid.UUID,
    payload: LegalHoldRelease,
    db: DbSession,
    ctx: Annotated[RequestContext, Depends(require(Permission.retention_manage))],
) -> LegalHoldOut:
    hold = admin_service.release_legal_hold(db, ctx, hold_id, reason=payload.reason)
    db.commit()
    db.refresh(hold)
    return LegalHoldOut.model_validate(hold)


@router.get("/jobs", response_model=Page[JobOut], summary="Job queue")
def list_jobs(
    db: DbSession,
    ctx: Annotated[RequestContext, Depends(require(Permission.job_read))],
    params: Annotated[PageParams, Depends(page_params)],
    status_filter: Annotated[list[JobStatus] | None, Query(alias="status")] = None,
    task: Annotated[str | None, Query(max_length=64)] = None,
) -> Page[JobOut]:
    rows, total = admin_service.list_jobs(db, params, status=status_filter, task=task)
    return Page.build([JobOut.model_validate(row) for row in rows], total, params)


@router.get("/jobs/stats", response_model=JobStatsOut, summary="Queue statistics")
def job_stats(
    db: DbSession,
    ctx: Annotated[RequestContext, Depends(require(Permission.job_read))],
) -> JobStatsOut:
    return JobStatsOut.model_validate(DbTaskQueue().stats(db))


@router.post("/jobs/{job_id}/retry", response_model=JobOut, summary="Retry a job")
def retry_job(
    job_id: uuid.UUID,
    db: DbSession,
    ctx: Annotated[RequestContext, Depends(require(Permission.job_manage))],
) -> JobOut:
    job = admin_service.retry_job(db, ctx, job_id)
    db.commit()
    return JobOut.model_validate(job)


@router.post("/jobs/{job_id}/cancel", response_model=JobOut, summary="Cancel a job")
def cancel_job(
    job_id: uuid.UUID,
    db: DbSession,
    ctx: Annotated[RequestContext, Depends(require(Permission.job_manage))],
) -> JobOut:
    job = admin_service.cancel_job(db, ctx, job_id)
    db.commit()
    return JobOut.model_validate(job)


@router.get("/schedule", response_model=list[PeriodicTaskOut], summary="Periodic tasks")
def list_schedule(
    db: DbSession,
    ctx: Annotated[RequestContext, Depends(require(Permission.job_read))],
) -> list[PeriodicTaskOut]:
    return [PeriodicTaskOut.model_validate(row) for row in admin_service.list_periodic_tasks(db)]


@router.patch("/schedule/{task_id}", response_model=PeriodicTaskOut, summary="Update a schedule")
def update_schedule(
    task_id: uuid.UUID,
    payload: PeriodicTaskUpdate,
    db: DbSession,
    ctx: Annotated[RequestContext, Depends(require(Permission.job_manage))],
) -> PeriodicTaskOut:
    row = admin_service.update_periodic_task(
        db, ctx, task_id, payload.model_dump(exclude_unset=True)
    )
    db.commit()
    return PeriodicTaskOut.model_validate(row)


@router.get("/backups", response_model=list[BackupOut], summary="Backup history")
def list_backups(
    db: DbSession,
    ctx: Annotated[RequestContext, Depends(require(Permission.backup_manage))],
) -> list[BackupOut]:
    return [BackupOut.model_validate(row) for row in admin_service.list_backups(db)]


@router.post("/backups", response_model=OperationResult, summary="Trigger a backup")
def trigger_backup(
    db: DbSession,
    ctx: Annotated[RequestContext, Depends(require(Permission.backup_manage))],
) -> OperationResult:
    job = admin_service.enqueue_backup(db, ctx)
    db.commit()
    if job is None:
        return OperationResult(message="A backup is already queued or running")
    return OperationResult(message=f"Backup queued as job {job.id}")


@router.get("/health", response_model=SystemHealthOut, summary="System health")
def health(
    db: DbSession,
    ctx: Annotated[RequestContext, Depends(require(Permission.system_read))],
) -> SystemHealthOut:
    return SystemHealthOut.model_validate(admin_service.system_health(db))


@router.get("/tokens", response_model=list[ApiTokenOut], summary="API tokens")
def list_tokens(
    db: DbSession,
    user: CurrentUser,
    ctx: Annotated[RequestContext, Depends(require(Permission.case_read))],
) -> list[ApiTokenOut]:
    return [ApiTokenOut.model_validate(row) for row in admin_service.list_api_tokens(db, user.id)]


@router.post(
    "/tokens",
    response_model=ApiTokenCreatedOut,
    status_code=status.HTTP_201_CREATED,
    summary="Create an API token",
)
def create_token(
    payload: ApiTokenCreate,
    db: DbSession,
    user: CurrentUser,
    ctx: Annotated[RequestContext, Depends(require(Permission.case_read))],
) -> ApiTokenCreatedOut:
    token, secret = admin_service.create_api_token(
        db,
        ctx,
        user.id,
        name=payload.name,
        scopes=payload.scopes,
        expires_at=payload.expires_at,
    )
    db.commit()
    return ApiTokenCreatedOut(
        id=token.id,
        name=token.name,
        prefix=token.prefix,
        token=secret,
        scopes=list(token.scopes or []),
        expires_at=token.expires_at,
        created_at=token.created_at,
    )


@router.delete("/tokens/{token_id}", response_model=OperationResult, summary="Revoke an API token")
def revoke_token(
    token_id: uuid.UUID,
    db: DbSession,
    user: CurrentUser,
    ctx: Annotated[RequestContext, Depends(require(Permission.case_read))],
) -> OperationResult:
    admin_service.revoke_api_token(db, ctx, token_id, user.id)
    db.commit()
    return OperationResult(message="Token revoked")
