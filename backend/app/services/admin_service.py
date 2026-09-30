"""Administration: users, roles, settings, retention, jobs, health and tokens."""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session, joinedload

from app import __version__
from app.audit.writer import append_audit, append_custody
from app.core.clock import utcnow
from app.core.config import settings
from app.core.context import RequestContext
from app.core.errors import Conflict, NotFound, ValidationFailed
from app.core.pagination import PageParams, paginate
from app.jobs.queue import DbTaskQueue, enqueue
from app.jobs.registry import all_tasks
from app.models.enums import (
    AuditResult,
    CustodyAction,
    DispositionAction,
    JobStatus,
    UserStatus,
)
from app.models.ops import (
    Backup,
    Job,
    LegalHold,
    PeriodicTask,
    RetentionPolicy,
    SystemHealthSample,
    SystemSetting,
)
from app.models.user import ApiToken, PermissionRecord, Role, User, UserSession
from app.security.crypto import generate_token, hash_password, hash_token
from app.security.permissions import PERMISSION_BY_CODE
from app.services import case_service, evidence_service
from app.storage.local import get_storage

DEFAULT_SETTINGS: tuple[dict[str, Any], ...] = (
    {
        "key": "session.max_concurrent",
        "value": {"n": 8},
        "category": "security",
        "label": "Maximum concurrent sessions per user",
        "description": "Older sessions are not revoked automatically; this is an advisory cap.",
    },
    {
        "key": "retention.warn_days",
        "value": {"n": 30},
        "category": "retention",
        "label": "Default retention warning window (days)",
        "description": "How far in advance approaching expiry raises an alert.",
    },
    {
        "key": "analysis.auto_run",
        "value": {"enabled": True},
        "category": "analysis",
        "label": "Run analyzers on ingest",
        "description": "When disabled, evidence is preserved but not analysed until requested.",
    },
)


def list_users(
    db: Session,
    ctx: RequestContext,
    params: PageParams,
    *,
    status: list[UserStatus] | None = None,
    search: str | None = None,
) -> tuple[list[User], int]:
    stmt = select(User).options(joinedload(User.roles)).order_by(User.full_name)
    if status:
        stmt = stmt.where(User.status.in_(status))
    if search:
        pattern = f"%{search.strip()}%"
        stmt = stmt.where(User.email.ilike(pattern) | User.full_name.ilike(pattern))
    return paginate(db, stmt, params)


def get_user(db: Session, user_id: uuid.UUID) -> User:
    user = (
        db.execute(select(User).options(joinedload(User.roles)).where(User.id == user_id))
        .unique()
        .scalar_one_or_none()
    )
    if user is None:
        raise NotFound("User", str(user_id))
    return user


def create_user(
    db: Session,
    ctx: RequestContext,
    *,
    email: str,
    full_name: str,
    password: str,
    role_slugs: list[str],
    job_title: str | None = None,
    department: str | None = None,
    badge_number: str | None = None,
    phone: str | None = None,
    must_change_password: bool = True,
) -> User:
    existing = db.execute(select(User).where(User.email == email)).scalar_one_or_none()
    if existing is not None:
        raise Conflict(f"An account already exists for {email}")
    user = User(
        email=email,
        full_name=full_name,
        password_hash=hash_password(password),
        job_title=job_title,
        department=department,
        badge_number=badge_number,
        phone=phone,
        must_change_password=must_change_password,
        created_by_id=ctx.actor_id,
        password_changed_at=utcnow(),
    )
    user.roles = _load_roles(db, role_slugs)
    db.add(user)
    db.flush()
    append_audit(
        db,
        ctx,
        action="user.created",
        resource_type="user",
        resource_id=user.id,
        resource_label=user.email,
        after_state={"roles": role_slugs},
        result=AuditResult.success,
    )
    return user


def update_user(
    db: Session, ctx: RequestContext, user_id: uuid.UUID, changes: dict[str, Any]
) -> User:
    user = get_user(db, user_id)
    if user.is_superuser and changes.get("status") in {
        UserStatus.suspended,
        UserStatus.disabled,
    }:
        raise ValidationFailed("A protected account cannot be suspended or disabled")
    before = {"status": user.status.value, "roles": [role.slug for role in user.roles]}
    for field in ("full_name", "job_title", "department", "badge_number", "phone", "timezone"):
        if field in changes and changes[field] is not None:
            setattr(user, field, changes[field])
    if changes.get("status") is not None:
        user.status = UserStatus(changes["status"])
    if changes.get("role_slugs") is not None:
        if user.is_superuser and "administrator" not in changes["role_slugs"]:
            raise ValidationFailed("A protected account must retain the administrator role")
        user.roles = _load_roles(db, changes["role_slugs"])
    append_audit(
        db,
        ctx,
        action="user.updated",
        resource_type="user",
        resource_id=user.id,
        resource_label=user.email,
        before_state=before,
        after_state={"status": user.status.value, "roles": [role.slug for role in user.roles]},
        result=AuditResult.success,
    )
    return user


def reset_password(
    db: Session,
    ctx: RequestContext,
    user_id: uuid.UUID,
    *,
    new_password: str,
    must_change_password: bool,
) -> User:
    user = get_user(db, user_id)
    user.password_hash = hash_password(new_password)
    user.must_change_password = must_change_password
    user.password_changed_at = utcnow()
    user.failed_login_count = 0
    user.locked_until = None
    db.execute(
        select(UserSession)
        .where(UserSession.user_id == user.id)
        .where(UserSession.revoked_at.is_(None))
    )
    for session_row in (
        db.execute(
            select(UserSession)
            .where(UserSession.user_id == user.id)
            .where(UserSession.revoked_at.is_(None))
        )
        .scalars()
        .all()
    ):
        session_row.revoked_at = utcnow()
        session_row.revoked_reason = "password_reset"
    append_audit(
        db,
        ctx,
        action="user.password_reset",
        resource_type="user",
        resource_id=user.id,
        resource_label=user.email,
        result=AuditResult.success,
    )
    return user


def list_roles(db: Session) -> list[tuple[Role, int]]:
    counts = dict(
        db.execute(
            select(Role.id, func.count(User.id))
            .select_from(Role)
            .outerjoin(Role.users)
            .group_by(Role.id)
        ).all()
    )
    roles = list(
        db.execute(select(Role).options(joinedload(Role.permissions)).order_by(Role.rank.desc()))
        .unique()
        .scalars()
        .all()
    )
    return [(role, int(counts.get(role.id, 0))) for role in roles]


def list_permissions(db: Session) -> list[PermissionRecord]:
    return list(
        db.execute(
            select(PermissionRecord).order_by(PermissionRecord.category, PermissionRecord.code)
        ).scalars()
    )


def update_role(
    db: Session, ctx: RequestContext, role_id: uuid.UUID, changes: dict[str, Any]
) -> Role:
    role = (
        db.execute(select(Role).options(joinedload(Role.permissions)).where(Role.id == role_id))
        .unique()
        .scalar_one_or_none()
    )
    if role is None:
        raise NotFound("Role", str(role_id))
    before = [perm.code for perm in role.permissions]
    if changes.get("name"):
        role.name = changes["name"]
    if changes.get("description") is not None:
        role.description = changes["description"]
    if changes.get("permission_codes") is not None:
        codes = list(changes["permission_codes"])
        unknown = [code for code in codes if code not in {p.value for p in PERMISSION_BY_CODE}]
        if unknown:
            raise ValidationFailed(f"Unknown permission(s): {', '.join(unknown)}")
        records = list(
            db.execute(select(PermissionRecord).where(PermissionRecord.code.in_(codes))).scalars()
        )
        role.permissions = records
    append_audit(
        db,
        ctx,
        action="role.updated",
        resource_type="role",
        resource_id=role.id,
        resource_label=role.slug,
        before_state={"permissions": before},
        after_state={"permissions": [perm.code for perm in role.permissions]},
        result=AuditResult.success,
    )
    return role


def ensure_settings(db: Session) -> None:
    existing = {row.key for row in db.execute(select(SystemSetting.key)).scalars()}
    now = utcnow()
    for spec in DEFAULT_SETTINGS:
        if spec["key"] in existing:
            continue
        db.add(
            SystemSetting(
                key=spec["key"],
                value=spec["value"],
                category=spec["category"],
                label=spec["label"],
                description=spec["description"],
                updated_at=now,
            )
        )
    db.flush()


def list_settings(db: Session) -> list[SystemSetting]:
    ensure_settings(db)
    return list(
        db.execute(
            select(SystemSetting).order_by(SystemSetting.category, SystemSetting.key)
        ).scalars()
    )


def update_setting(
    db: Session, ctx: RequestContext, key: str, value: dict[str, Any]
) -> SystemSetting:
    ensure_settings(db)
    row = db.execute(select(SystemSetting).where(SystemSetting.key == key)).scalar_one_or_none()
    if row is None:
        raise NotFound("Setting", key)
    if row.is_sensitive:
        raise ValidationFailed("This setting cannot be changed through the API")
    before = dict(row.value)
    row.value = value
    row.updated_at = utcnow()
    row.updated_by_id = ctx.actor_id
    append_audit(
        db,
        ctx,
        action="setting.updated",
        resource_type="setting",
        resource_id=row.id,
        resource_label=row.key,
        before_state=before,
        after_state=value,
        result=AuditResult.success,
    )
    return row


def list_retention_policies(db: Session) -> list[RetentionPolicy]:
    return list(db.execute(select(RetentionPolicy).order_by(RetentionPolicy.name)).scalars())


def create_retention_policy(
    db: Session, ctx: RequestContext, payload: dict[str, Any]
) -> RetentionPolicy:
    if payload.get("is_default"):
        for row in db.execute(
            select(RetentionPolicy).where(RetentionPolicy.is_default.is_(True))
        ).scalars():
            row.is_default = False
    policy = RetentionPolicy(
        name=payload["name"],
        description=payload.get("description") or "",
        criteria=payload.get("criteria") or {},
        retention_days=payload["retention_days"],
        disposition_action=DispositionAction(payload.get("disposition_action", "review")),
        requires_review=payload.get("requires_review", True),
        warn_days_before=payload.get("warn_days_before", 30),
        is_default=payload.get("is_default", False),
        enabled=payload.get("enabled", True),
        created_by_id=ctx.actor_id,
    )
    db.add(policy)
    db.flush()
    append_audit(
        db,
        ctx,
        action="retention.created",
        resource_type="retention_policy",
        resource_id=policy.id,
        resource_label=policy.name,
        result=AuditResult.success,
    )
    return policy


def apply_legal_hold(
    db: Session,
    ctx: RequestContext,
    *,
    case_id: uuid.UUID | None,
    evidence_id: uuid.UUID | None,
    reason: str,
    authority: str | None,
    reference: str | None,
) -> LegalHold:
    if case_id is None and evidence_id is None:
        raise ValidationFailed("A legal hold must name a case or an evidence item")
    if case_id:
        case = case_service.require_case_access(db, ctx, case_id)
        case.legal_hold = True
    if evidence_id:
        evidence = evidence_service.get_evidence(db, ctx, evidence_id)
        evidence.legal_hold = True
        append_custody(
            db,
            ctx,
            evidence,
            action=CustodyAction.legal_hold_applied,
            reason=reason,
        )
        case_id = evidence.case_id
    hold = LegalHold(
        reference=reference or f"LH-{utcnow().strftime('%Y%m%d%H%M%S')}",
        case_id=case_id,
        evidence_id=evidence_id,
        reason=reason,
        authority=authority,
        applied_by_id=ctx.actor_id,
    )
    db.add(hold)
    db.flush()
    append_audit(
        db,
        ctx,
        action="legal_hold.applied",
        resource_type="legal_hold",
        resource_id=hold.id,
        resource_label=hold.reference,
        case_id=case_id,
        reason=reason,
        result=AuditResult.success,
    )
    return hold


def release_legal_hold(
    db: Session, ctx: RequestContext, hold_id: uuid.UUID, *, reason: str
) -> LegalHold:
    hold = db.get(LegalHold, hold_id)
    if hold is None:
        raise NotFound("LegalHold", str(hold_id))
    if hold.released_at is not None:
        raise Conflict("This legal hold has already been released")
    hold.released_at = utcnow()
    hold.released_by_id = ctx.actor_id
    hold.release_reason = reason
    if hold.evidence_id:
        evidence = evidence_service.get_evidence(db, ctx, hold.evidence_id)
        still = db.execute(
            select(LegalHold)
            .where(LegalHold.evidence_id == hold.evidence_id)
            .where(LegalHold.released_at.is_(None))
            .where(LegalHold.id != hold.id)
        ).scalar_one_or_none()
        if still is None:
            evidence.legal_hold = False
        append_custody(db, ctx, evidence, action=CustodyAction.legal_hold_released, reason=reason)
    if hold.case_id:
        still_case = db.execute(
            select(LegalHold)
            .where(LegalHold.case_id == hold.case_id)
            .where(LegalHold.released_at.is_(None))
            .where(LegalHold.id != hold.id)
        ).scalar_one_or_none()
        if still_case is None:
            case = case_service.require_case_access(db, ctx, hold.case_id)
            case.legal_hold = False
    append_audit(
        db,
        ctx,
        action="legal_hold.released",
        resource_type="legal_hold",
        resource_id=hold.id,
        resource_label=hold.reference,
        case_id=hold.case_id,
        reason=reason,
        result=AuditResult.success,
    )
    return hold


def list_legal_holds(db: Session, *, active_only: bool = True) -> list[LegalHold]:
    stmt = select(LegalHold).order_by(LegalHold.created_at.desc())
    if active_only:
        stmt = stmt.where(LegalHold.released_at.is_(None))
    return list(db.execute(stmt).scalars().all())


def list_jobs(
    db: Session,
    params: PageParams,
    *,
    status: list[JobStatus] | None = None,
    task: str | None = None,
) -> tuple[list[Job], int]:
    stmt = select(Job)
    if status:
        stmt = stmt.where(Job.status.in_(status))
    if task:
        stmt = stmt.where(Job.task == task)
    stmt = stmt.order_by(Job.created_at.desc())
    return paginate(db, stmt, params)


def get_job(db: Session, job_id: uuid.UUID) -> Job:
    job = db.get(Job, job_id)
    if job is None:
        raise NotFound("Job", str(job_id))
    return job


def retry_job(db: Session, ctx: RequestContext, job_id: uuid.UUID) -> Job:
    job = get_job(db, job_id)
    DbTaskQueue().retry(db, job)
    append_audit(
        db,
        ctx,
        action="job.retried",
        resource_type="job",
        resource_id=job.id,
        resource_label=job.task,
        result=AuditResult.success,
    )
    return job


def cancel_job(db: Session, ctx: RequestContext, job_id: uuid.UUID) -> Job:
    job = get_job(db, job_id)
    DbTaskQueue().cancel(db, job)
    append_audit(
        db,
        ctx,
        action="job.cancelled",
        resource_type="job",
        resource_id=job.id,
        resource_label=job.task,
        result=AuditResult.success,
    )
    return job


def list_periodic_tasks(db: Session) -> list[PeriodicTask]:
    return list(db.execute(select(PeriodicTask).order_by(PeriodicTask.name)).scalars())


def update_periodic_task(
    db: Session, ctx: RequestContext, task_id: uuid.UUID, changes: dict[str, Any]
) -> PeriodicTask:
    row = db.get(PeriodicTask, task_id)
    if row is None:
        raise NotFound("PeriodicTask", str(task_id))
    if changes.get("enabled") is not None:
        row.enabled = bool(changes["enabled"])
    if changes.get("interval_seconds") is not None:
        row.interval_seconds = int(changes["interval_seconds"])
    append_audit(
        db,
        ctx,
        action="periodic_task.updated",
        resource_type="periodic_task",
        resource_id=row.id,
        resource_label=row.name,
        after_state=changes,
        result=AuditResult.success,
    )
    return row


def enqueue_backup(db: Session, ctx: RequestContext) -> Job | None:
    return enqueue(
        db,
        "backup.run",
        payload={"kind": "full"},
        requested_by_id=ctx.actor_id,
        dedupe_key="backup:full",
    )


def list_backups(db: Session) -> list[Backup]:
    return list(db.execute(select(Backup).order_by(Backup.started_at.desc()).limit(50)).scalars())


def system_health(db: Session) -> dict[str, Any]:
    stats = DbTaskQueue().stats(db)
    samples = list(
        db.execute(
            select(SystemHealthSample).order_by(SystemHealthSample.created_at.desc()).limit(48)
        )
        .scalars()
        .all()
    )
    latest = samples[0] if samples else None
    storage = get_storage()
    return {
        "status": "ok" if stats["failed_24h"] < 20 else "degraded",
        "version": __version__,
        "environment": settings.env.value,
        "queue": stats,
        "latest_sample": latest,
        "samples": list(reversed(samples)),
        "storage_bytes": storage.usage_bytes(),
        "storage_objects": storage.object_count(),
        "registered_tasks": [spec.name for spec in all_tasks()],
    }


def create_api_token(
    db: Session,
    ctx: RequestContext,
    user_id: uuid.UUID,
    *,
    name: str,
    scopes: list[str],
    expires_at: Any = None,
) -> tuple[ApiToken, str]:
    secret = generate_token(32)
    prefix = secret[:8]
    token = ApiToken(
        user_id=user_id,
        name=name,
        prefix=prefix,
        token_hash=hash_token(secret),
        scopes=scopes,
        expires_at=expires_at,
    )
    db.add(token)
    db.flush()
    append_audit(
        db,
        ctx,
        action="api_token.created",
        resource_type="api_token",
        resource_id=token.id,
        resource_label=name,
        result=AuditResult.success,
    )
    return token, secret


def list_api_tokens(db: Session, user_id: uuid.UUID) -> list[ApiToken]:
    return list(
        db.execute(
            select(ApiToken).where(ApiToken.user_id == user_id).order_by(ApiToken.created_at.desc())
        )
        .scalars()
        .all()
    )


def revoke_api_token(
    db: Session, ctx: RequestContext, token_id: uuid.UUID, user_id: uuid.UUID
) -> ApiToken:
    token = db.get(ApiToken, token_id)
    if token is None or token.user_id != user_id:
        raise NotFound("ApiToken", str(token_id))
    token.revoked_at = utcnow()
    append_audit(
        db,
        ctx,
        action="api_token.revoked",
        resource_type="api_token",
        resource_id=token.id,
        resource_label=token.name,
        result=AuditResult.success,
    )
    return token


def _load_roles(db: Session, slugs: list[str]) -> list[Role]:
    roles = list(db.execute(select(Role).where(Role.slug.in_(slugs))).scalars().all())
    found = {role.slug for role in roles}
    missing = [slug for slug in slugs if slug not in found]
    if missing:
        raise ValidationFailed(f"Unknown role(s): {', '.join(missing)}")
    return roles
