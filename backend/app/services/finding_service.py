"""Human-authored investigative findings."""

from __future__ import annotations

import uuid

from sqlalchemy import func, select
from sqlalchemy.orm import Session, joinedload

from app.audit.writer import append_audit, append_custody
from app.core.context import RequestContext
from app.core.errors import NotFound, ValidationFailed
from app.models.case import Finding
from app.models.enums import AuditResult, Confidence, CustodyAction, FindingKind, Severity
from app.models.evidence import Evidence
from app.services import case_service, evidence_service


def list_findings(db: Session, ctx: RequestContext, case_id: uuid.UUID) -> list[Finding]:
    case_service.require_case_access(db, ctx, case_id)
    return list(
        db.execute(
            select(Finding)
            .options(joinedload(Finding.author), joinedload(Finding.evidence_items))
            .where(Finding.case_id == case_id)
            .order_by(Finding.sequence)
        )
        .unique()
        .scalars()
        .all()
    )


def get_finding(db: Session, ctx: RequestContext, finding_id: uuid.UUID) -> Finding:
    finding = (
        db.execute(
            select(Finding)
            .options(joinedload(Finding.author), joinedload(Finding.evidence_items))
            .where(Finding.id == finding_id)
        )
        .unique()
        .scalar_one_or_none()
    )
    if finding is None:
        raise NotFound("Finding", str(finding_id))
    case_service.require_case_access(db, ctx, finding.case_id)
    return finding


def create_finding(
    db: Session,
    ctx: RequestContext,
    case_id: uuid.UUID,
    *,
    kind: FindingKind,
    title: str,
    description: str,
    confidence: Confidence,
    severity: Severity,
    evidence_ids: list[uuid.UUID],
    is_included_in_report: bool,
) -> Finding:
    case = case_service.require_case_access(db, ctx, case_id)
    case_service.require_open_case(case)

    next_sequence = (
        db.execute(
            select(func.coalesce(func.max(Finding.sequence), 0)).where(Finding.case_id == case_id)
        ).scalar_one()
        + 1
    )
    finding = Finding(
        case_id=case_id,
        sequence=next_sequence,
        kind=kind,
        title=title.strip(),
        description=description.strip(),
        confidence=confidence,
        severity=severity,
        author_id=ctx.actor_id,
        is_included_in_report=is_included_in_report,
    )
    finding.evidence_items = _load_evidence(db, ctx, case_id, evidence_ids)
    db.add(finding)
    db.flush()

    for item in finding.evidence_items:
        append_custody(
            db,
            ctx,
            item,
            action=CustodyAction.included_in_report,
            reason=f"cited in finding {case.reference}/{finding.sequence}",
            details={"finding_id": str(finding.id), "finding_title": finding.title},
        )

    append_audit(
        db,
        ctx,
        action="finding.created",
        resource_type="finding",
        resource_id=finding.id,
        resource_label=finding.title,
        case_id=case_id,
        after_state={"kind": kind.value, "sequence": finding.sequence},
        result=AuditResult.success,
    )
    return finding


def update_finding(
    db: Session,
    ctx: RequestContext,
    finding_id: uuid.UUID,
    changes: dict[str, object],
) -> Finding:
    finding = get_finding(db, ctx, finding_id)
    case = case_service.require_case_access(db, ctx, finding.case_id)
    case_service.require_open_case(case)

    before = {"title": finding.title, "kind": finding.kind.value}
    if "kind" in changes and changes["kind"] is not None:
        finding.kind = FindingKind(changes["kind"])  # type: ignore[arg-type]
    if "title" in changes and changes["title"] is not None:
        finding.title = str(changes["title"]).strip()
    if "description" in changes and changes["description"] is not None:
        finding.description = str(changes["description"]).strip()
    if "confidence" in changes and changes["confidence"] is not None:
        finding.confidence = Confidence(changes["confidence"])  # type: ignore[arg-type]
    if "severity" in changes and changes["severity"] is not None:
        finding.severity = Severity(changes["severity"])  # type: ignore[arg-type]
    if "is_included_in_report" in changes and changes["is_included_in_report"] is not None:
        finding.is_included_in_report = bool(changes["is_included_in_report"])
    if "evidence_ids" in changes and changes["evidence_ids"] is not None:
        finding.evidence_items = _load_evidence(
            db,
            ctx,
            finding.case_id,
            list(changes["evidence_ids"]),  # type: ignore[arg-type]
        )
    db.flush()
    append_audit(
        db,
        ctx,
        action="finding.updated",
        resource_type="finding",
        resource_id=finding.id,
        resource_label=finding.title,
        case_id=finding.case_id,
        before_state=before,
        after_state={"title": finding.title},
        result=AuditResult.success,
    )
    return finding


def delete_finding(db: Session, ctx: RequestContext, finding_id: uuid.UUID) -> None:
    finding = get_finding(db, ctx, finding_id)
    case = case_service.require_case_access(db, ctx, finding.case_id)
    case_service.require_open_case(case)
    append_audit(
        db,
        ctx,
        action="finding.deleted",
        resource_type="finding",
        resource_id=finding.id,
        resource_label=finding.title,
        case_id=finding.case_id,
        result=AuditResult.success,
    )
    db.delete(finding)


def _load_evidence(
    db: Session, ctx: RequestContext, case_id: uuid.UUID, evidence_ids: list[uuid.UUID]
) -> list[Evidence]:
    if not evidence_ids:
        return []
    items = []
    for evidence_id in evidence_ids:
        item = evidence_service.get_evidence(db, ctx, evidence_id)
        if item.case_id != case_id:
            raise ValidationFailed(
                f"Evidence {item.reference} does not belong to this case and cannot be cited."
            )
        items.append(item)
    return items
