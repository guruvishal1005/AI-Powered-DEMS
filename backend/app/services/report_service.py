"""Report lifecycle: snapshot, render, sign.

Signing is gated on ``report:sign`` at the router, and additionally refuses the preparer of
the report. Separation of duties is otherwise theatre: the person who assembled the narrative
must not also be the person who attests that it is complete.
"""

from __future__ import annotations

import io
import uuid
from typing import Any, BinaryIO

from sqlalchemy import select
from sqlalchemy.orm import Session, joinedload

from app.audit.writer import append_audit, append_custody
from app.core.clock import utcnow
from app.core.context import RequestContext
from app.core.errors import Conflict, NotFound, PermissionDenied
from app.core.pagination import PageParams, paginate
from app.models.enums import AuditResult, CustodyAction, ReportFormat, ReportStatus
from app.models.evidence import Evidence
from app.models.report import Report, ReportArtifact
from app.reports import renderers
from app.reports import snapshot as snapshot_mod
from app.reports.signing import sign_snapshot, verify_snapshot_signature
from app.security.scoping import scope_case_ids
from app.services import case_service, evidence_service
from app.services.reference_service import next_report_reference
from app.storage.local import get_storage


def list_reports(
    db: Session,
    ctx: RequestContext,
    params: PageParams,
    *,
    case_id: uuid.UUID | None = None,
    status: list[ReportStatus] | None = None,
) -> tuple[list[Report], int]:
    stmt = scope_case_ids(
        select(Report).options(
            joinedload(Report.prepared_by),
            joinedload(Report.reviewed_by),
            joinedload(Report.artifacts).joinedload(ReportArtifact.stored_object),
        ),
        ctx,
        Report.case_id,
    )
    if case_id:
        case_service.require_case_access(db, ctx, case_id)
        stmt = stmt.where(Report.case_id == case_id)
    if status:
        stmt = stmt.where(Report.status.in_(status))
    stmt = stmt.order_by(Report.created_at.desc())
    return paginate(db, stmt, params)


def get_report(db: Session, ctx: RequestContext, report_id: uuid.UUID) -> Report:
    report = (
        db.execute(
            scope_case_ids(
                select(Report).options(
                    joinedload(Report.prepared_by),
                    joinedload(Report.reviewed_by),
                    joinedload(Report.artifacts).joinedload(ReportArtifact.stored_object),
                ),
                ctx,
                Report.case_id,
            ).where(Report.id == report_id)
        )
        .unique()
        .scalar_one_or_none()
    )
    if report is None:
        raise NotFound("Report", str(report_id))
    return report


def create_report(
    db: Session,
    ctx: RequestContext,
    case_id: uuid.UUID,
    *,
    title: str,
    classification: str,
    executive_summary: str | None,
    conclusion: str | None,
    distribution_list: list[str],
    spec: dict[str, Any],
) -> Report:
    case = case_service.require_case_access(db, ctx, case_id)
    captured = snapshot_mod.capture(db, ctx, case, spec)
    digest = snapshot_mod.snapshot_digest(captured)
    integrity = captured["integrity"]
    now = utcnow()
    report = Report(
        reference=next_report_reference(db),
        case_id=case_id,
        title=title.strip(),
        version=1,
        status=ReportStatus.draft,
        classification=classification,
        spec=spec,
        snapshot=captured,
        snapshot_sha256=digest,
        snapshot_captured_at=now,
        executive_summary=executive_summary,
        conclusion=conclusion,
        distribution_list=distribution_list,
        prepared_by_id=ctx.actor_id,
        prepared_at=now,
        evidence_count=captured["counts"]["evidence"],
        finding_count=captured["counts"]["findings"],
        integrity_verified_count=integrity["verified_count"],
        integrity_failed_count=integrity["failed_count"],
        custody_chain_intact=integrity["all_custody_chains_intact"],
    )
    db.add(report)
    db.flush()
    _cite_evidence(db, ctx, case_id, report)
    append_audit(
        db,
        ctx,
        action="report.created",
        resource_type="report",
        resource_id=report.id,
        resource_label=report.reference,
        case_id=case_id,
        after_state={"snapshot_sha256": digest, "evidence_count": report.evidence_count},
        result=AuditResult.success,
    )
    return report


def update_report(
    db: Session, ctx: RequestContext, report_id: uuid.UUID, changes: dict[str, Any]
) -> Report:
    report = get_report(db, ctx, report_id)
    if report.status is not ReportStatus.draft:
        raise Conflict("Only a draft report can be edited")
    for field in (
        "title",
        "classification",
        "executive_summary",
        "conclusion",
        "distribution_list",
    ):
        if field in changes and changes[field] is not None:
            setattr(report, field, changes[field])
    if changes.get("spec"):
        report.spec = changes["spec"]
    append_audit(
        db,
        ctx,
        action="report.updated",
        resource_type="report",
        resource_id=report.id,
        resource_label=report.reference,
        case_id=report.case_id,
        result=AuditResult.success,
    )
    return report


def recapture(db: Session, ctx: RequestContext, report_id: uuid.UUID) -> Report:
    """Replace the snapshot of a draft. The live case may have moved on since creation."""
    report = get_report(db, ctx, report_id)
    if report.status is not ReportStatus.draft:
        raise Conflict("The snapshot of a submitted report is frozen")
    case = case_service.require_case_access(db, ctx, report.case_id)
    captured = snapshot_mod.capture(db, ctx, case, report.spec)
    report.snapshot = captured
    report.snapshot_sha256 = snapshot_mod.snapshot_digest(captured)
    report.snapshot_captured_at = utcnow()
    report.evidence_count = captured["counts"]["evidence"]
    report.finding_count = captured["counts"]["findings"]
    report.integrity_verified_count = captured["integrity"]["verified_count"]
    report.integrity_failed_count = captured["integrity"]["failed_count"]
    report.custody_chain_intact = captured["integrity"]["all_custody_chains_intact"]
    return report


def submit(db: Session, ctx: RequestContext, report_id: uuid.UUID, *, note: str | None) -> Report:
    report = get_report(db, ctx, report_id)
    if report.status is not ReportStatus.draft:
        raise Conflict("Only a draft can be submitted for review")
    if report.snapshot_sha256 is None:
        recapture(db, ctx, report_id)
    report.status = ReportStatus.pending_review
    report.submitted_at = utcnow()
    append_audit(
        db,
        ctx,
        action="report.submitted",
        resource_type="report",
        resource_id=report.id,
        resource_label=report.reference,
        case_id=report.case_id,
        reason=note,
        result=AuditResult.success,
    )
    return report


def reject(db: Session, ctx: RequestContext, report_id: uuid.UUID, *, note: str) -> Report:
    report = get_report(db, ctx, report_id)
    if report.status is not ReportStatus.pending_review:
        raise Conflict("Only a report pending review can be rejected")
    if report.prepared_by_id == ctx.actor_id:
        raise PermissionDenied("The preparer of a report cannot review it")
    report.status = ReportStatus.rejected
    report.reviewed_by_id = ctx.actor_id
    report.reviewed_at = utcnow()
    report.review_note = note
    append_audit(
        db,
        ctx,
        action="report.rejected",
        resource_type="report",
        resource_id=report.id,
        resource_label=report.reference,
        case_id=report.case_id,
        reason=note,
        result=AuditResult.success,
    )
    return report


def sign(db: Session, ctx: RequestContext, report_id: uuid.UUID, *, note: str) -> Report:
    report = get_report(db, ctx, report_id)
    if report.status not in (ReportStatus.pending_review, ReportStatus.draft):
        raise Conflict(f"A report in status {report.status.value} cannot be signed")
    if report.prepared_by_id == ctx.actor_id:
        raise PermissionDenied(
            "The preparer of a report cannot also sign it. Another authorised officer must attest."
        )
    if not report.snapshot_sha256:
        raise Conflict("This report has no snapshot to sign")
    signature, key_id = sign_snapshot(report.snapshot_sha256)
    report.signature = signature
    report.signing_key_id = key_id
    report.signed_at = utcnow()
    report.status = ReportStatus.approved
    report.reviewed_by_id = ctx.actor_id
    report.reviewed_at = report.signed_at
    report.review_note = note
    append_audit(
        db,
        ctx,
        action="report.signed",
        resource_type="report",
        resource_id=report.id,
        resource_label=report.reference,
        case_id=report.case_id,
        after_state={"snapshot_sha256": report.snapshot_sha256, "signing_key_id": key_id},
        reason=note,
        result=AuditResult.success,
    )
    return report


def render_artifact(
    db: Session, ctx: RequestContext, report_id: uuid.UUID, fmt: ReportFormat
) -> ReportArtifact:
    report = get_report(db, ctx, report_id)
    existing = next((row for row in report.artifacts if row.format is fmt), None)
    if existing is not None and report.status is not ReportStatus.draft:
        return existing

    started = utcnow()
    payload = renderers.render(
        report.snapshot,
        fmt,
        title=report.title,
        classification=report.classification,
    )
    duration_ms = int((utcnow() - started).total_seconds() * 1000)
    filename = f"{report.reference}.{fmt.value}"
    stored, _ = evidence_service._resolve_stored_object(
        db, get_storage().stage(io.BytesIO(payload))
    )

    if existing is not None:
        existing.stored_object_id = stored.id
        existing.size_bytes = len(payload)
        existing.sha256 = stored.sha256
        existing.render_duration_ms = duration_ms
        existing.generated_by_id = ctx.actor_id
        existing.filename = filename
        return existing

    artifact = ReportArtifact(
        report_id=report.id,
        format=fmt,
        filename=filename,
        size_bytes=len(payload),
        sha256=stored.sha256,
        stored_object_id=stored.id,
        render_duration_ms=duration_ms,
        generated_by_id=ctx.actor_id,
    )
    db.add(artifact)
    db.flush()
    return artifact


def open_artifact(
    db: Session, ctx: RequestContext, report_id: uuid.UUID, fmt: ReportFormat
) -> tuple[Report, ReportArtifact, BinaryIO]:
    report = get_report(db, ctx, report_id)
    artifact = next((row for row in report.artifacts if row.format is fmt), None)
    if artifact is None:
        artifact = render_artifact(db, ctx, report_id, fmt)
        db.flush()
    from app.storage.base import StoredObjectRef

    stored = artifact.stored_object
    ref = StoredObjectRef(
        storage_key=stored.storage_key,
        nonce=stored.nonce,
        wrapped_key=stored.wrapped_key,
        key_version=stored.key_version,
        expected_sha256=stored.sha256,
        expected_ciphertext_sha256=stored.ciphertext_sha256,
        size_bytes=stored.size_bytes,
    )
    stream = get_storage().open_stream(ref)
    return report, artifact, stream  # type: ignore[return-value]


def verify(db: Session, ctx: RequestContext, report_id: uuid.UUID) -> dict[str, Any]:
    report = get_report(db, ctx, report_id)
    present = report.signature is not None
    valid = False
    if present and report.snapshot_sha256 and report.signature:
        valid = verify_snapshot_signature(report.snapshot_sha256, report.signature)
    if present and valid:
        detail = "Signature is valid over the persisted snapshot digest."
    elif present:
        detail = "A signature is present but does not verify against the snapshot digest."
    else:
        detail = "This report has not been signed."
    return {
        "report_id": report.id,
        "reference": report.reference,
        "snapshot_sha256": report.snapshot_sha256,
        "signature_present": present,
        "signature_valid": valid,
        "signing_key_id": report.signing_key_id,
        "status": report.status,
        "detail": detail,
    }


def _cite_evidence(db: Session, ctx: RequestContext, case_id: uuid.UUID, report: Report) -> None:
    items = db.execute(select(Evidence).where(Evidence.case_id == case_id)).scalars().all()
    for item in items:
        append_custody(
            db,
            ctx,
            item,
            action=CustodyAction.included_in_report,
            reason=f"included in {report.reference}",
            details={"report_id": str(report.id), "snapshot_sha256": report.snapshot_sha256},
        )
