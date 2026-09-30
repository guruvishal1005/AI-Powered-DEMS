"""Point-in-time case snapshot for a forensic report.

The snapshot is the thing a signature attests to. Everything downstream - PDF, JSON export,
CSV inventory - renders from this document, so re-rendering an old report cannot silently
pick up later analysis.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session, joinedload

from app.core.canonical import canonical_bytes, jsonable
from app.core.clock import isoformat, utcnow
from app.core.context import RequestContext
from app.models.analysis import AnalysisFinding, Anomaly, CorrelationEdge, Insight, Observation
from app.models.case import Case, Finding
from app.models.custody import AuditLogEntry
from app.models.enums import IntegrityStatus
from app.models.evidence import Evidence
from app.services.custody_service import chain_status


def capture(db: Session, ctx: RequestContext, case: Case, spec: dict[str, Any]) -> dict[str, Any]:
    """Assemble an immutable JSON document describing the case as it stands now."""
    evidence_items = list(
        db.execute(
            select(Evidence)
            .options(joinedload(Evidence.uploaded_by))
            .where(Evidence.case_id == case.id)
            .order_by(Evidence.reference)
        )
        .unique()
        .scalars()
        .all()
    )

    inventory = []
    verified = 0
    failed = 0
    all_chains_intact = True
    for item in evidence_items:
        chain = chain_status(db, item)
        if item.integrity_status is IntegrityStatus.verified:
            verified += 1
        elif item.integrity_status in (
            IntegrityStatus.hash_mismatch,
            IntegrityStatus.decryption_failed,
            IntegrityStatus.object_missing,
        ):
            failed += 1
        if not chain.trustworthy:
            all_chains_intact = False
        inventory.append(
            {
                "id": str(item.id),
                "reference": item.reference,
                "title": item.title,
                "original_filename": item.original_filename,
                "evidence_type": item.evidence_type.value,
                "sha256": item.sha256,
                "size_bytes": item.size_bytes,
                "mime_type": item.mime_type,
                "mime_mismatch": item.mime_mismatch,
                "integrity_status": item.integrity_status.value,
                "acquired_at": isoformat(item.acquired_at) if item.acquired_at else None,
                "acquired_by": item.acquired_by_name,
                "custody": {
                    "event_count": chain.event_count,
                    "intact": chain.intact,
                    "trustworthy": chain.trustworthy,
                    "head_hash": chain.head_hash,
                    "summary": chain.summary,
                },
            }
        )

    findings = [
        {
            "sequence": finding.sequence,
            "kind": finding.kind.value,
            "title": finding.title,
            "description": finding.description,
            "confidence": finding.confidence.value,
            "severity": finding.severity.value,
            "author": finding.author.full_name if finding.author else None,
            "evidence_references": [item.reference for item in finding.evidence_items],
        }
        for finding in db.execute(
            select(Finding)
            .options(joinedload(Finding.author), joinedload(Finding.evidence_items))
            .where(Finding.case_id == case.id)
            .where(Finding.is_included_in_report.is_(True))
            .order_by(Finding.sequence)
        )
        .unique()
        .scalars()
        .all()
    ]

    observations = [
        {
            "kind": row.kind.value,
            "occurred_at": isoformat(row.occurred_at),
            "summary": row.summary,
            "evidence_id": str(row.evidence_id),
            "analyzer": row.analyzer,
            "time_confidence": row.time_confidence.value,
            "timezone_assumed": row.timezone_assumed,
        }
        for row in db.execute(
            select(Observation)
            .where(Observation.case_id == case.id)
            .order_by(Observation.occurred_at)
            .limit(2000)
        )
        .scalars()
        .all()
    ]

    insights = [
        {
            "kind": row.kind.value,
            "provenance": row.provenance.value,
            "severity": row.severity.value,
            "title": row.title,
            "observed": row.observed,
            "interpretation": row.interpretation,
            "confidence": row.confidence,
            "evidence_refs": row.evidence_refs,
            "basis": row.basis,
        }
        for row in db.execute(
            select(Insight)
            .where(Insight.case_id == case.id)
            .where(Insight.dismissed_at.is_(None))
            .order_by(Insight.rank_score.desc())
        )
        .scalars()
        .all()
    ]

    correlations = [
        {
            "kind": row.kind.value,
            "score": row.score,
            "explanation": row.explanation,
            "is_cross_case": row.is_cross_case,
            "shared_entity_count": row.shared_entity_count,
            "basis": row.basis,
            "source_evidence_id": str(row.source_evidence_id),
            "target_evidence_id": str(row.target_evidence_id),
        }
        for row in db.execute(
            select(CorrelationEdge).where(
                (CorrelationEdge.source_case_id == case.id)
                | (CorrelationEdge.target_case_id == case.id)
            )
        )
        .scalars()
        .all()
    ]

    anomalies = [
        {
            "kind": row.kind.value,
            "severity": row.severity.value,
            "title": row.title,
            "description": row.description,
            "method": row.method,
            "threshold": row.threshold,
            "observed_value": row.observed_value,
            "baseline_value": row.baseline_value,
        }
        for row in db.execute(
            select(Anomaly).where(Anomaly.case_id == case.id).where(Anomaly.dismissed_at.is_(None))
        )
        .scalars()
        .all()
    ]

    analysis_findings = [
        {
            "code": row.code,
            "title": row.title,
            "severity": row.severity.value,
            "analyzer": row.analyzer,
            "analyzer_version": row.analyzer_version,
        }
        for row in db.execute(select(AnalysisFinding).where(AnalysisFinding.case_id == case.id))
        .scalars()
        .all()
    ]

    audit_count = db.execute(
        select(AuditLogEntry.id).where(AuditLogEntry.case_id == case.id).limit(1)
    ).first()

    snapshot = {
        "schema_version": 1,
        "captured_at": isoformat(utcnow()),
        "captured_by": ctx.actor_label,
        "spec": spec,
        "case": {
            "id": str(case.id),
            "reference": case.reference,
            "title": case.title,
            "summary": case.summary,
            "incident_type": case.incident_type.value,
            "severity": case.severity.value,
            "status": case.status.value,
            "classification": case.classification,
            "jurisdiction": case.jurisdiction,
            "organization": case.organization,
            "opened_at": isoformat(case.opened_at) if case.opened_at else None,
            "lead": case.lead_investigator.full_name if case.lead_investigator else None,
        },
        "evidence_inventory": inventory,
        "integrity": {
            "verified_count": verified,
            "failed_count": failed,
            "pending_count": len(evidence_items) - verified - failed,
            "all_custody_chains_intact": all_chains_intact and failed == 0,
        },
        "findings": findings,
        "timeline": observations,
        "insights": insights,
        "correlations": correlations,
        "anomalies": anomalies,
        "analysis_findings": analysis_findings,
        "audit": {
            "case_has_audit_entries": audit_count is not None,
        },
        "counts": {
            "evidence": len(evidence_items),
            "findings": len(findings),
            "observations": len(observations),
            "insights": len(insights),
            "correlations": len(correlations),
        },
    }
    return jsonable(snapshot)


def snapshot_digest(snapshot: dict[str, Any]) -> str:
    import hashlib

    return hashlib.sha256(canonical_bytes(snapshot)).hexdigest()
