"""Drive the real case/evidence/analysis pipeline for three linked investigations."""

from __future__ import annotations

import io
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.analysis.pipeline import analyze_evidence
from app.core.context import RequestContext
from app.intelligence import anomalies, correlation, insights, risk, threatintel
from app.models.case import Case
from app.models.enums import (
    AcquisitionMethod,
    CaseStatus,
    Confidence,
    EvidenceType,
    FindingKind,
    IncidentType,
    Severity,
    SourceCategory,
)
from app.models.user import User
from app.seed.artifacts import GeneratedFile
from app.services import case_service, evidence_service, finding_service


def ingest_scenarios(
    session: Session,
    ctx: RequestContext,
    investigator: User,
    analyst: User,
    files: dict[str, GeneratedFile],
) -> dict[str, str]:
    existing = {
        row.title: row
        for row in session.execute(select(Case)).scalars().all()
    }
    if "Globex file-server encryption — InvoiceLock" in existing:
        return {
            "ransomware": existing["Globex file-server encryption — InvoiceLock"].reference,
            "bec": existing["Globex CFO — supplier payment diversion"].reference,
            "insider": existing["Suspected insider copy of customer database"].reference,
        }

    ransomware = case_service.create_case(
        session,
        ctx,
        title="Globex file-server encryption — InvoiceLock",
        summary=(
            "Overnight encryption of the finance file server. Authentication logs show a "
            "brute-force then a successful login from 203.0.113.77, after which backups "
            "were stopped."
        ),
        incident_type=IncidentType.ransomware,
        severity=Severity.critical,
        incident_occurred_at=datetime(2026, 8, 12, 2, 14, tzinfo=UTC),
        reported_at=datetime(2026, 8, 12, 6, 40, tzinfo=UTC),
        lead_investigator_id=investigator.id,
        jurisdiction="England and Wales",
        organization="Globex Holding",
        classification="RESTRICTED",
        tags=["ransomware", "invoicelock"],
        status=CaseStatus.active,
    )
    bec = case_service.create_case(
        session,
        ctx,
        title="Globex CFO — supplier payment diversion",
        summary=(
            "A spoofed accounts-payable message instructed a change of bank details. "
            "The message failed SPF/DKIM and originated from invoices-secure-mail.net."
        ),
        incident_type=IncidentType.business_email_compromise,
        severity=Severity.high,
        incident_occurred_at=datetime(2026, 8, 11, 16, 42, tzinfo=UTC),
        reported_at=datetime(2026, 8, 11, 18, 5, tzinfo=UTC),
        lead_investigator_id=investigator.id,
        jurisdiction="England and Wales",
        organization="Globex Holding",
        classification="RESTRICTED",
        tags=["bec", "phishing"],
        status=CaseStatus.active,
    )
    insider = case_service.create_case(
        session,
        ctx,
        title="Suspected insider copy of customer database",
        summary=(
            "A workstation user exported a customer database overnight and copied it to "
            "removable media. The same external address seen in the ransomware case appears "
            "in the workstation syslog."
        ),
        incident_type=IncidentType.insider_threat,
        severity=Severity.high,
        incident_occurred_at=datetime(2026, 8, 12, 1, 2, tzinfo=UTC),
        reported_at=datetime(2026, 8, 12, 8, 15, tzinfo=UTC),
        lead_investigator_id=investigator.id,
        jurisdiction="England and Wales",
        organization="Globex Holding",
        classification="RESTRICTED",
        tags=["insider", "exfiltration"],
        status=CaseStatus.active,
    )

    case_service.assign_user(
        session, ctx, ransomware.id, user_id=analyst.id, role_on_case="forensic_analyst"
    )
    case_service.assign_user(
        session, ctx, bec.id, user_id=analyst.id, role_on_case="forensic_analyst"
    )
    case_service.assign_user(
        session, ctx, insider.id, user_id=analyst.id, role_on_case="forensic_analyst"
    )

    mapping: list[tuple[object, str, EvidenceType, SourceCategory, AcquisitionMethod]] = [
        (
            ransomware,
            "auth_log",
            EvidenceType.system_log,
            SourceCategory.digital_device,
            AcquisitionMethod.log_export,
        ),
        (
            ransomware,
            "ransom_note",
            EvidenceType.document,
            SourceCategory.digital_device,
            AcquisitionMethod.file_export,
        ),
        (
            ransomware,
            "netflow",
            EvidenceType.network_log,
            SourceCategory.network_system,
            AcquisitionMethod.network_capture,
        ),
        (
            bec,
            "bec_email",
            EvidenceType.email_message,
            SourceCategory.cloud_communication,
            AcquisitionMethod.file_export,
        ),
        (
            bec,
            "nginx_log",
            EvidenceType.network_log,
            SourceCategory.network_system,
            AcquisitionMethod.log_export,
        ),
        (
            insider,
            "exfil_archive",
            EvidenceType.archive,
            SourceCategory.digital_device,
            AcquisitionMethod.logical_copy,
        ),
        (
            insider,
            "camera_jpeg",
            EvidenceType.image,
            SourceCategory.digital_device,
            AcquisitionMethod.file_export,
        ),
        (
            insider,
            "insider_syslog",
            EvidenceType.system_log,
            SourceCategory.digital_device,
            AcquisitionMethod.log_export,
        ),
    ]

    ingested = []
    for case, key, evidence_type, source, method in mapping:
        generated = files[key]
        item = evidence_service.ingest_evidence(
            session,
            ctx,
            case_id=case.id,
            stream=io.BytesIO(generated.content),
            original_filename=generated.filename,
            title=generated.filename,
            declared_mime=generated.mime,
            evidence_type=evidence_type,
            source_category=source,
            acquisition_method=method,
            acquired_at=case.incident_occurred_at,
            acquired_by_name=investigator.full_name,
            collection_notes="Seeded demonstration artifact generated by CYBERTRACE.",
        )
        analyze_evidence(session, ctx, item)
        correlation.correlate_evidence(session, item)
        ingested.append(item)

    for case in (ransomware, bec, insider):
        threatintel.check_case(session, case.id)
        anomalies.detect_for_case(session, case.id)
        insights.generate_for_case(session, case)
        risk.score_case(session, case)

    finding_service.create_finding(
        session,
        ctx,
        ransomware.id,
        kind=FindingKind.indicator_of_compromise,
        title="Shared C2 address 203.0.113.77 used for initial access",
        description=(
            "The file-server authentication log records a failed-then-successful SSH login "
            "from 203.0.113.77, an address also present in the BEC Received chain and the "
            "insider workstation syslog. The local intelligence feed classifies it as "
            "InvoiceLock infrastructure."
        ),
        confidence=Confidence.high,
        severity=Severity.critical,
        evidence_ids=[ingested[0].id, ingested[2].id],
        is_included_in_report=True,
    )
    return {
        "ransomware": ransomware.reference,
        "bec": bec.reference,
        "insider": insider.reference,
    }
