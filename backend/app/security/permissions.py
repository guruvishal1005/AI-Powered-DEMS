"""Permission catalogue and the default role bundles.

This module is the *source* of the permission vocabulary; the ``permissions`` and
``role_permissions`` tables are the editable projection of it, synchronised at startup by
:func:`app.security.bootstrap.sync_permissions`. Runtime checks always read the database, so
an administrator's changes take effect without a deployment, while this file keeps a
reviewable record of what the platform ships with.

Two decisions here are load-bearing, and both are separation-of-duties controls rather than
convenience:

**Administrators cannot read evidence content.** They hold ``evidence:read`` (metadata,
hashes, custody) but neither ``evidence:download`` nor ``evidence:preview``. An account that
manages users and retention policies should not also be able to walk out with the case
material, and on this platform it cannot.

**Auditors cannot read evidence content either.** Their remit is history, integrity and
compliance. They see every case (``case:read_all``) precisely because an auditor must not be
restricted to what an investigator chose to share, but they hold no write permission at all.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.models.enums import Permission, RoleSlug


@dataclass(frozen=True, slots=True)
class PermissionSpec:
    code: Permission
    category: str
    label: str
    description: str
    is_sensitive: bool = False


@dataclass(frozen=True, slots=True)
class RoleSpec:
    slug: RoleSlug
    name: str
    description: str
    rank: int
    permissions: frozenset[Permission]


P = Permission

PERMISSION_CATALOG: tuple[PermissionSpec, ...] = (
    # --- Cases ---
    PermissionSpec(P.case_create, "cases", "Create cases", "Register a new cybercrime case."),
    PermissionSpec(
        P.case_read, "cases", "View assigned cases", "View cases the user leads or is assigned to."
    ),
    PermissionSpec(
        P.case_read_all,
        "cases",
        "View all cases",
        "View every case regardless of assignment. Required for oversight and audit.",
        is_sensitive=True,
    ),
    PermissionSpec(P.case_update, "cases", "Edit cases", "Change case details and metadata."),
    PermissionSpec(
        P.case_assign, "cases", "Assign personnel", "Add or remove investigators and analysts."
    ),
    PermissionSpec(P.case_close, "cases", "Close cases", "Close a case after review."),
    PermissionSpec(P.case_reopen, "cases", "Reopen cases", "Reopen a previously closed case."),
    PermissionSpec(
        P.case_delete,
        "cases",
        "Delete cases",
        "Permanently remove a case. Only ever possible for empty draft cases.",
        is_sensitive=True,
    ),
    # --- Evidence ---
    PermissionSpec(
        P.evidence_upload, "evidence", "Register evidence", "Upload and register digital evidence."
    ),
    PermissionSpec(
        P.evidence_read,
        "evidence",
        "View evidence metadata",
        "View evidence records, hashes, integrity state and custody history.",
    ),
    PermissionSpec(
        P.evidence_download,
        "evidence",
        "Download evidence content",
        "Retrieve the original artifact bytes. Every download is recorded in custody and "
        "requires a stated reason.",
        is_sensitive=True,
    ),
    PermissionSpec(
        P.evidence_preview,
        "evidence",
        "Preview evidence",
        "View a sanitised rendering of evidence content.",
        is_sensitive=True,
    ),
    PermissionSpec(
        P.evidence_update, "evidence", "Edit evidence metadata", "Amend descriptive metadata."
    ),
    PermissionSpec(
        P.evidence_verify,
        "evidence",
        "Verify integrity",
        "Recompute hashes and verify an artifact against its acquisition fingerprint.",
    ),
    PermissionSpec(
        P.evidence_transfer,
        "evidence",
        "Transfer custody",
        "Record transfer of custody to another responsible party.",
    ),
    PermissionSpec(P.evidence_archive, "evidence", "Archive evidence", "Move evidence to archive."),
    PermissionSpec(
        P.evidence_delete,
        "evidence",
        "Dispose of evidence",
        "Destroy artifact content under a retention policy. Custody history is retained.",
        is_sensitive=True,
    ),
    # --- Custody ---
    PermissionSpec(
        P.custody_read,
        "custody",
        "View chain of custody",
        "Inspect the full custody chain and its verification state.",
    ),
    # --- Analysis ---
    PermissionSpec(
        P.analysis_run, "analysis", "Run analysis", "Execute analyzers against evidence."
    ),
    PermissionSpec(
        P.analysis_read,
        "analysis",
        "View analysis",
        "View extracted entities, observations, correlations and insights.",
    ),
    # --- Findings ---
    PermissionSpec(
        P.finding_create, "findings", "Record findings", "Document investigative findings."
    ),
    PermissionSpec(P.finding_update, "findings", "Edit findings", "Amend an existing finding."),
    PermissionSpec(P.finding_delete, "findings", "Delete findings", "Remove a finding."),
    # --- Reports ---
    PermissionSpec(
        P.report_generate, "reports", "Generate reports", "Build a forensic report from a case."
    ),
    PermissionSpec(P.report_read, "reports", "View reports", "Read generated reports."),
    PermissionSpec(
        P.report_sign,
        "reports",
        "Approve and sign reports",
        "Attest to a report's contents. The preparer of a report can never also sign it.",
        is_sensitive=True,
    ),
    PermissionSpec(P.report_delete, "reports", "Delete reports", "Remove a draft report."),
    # --- Alerts ---
    PermissionSpec(P.alert_read, "alerts", "View alerts", "View security and integrity alerts."),
    PermissionSpec(
        P.alert_manage, "alerts", "Triage alerts", "Acknowledge, assign and resolve alerts."
    ),
    # --- Audit ---
    PermissionSpec(
        P.audit_read,
        "audit",
        "View audit log",
        "Read the platform-wide audit trail and verify its hash chain.",
        is_sensitive=True,
    ),
    # --- Threat intelligence ---
    PermissionSpec(P.intel_read, "intelligence", "View intelligence", "View indicator matches."),
    PermissionSpec(
        P.intel_manage, "intelligence", "Manage intelligence", "Manage indicator feeds and entries."
    ),
    # --- Administration ---
    PermissionSpec(P.user_read, "administration", "View users", "View user accounts."),
    PermissionSpec(
        P.user_manage,
        "administration",
        "Manage users",
        "Create, edit, suspend and unlock accounts.",
        is_sensitive=True,
    ),
    PermissionSpec(
        P.role_manage,
        "administration",
        "Manage roles",
        "Create roles and change which permissions they grant.",
        is_sensitive=True,
    ),
    PermissionSpec(P.system_read, "administration", "View system status", "View platform health."),
    PermissionSpec(
        P.system_configure,
        "administration",
        "Configure system",
        "Change runtime system and security settings.",
        is_sensitive=True,
    ),
    PermissionSpec(P.job_read, "administration", "View jobs", "Inspect the background job queue."),
    PermissionSpec(
        P.job_manage, "administration", "Manage jobs", "Retry, cancel and requeue background jobs."
    ),
    PermissionSpec(
        P.retention_manage,
        "administration",
        "Manage retention",
        "Define retention policies and legal holds.",
        is_sensitive=True,
    ),
    PermissionSpec(
        P.backup_manage, "administration", "Manage backups", "Trigger and verify backups."
    ),
)

PERMISSION_BY_CODE: dict[Permission, PermissionSpec] = {
    spec.code: spec for spec in PERMISSION_CATALOG
}

# --------------------------------------------------------------------------------------
# Role bundles
# --------------------------------------------------------------------------------------

_INVESTIGATOR_PERMISSIONS = frozenset(
    {
        P.case_create,
        P.case_read,
        P.case_update,
        P.case_assign,
        P.case_close,
        P.case_reopen,
        P.evidence_upload,
        P.evidence_read,
        P.evidence_download,
        P.evidence_preview,
        P.evidence_update,
        P.evidence_verify,
        P.evidence_transfer,
        P.evidence_archive,
        P.custody_read,
        P.analysis_run,
        P.analysis_read,
        P.finding_create,
        P.finding_update,
        P.finding_delete,
        P.report_generate,
        P.report_read,
        P.report_sign,
        P.alert_read,
        P.alert_manage,
        P.intel_read,
    }
)

_ANALYST_PERMISSIONS = frozenset(
    {
        P.case_read,
        P.evidence_upload,
        P.evidence_read,
        P.evidence_download,
        P.evidence_preview,
        P.evidence_update,
        P.evidence_verify,
        P.custody_read,
        P.analysis_run,
        P.analysis_read,
        P.finding_create,
        P.finding_update,
        P.report_generate,
        P.report_read,
        P.report_sign,
        P.alert_read,
        P.alert_manage,
        P.intel_read,
    }
)

# Read-only across the entire platform, and deliberately without access to artifact content.
_AUDITOR_PERMISSIONS = frozenset(
    {
        P.case_read,
        P.case_read_all,
        P.evidence_read,
        P.custody_read,
        P.analysis_read,
        P.report_read,
        P.alert_read,
        P.audit_read,
        P.intel_read,
        P.user_read,
        P.system_read,
        P.job_read,
    }
)

# Operates the platform. Note the absence of evidence_download, evidence_preview,
# finding_* and report_sign: administration is not investigation.
_ADMINISTRATOR_PERMISSIONS = frozenset(
    {
        P.case_read,
        P.case_read_all,
        P.case_delete,
        P.evidence_read,
        P.evidence_delete,
        P.custody_read,
        P.analysis_read,
        P.report_read,
        P.alert_read,
        P.alert_manage,
        P.audit_read,
        P.intel_read,
        P.intel_manage,
        P.user_read,
        P.user_manage,
        P.role_manage,
        P.system_read,
        P.system_configure,
        P.job_read,
        P.job_manage,
        P.retention_manage,
        P.backup_manage,
    }
)

ROLE_DEFINITIONS: tuple[RoleSpec, ...] = (
    RoleSpec(
        slug=RoleSlug.administrator,
        name="Administrator",
        description=(
            "Operates the platform: accounts, roles, retention, storage, backups and "
            "monitoring. Cannot read evidence content or author investigative findings."
        ),
        rank=40,
        permissions=_ADMINISTRATOR_PERMISSIONS,
    ),
    RoleSpec(
        slug=RoleSlug.investigator,
        name="Investigator",
        description=(
            "Owns cases end to end: registers incidents, acquires and registers evidence, "
            "documents findings and produces reports for review."
        ),
        rank=30,
        permissions=_INVESTIGATOR_PERMISSIONS,
    ),
    RoleSpec(
        slug=RoleSlug.forensic_analyst,
        name="Forensic Analyst",
        description=(
            "Performs deep examination of evidence on assigned cases: runs analyzers, "
            "verifies integrity, builds timelines and attests to technical reports."
        ),
        rank=20,
        permissions=_ANALYST_PERMISSIONS,
    ),
    RoleSpec(
        slug=RoleSlug.auditor,
        name="Auditor",
        description=(
            "Read-only oversight across every case: custody chains, integrity verification, "
            "audit trail and compliance. Has no access to evidence content."
        ),
        rank=10,
        permissions=_AUDITOR_PERMISSIONS,
    ),
)

ROLE_BY_SLUG: dict[RoleSlug, RoleSpec] = {spec.slug: spec for spec in ROLE_DEFINITIONS}


def permissions_for_role(slug: RoleSlug) -> frozenset[Permission]:
    return ROLE_BY_SLUG[slug].permissions
