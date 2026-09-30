"""Domain vocabulary.

Every enum is a :class:`~enum.StrEnum` so the stored value, the JSON value and the value
an investigator reads are the same string. Columns are declared with :func:`enum_type`,
which stores the value as ``VARCHAR`` without a database ``CHECK`` constraint. That is a
deliberate trade-off: forensic vocabularies grow (a new evidence type, a new custody
action), and constraint churn on a table holding append-only chained records is a far worse
problem than validating membership in Python and Pydantic, which happens anyway.
"""

from __future__ import annotations

from enum import StrEnum

from sqlalchemy import Enum as SAEnum


def enum_type(enum_cls: type[StrEnum], *, length: int = 48) -> SAEnum:
    return SAEnum(
        enum_cls,
        native_enum=False,
        create_constraint=False,
        values_callable=lambda cls: [member.value for member in cls],
        length=length,
    )


# --------------------------------------------------------------------------------------
# Access control
# --------------------------------------------------------------------------------------


class RoleSlug(StrEnum):
    administrator = "administrator"
    investigator = "investigator"
    forensic_analyst = "forensic_analyst"
    auditor = "auditor"


class Permission(StrEnum):
    """Atomic capabilities. Roles are bundles of these, editable at runtime.

    Two grants are deliberately narrow because they are the ones that matter most:
    ``evidence_download`` (access to raw artifact content) and ``report_sign`` (attesting
    to a report's contents). Neither is granted to administrators or auditors.
    """

    # Cases
    case_create = "case:create"
    case_read = "case:read"
    case_read_all = "case:read_all"  # see cases you are not assigned to
    case_update = "case:update"
    case_assign = "case:assign"
    case_close = "case:close"
    case_reopen = "case:reopen"
    case_delete = "case:delete"

    # Evidence
    evidence_upload = "evidence:upload"
    evidence_read = "evidence:read"  # metadata, hashes, custody
    evidence_download = "evidence:download"  # raw artifact content
    evidence_preview = "evidence:preview"  # sanitised derivative only
    evidence_update = "evidence:update"
    evidence_verify = "evidence:verify"
    evidence_transfer = "evidence:transfer"
    evidence_archive = "evidence:archive"
    evidence_delete = "evidence:delete"

    # Chain of custody
    custody_read = "custody:read"

    # Analysis
    analysis_run = "analysis:run"
    analysis_read = "analysis:read"

    # Findings
    finding_create = "finding:create"
    finding_update = "finding:update"
    finding_delete = "finding:delete"

    # Reports
    report_generate = "report:generate"
    report_read = "report:read"
    report_sign = "report:sign"
    report_delete = "report:delete"

    # Alerts
    alert_read = "alert:read"
    alert_manage = "alert:manage"

    # Audit
    audit_read = "audit:read"

    # Threat intelligence
    intel_read = "intel:read"
    intel_manage = "intel:manage"

    # Administration
    user_read = "user:read"
    user_manage = "user:manage"
    role_manage = "role:manage"
    system_read = "system:read"
    system_configure = "system:configure"
    job_read = "job:read"
    job_manage = "job:manage"
    retention_manage = "retention:manage"
    backup_manage = "backup:manage"


class UserStatus(StrEnum):
    active = "active"
    invited = "invited"
    suspended = "suspended"
    disabled = "disabled"


# --------------------------------------------------------------------------------------
# Cases
# --------------------------------------------------------------------------------------


class CaseStatus(StrEnum):
    draft = "draft"
    active = "active"
    pending_review = "pending_review"
    on_hold = "on_hold"
    closed = "closed"
    archived = "archived"


class Severity(StrEnum):
    informational = "informational"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


SEVERITY_WEIGHT: dict[Severity, int] = {
    Severity.informational: 0,
    Severity.low: 1,
    Severity.medium: 2,
    Severity.high: 3,
    Severity.critical: 4,
}


class IncidentType(StrEnum):
    ransomware = "ransomware"
    phishing = "phishing"
    business_email_compromise = "business_email_compromise"
    data_breach = "data_breach"
    insider_threat = "insider_threat"
    financial_fraud = "financial_fraud"
    identity_theft = "identity_theft"
    malware_infection = "malware_infection"
    denial_of_service = "denial_of_service"
    unauthorized_access = "unauthorized_access"
    intellectual_property_theft = "intellectual_property_theft"
    cyber_harassment = "cyber_harassment"
    cryptocurrency_fraud = "cryptocurrency_fraud"
    supply_chain_compromise = "supply_chain_compromise"
    other = "other"


class CasePersonRole(StrEnum):
    suspect = "suspect"
    victim = "victim"
    witness = "witness"
    complainant = "complainant"
    person_of_interest = "person_of_interest"
    organization = "organization"
    custodian = "custodian"


class FindingKind(StrEnum):
    observation = "observation"
    indicator_of_compromise = "indicator_of_compromise"
    attribution = "attribution"
    timeline_reconstruction = "timeline_reconstruction"
    root_cause = "root_cause"
    impact_assessment = "impact_assessment"
    recommendation = "recommendation"


class Confidence(StrEnum):
    low = "low"
    moderate = "moderate"
    high = "high"
    confirmed = "confirmed"


# --------------------------------------------------------------------------------------
# Evidence
# --------------------------------------------------------------------------------------


class EvidenceType(StrEnum):
    disk_image = "disk_image"
    memory_dump = "memory_dump"
    document = "document"
    spreadsheet = "spreadsheet"
    email_message = "email_message"
    image = "image"
    video = "video"
    audio = "audio"
    screenshot = "screenshot"
    network_capture = "network_capture"
    network_log = "network_log"
    system_log = "system_log"
    application_log = "application_log"
    database_export = "database_export"
    mobile_extraction = "mobile_extraction"
    chat_export = "chat_export"
    cloud_export = "cloud_export"
    archive = "archive"
    executable = "executable"
    other = "other"


class SourceCategory(StrEnum):
    """Top-level provenance, mirroring the data-source layer of the architecture."""

    digital_device = "digital_device"
    network_system = "network_system"
    cloud_communication = "cloud_communication"
    external_intelligence = "external_intelligence"


class AcquisitionMethod(StrEnum):
    live_acquisition = "live_acquisition"
    dead_disk_imaging = "dead_disk_imaging"
    logical_copy = "logical_copy"
    physical_extraction = "physical_extraction"
    file_export = "file_export"
    network_capture = "network_capture"
    log_export = "log_export"
    cloud_api_export = "cloud_api_export"
    screenshot_capture = "screenshot_capture"
    manual_collection = "manual_collection"
    third_party_provided = "third_party_provided"


class IntegrityStatus(StrEnum):
    """Result of the most recent verification.

    The failure modes are kept distinct because they mean different things: a
    ``hash_mismatch`` says the artifact's own bytes changed, whereas
    ``decryption_failed`` says the stored ciphertext or its authentication tag was
    altered. Collapsing them into a single "corrupt" state would destroy the signal an
    investigator needs.
    """

    pending = "pending"
    verified = "verified"
    hash_mismatch = "hash_mismatch"
    decryption_failed = "decryption_failed"
    object_missing = "object_missing"


class EvidenceStatus(StrEnum):
    registered = "registered"
    processing = "processing"
    analyzed = "analyzed"
    requires_attention = "requires_attention"
    archived = "archived"
    disposed = "disposed"


class HashAlgorithm(StrEnum):
    sha256 = "sha256"
    sha1 = "sha1"
    md5 = "md5"
    sha512 = "sha512"


# --------------------------------------------------------------------------------------
# Chain of custody
# --------------------------------------------------------------------------------------


class CustodyAction(StrEnum):
    collected = "collected"
    uploaded = "uploaded"
    accessed = "accessed"
    previewed = "previewed"
    downloaded = "downloaded"
    analyzed = "analyzed"
    verified = "verified"
    integrity_failed = "integrity_failed"
    metadata_updated = "metadata_updated"
    version_created = "version_created"
    transferred = "transferred"
    exported = "exported"
    included_in_report = "included_in_report"
    archived = "archived"
    restored = "restored"
    legal_hold_applied = "legal_hold_applied"
    legal_hold_released = "legal_hold_released"
    disposed = "disposed"


# --------------------------------------------------------------------------------------
# Analysis and intelligence
# --------------------------------------------------------------------------------------


class AnalysisStatus(StrEnum):
    pending = "pending"
    running = "running"
    completed = "completed"
    failed = "failed"
    skipped = "skipped"


class EntityType(StrEnum):
    person = "person"
    organization = "organization"
    location = "location"
    ip_address = "ip_address"
    domain = "domain"
    url = "url"
    email_address = "email_address"
    phone_number = "phone_number"
    username = "username"
    account = "account"
    device = "device"
    # A value that identifies one specific physical device - a camera body serial, an IMEI - as
    # opposed to `device`, which names a make and model shared by millions of units.
    device_identifier = "device_identifier"
    software = "software"
    file_name = "file_name"
    file_path = "file_path"
    file_hash = "file_hash"
    mac_address = "mac_address"
    crypto_wallet = "crypto_wallet"
    payment_card = "payment_card"
    cve = "cve"
    registry_key = "registry_key"
    process = "process"
    port = "port"
    user_agent = "user_agent"
    credential = "credential"
    keyword = "keyword"


class ObservationKind(StrEnum):
    """A timestamped event extracted from evidence content."""

    login_success = "login_success"
    login_failure = "login_failure"
    account_lockout = "account_lockout"
    privilege_change = "privilege_change"
    file_access = "file_access"
    file_created = "file_created"
    file_modified = "file_modified"
    file_deleted = "file_deleted"
    process_execution = "process_execution"
    network_connection = "network_connection"
    dns_query = "dns_query"
    http_request = "http_request"
    email_sent = "email_sent"
    email_received = "email_received"
    email_relay_hop = "email_relay_hop"
    media_captured = "media_captured"
    geolocation = "geolocation"
    document_authored = "document_authored"
    # A log record that carries a timestamp but no more specific semantics than "something was
    # written here". Kept distinct from `generic` so timeline lanes can separate raw log volume
    # from typed events.
    log_entry = "log_entry"
    transaction = "transaction"
    configuration_change = "configuration_change"
    generic = "generic"


class CorrelationKind(StrEnum):
    shared_indicator = "shared_indicator"
    temporal_proximity = "temporal_proximity"
    near_duplicate = "near_duplicate"
    identical_content = "identical_content"
    same_device = "same_device"
    same_account = "same_account"
    cross_case = "cross_case"


class AnomalyKind(StrEnum):
    temporal_burst = "temporal_burst"
    off_hours_activity = "off_hours_activity"
    failed_login_burst = "failed_login_burst"
    privilege_escalation = "privilege_escalation"
    mime_extension_mismatch = "mime_extension_mismatch"
    high_entropy_content = "high_entropy_content"
    timestamp_inconsistency = "timestamp_inconsistency"
    volume_outlier = "volume_outlier"
    access_outside_scope = "access_outside_scope"
    email_spoofing_indicator = "email_spoofing_indicator"
    known_malicious_indicator = "known_malicious_indicator"


class InsightKind(StrEnum):
    correlation = "correlation"
    cross_case_link = "cross_case_link"
    anomaly = "anomaly"
    temporal_pattern = "temporal_pattern"
    entity_pivot = "entity_pivot"
    integrity = "integrity"
    risk_assessment = "risk_assessment"
    coverage_gap = "coverage_gap"


class InsightProvenance(StrEnum):
    """How an insight was produced, surfaced verbatim in the interface.

    ``derived``   - a deterministic rule over recorded observations
    ``statistical`` - a threshold or distribution test, with the maths recorded
    ``llm_assisted`` - phrasing assistance only; may never introduce a fact
    """

    derived = "derived"
    statistical = "statistical"
    llm_assisted = "llm_assisted"


# --------------------------------------------------------------------------------------
# Alerts
# --------------------------------------------------------------------------------------


class AlertType(StrEnum):
    integrity_failure = "integrity_failure"
    chain_verification_failure = "chain_verification_failure"
    unauthorized_access_attempt = "unauthorized_access_attempt"
    access_outside_scope = "access_outside_scope"
    suspicious_download_volume = "suspicious_download_volume"
    ai_anomaly_detected = "ai_anomaly_detected"
    malicious_indicator_match = "malicious_indicator_match"
    evidence_pending_analysis = "evidence_pending_analysis"
    case_requires_attention = "case_requires_attention"
    retention_expiry_approaching = "retention_expiry_approaching"
    backup_failure = "backup_failure"
    job_failure = "job_failure"
    account_locked = "account_locked"


class AlertStatus(StrEnum):
    open = "open"
    acknowledged = "acknowledged"
    resolved = "resolved"
    suppressed = "suppressed"


class AlertSource(StrEnum):
    integrity_verifier = "integrity_verifier"
    anomaly_detector = "anomaly_detector"
    security_monitor = "security_monitor"
    threat_intelligence = "threat_intelligence"
    retention_engine = "retention_engine"
    platform_monitor = "platform_monitor"


# --------------------------------------------------------------------------------------
# Reports
# --------------------------------------------------------------------------------------


class ReportStatus(StrEnum):
    draft = "draft"
    pending_review = "pending_review"
    approved = "approved"
    rejected = "rejected"
    superseded = "superseded"


class ReportFormat(StrEnum):
    pdf = "pdf"
    html = "html"
    json = "json"
    csv = "csv"


# --------------------------------------------------------------------------------------
# Operations
# --------------------------------------------------------------------------------------


class JobStatus(StrEnum):
    queued = "queued"
    running = "running"
    succeeded = "succeeded"
    failed = "failed"
    dead = "dead"
    cancelled = "cancelled"


class AuditResult(StrEnum):
    success = "success"
    failure = "failure"
    denied = "denied"


class DispositionAction(StrEnum):
    retain = "retain"
    review = "review"
    archive = "archive"
    destroy = "destroy"


class BackupStatus(StrEnum):
    running = "running"
    succeeded = "succeeded"
    failed = "failed"
    verified = "verified"


class IndicatorType(StrEnum):
    ip_address = "ip_address"
    domain = "domain"
    url = "url"
    file_hash = "file_hash"
    email_address = "email_address"
    crypto_wallet = "crypto_wallet"


class IndicatorSeverity(StrEnum):
    benign = "benign"
    suspicious = "suspicious"
    malicious = "malicious"
