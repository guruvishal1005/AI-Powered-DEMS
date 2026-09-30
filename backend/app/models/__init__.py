"""SQLAlchemy models.

Importing this package registers every table on ``Base.metadata``, which is what Alembic
autogenerate and the test harness both rely on.
"""

from __future__ import annotations

from app.models.alert import Alert, AlertEvent, Notification
from app.models.analysis import (
    AnalysisFinding,
    AnalysisRun,
    Anomaly,
    CaseRiskSnapshot,
    CorrelationEdge,
    Entity,
    EntityOccurrence,
    EntityRelationship,
    Insight,
    Observation,
    observation_entities,
)
from app.models.case import (
    Case,
    CaseAssignment,
    CaseNote,
    CasePerson,
    CaseStatusHistory,
    Finding,
    finding_evidence,
)
from app.models.custody import AuditLogEntry, CustodyEvent
from app.models.evidence import (
    Evidence,
    EvidenceNote,
    EvidenceVersion,
    IntegrityCheck,
    StoredObject,
    Tag,
    evidence_tags,
)
from app.models.intel import IndicatorMatch, ThreatIndicator
from app.models.ops import (
    Backup,
    Job,
    LegalHold,
    PeriodicTask,
    RetentionPolicy,
    SystemHealthSample,
    SystemSetting,
)
from app.models.report import Report, ReportArtifact
from app.models.user import (
    ApiToken,
    LoginAttempt,
    PermissionRecord,
    RefreshToken,
    Role,
    User,
    UserSession,
    role_permissions,
    user_roles,
)

__all__ = [
    "Alert",
    "AlertEvent",
    "AnalysisFinding",
    "AnalysisRun",
    "Anomaly",
    "ApiToken",
    "AuditLogEntry",
    "Backup",
    "Case",
    "CaseAssignment",
    "CaseNote",
    "CasePerson",
    "CaseRiskSnapshot",
    "CaseStatusHistory",
    "CorrelationEdge",
    "CustodyEvent",
    "Entity",
    "EntityOccurrence",
    "EntityRelationship",
    "Evidence",
    "EvidenceNote",
    "EvidenceVersion",
    "Finding",
    "IndicatorMatch",
    "Insight",
    "IntegrityCheck",
    "Job",
    "LegalHold",
    "LoginAttempt",
    "Notification",
    "Observation",
    "PeriodicTask",
    "PermissionRecord",
    "RefreshToken",
    "Report",
    "ReportArtifact",
    "RetentionPolicy",
    "Role",
    "StoredObject",
    "SystemHealthSample",
    "SystemSetting",
    "Tag",
    "ThreatIndicator",
    "User",
    "UserSession",
    "evidence_tags",
    "finding_evidence",
    "observation_entities",
    "role_permissions",
    "user_roles",
]
