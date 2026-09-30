"""Transparent case risk scoring.

A risk score is only useful if an investigator can see what produced it. A number that appears
without justification gets ignored the first time it disagrees with someone's judgement, and rightly
so. So this engine has one hard rule: **every point is attributable to a named component with a
stated input, and the components always sum to the total.**

The score is deliberately not machine-learned. There is no labelled corpus of "risky cases" to train
on, a learned model could not explain itself to a court, and a weighted sum of forensically
meaningful factors is both defensible and adjustable by the people who own the outcome. The weights
below are a starting position for review, not a discovered truth, and they live in one place so
changing them is a single edit with an audit trail.

Scores range 0-100 and are a triage aid: "look at this case before that one". They are not a
judgement about guilt, severity of harm, or admissibility, and the breakdown is written so nobody
can mistake them for one.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.clock import utcnow
from app.core.logging import get_logger
from app.models.analysis import (
    AnalysisFinding,
    Anomaly,
    CaseRiskSnapshot,
    CorrelationEdge,
    Entity,
    EntityOccurrence,
)
from app.models.case import Case
from app.models.enums import (
    EntityType,
    EvidenceStatus,
    IndicatorSeverity,
    IntegrityStatus,
    Severity,
)
from app.models.evidence import Evidence
from app.models.intel import IndicatorMatch, ThreatIndicator

logger = get_logger(__name__)

MODEL_VERSION = "1"

# Per-component ceilings. Capping each component is what stops one dimension owning the score: a
# case with two hundred findings and nothing else should not outrank one with a confirmed malicious
# indicator, a broken integrity check and an active cross-case link.
# The ceilings sum to exactly 100, so the score needs no final rescaling and every point on the
# scale belongs to an identifiable component.
_CAPS: dict[str, float] = {
    "finding_severity": 26.0,
    "anomalies": 13.0,
    "threat_intelligence": 18.0,
    "cross_case": 11.0,
    "integrity": 14.0,
    "high_value_indicators": 7.0,
    "recent_activity": 4.0,
    "case_severity": 7.0,
}

# Points per finding at each severity. Roughly geometric, because a critical finding is not
# incrementally worse than a high one - it usually means the case has changed character.
_FINDING_POINTS: dict[Severity, float] = {
    Severity.critical: 10.0,
    Severity.high: 5.0,
    Severity.medium: 2.0,
    Severity.low: 0.5,
    Severity.informational: 0.0,
}

_ANOMALY_POINTS: dict[Severity, float] = {
    Severity.critical: 6.0,
    Severity.high: 3.5,
    Severity.medium: 1.5,
    Severity.low: 0.5,
    Severity.informational: 0.0,
}

# Intelligence matches score higher than internal findings of the same nominal severity, because a
# match means a third party has independently observed this indicator in malicious activity.
_INTEL_POINTS: dict[IndicatorSeverity, float] = {
    IndicatorSeverity.malicious: 10.0,
    IndicatorSeverity.suspicious: 4.0,
    IndicatorSeverity.benign: 0.0,
}

# The investigator's own severity judgement is an input, not the output. It is weighted modestly:
# it reflects intake information, while everything else reflects what the evidence turned out to
# contain, and the two disagreeing is itself informative.
_CASE_SEVERITY_POINTS: dict[Severity, float] = {
    Severity.critical: 7.0,
    Severity.high: 5.0,
    Severity.medium: 3.0,
    Severity.low: 1.0,
    Severity.informational: 0.0,
}

# Types whose presence in a case indicates monetisation or attacker infrastructure rather than
# incidental technical detail.
_HIGH_VALUE_TYPES = frozenset(
    {
        EntityType.crypto_wallet,
        EntityType.payment_card,
        EntityType.file_hash,
        EntityType.credential,
    }
)

# Verification outcomes that mean the artifact can no longer be relied on. Kept as a set rather
# than a single "failed" state because the causes differ materially: altered plaintext, altered
# ciphertext, and a missing object are three different incidents.
_INTEGRITY_FAILURES = (
    IntegrityStatus.hash_mismatch,
    IntegrityStatus.decryption_failed,
    IntegrityStatus.object_missing,
)

RECENT_ACTIVITY_WINDOW = timedelta(days=7)


@dataclass(slots=True)
class RiskComponent:
    """One named contribution to a case's risk score."""

    key: str
    label: str
    points: float
    cap: float
    rationale: str
    inputs: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "label": self.label,
            "points": round(self.points, 2),
            "cap": self.cap,
            "rationale": self.rationale,
            "inputs": self.inputs,
        }


@dataclass(slots=True)
class RiskAssessment:
    """A complete score with the arithmetic behind it."""

    case_id: uuid.UUID
    components: list[RiskComponent]

    @property
    def score(self) -> float:
        return round(min(sum(component.points for component in self.components), 100.0), 2)

    @property
    def band(self) -> str:
        score = self.score
        if score >= 75:
            return "critical"
        if score >= 50:
            return "high"
        if score >= 25:
            return "moderate"
        return "low"

    def as_breakdown(self) -> dict[str, Any]:
        contributing = [
            component for component in self.components if component.points > 0
        ]
        return {
            "score": self.score,
            "band": self.band,
            "model_version": MODEL_VERSION,
            "method": (
                "capped weighted sum of forensic factors; components sum to the total score"
            ),
            "maximum_possible": sum(_CAPS.values()),
            "components": [component.as_dict() for component in self.components],
            "drivers": [
                component.label
                for component in sorted(
                    contributing, key=lambda item: item.points, reverse=True
                )[:3]
            ],
            "caveat": (
                "This score ranks cases for attention. It is not a measure of harm, culpability "
                "or evidentiary strength, and it should never be cited as a finding."
            ),
            "computed_at": utcnow().isoformat(),
        }


def _finding_component(db: Session, case_id: uuid.UUID) -> RiskComponent:
    rows = db.execute(
        select(AnalysisFinding.severity, func.count())
        .where(AnalysisFinding.case_id == case_id)
        .group_by(AnalysisFinding.severity)
    ).all()
    counts = {severity: int(count) for severity, count in rows}
    raw = sum(_FINDING_POINTS.get(sev, 0.0) * count for sev, count in counts.items())
    cap = _CAPS["finding_severity"]

    return RiskComponent(
        key="finding_severity",
        label="Analyzer findings",
        points=min(raw, cap),
        cap=cap,
        rationale=(
            "Findings raised by analyzers, weighted by severity "
            f"({', '.join(f'{count} {sev.value}' for sev, count in counts.items()) or 'none'})."
            + (f" Uncapped total was {raw:.1f}." if raw > cap else "")
        ),
        inputs={
            "counts": {sev.value: count for sev, count in counts.items()},
            "points_per_severity": {
                sev.value: points for sev, points in _FINDING_POINTS.items()
            },
            "uncapped_points": round(raw, 2),
        },
    )


def _anomaly_component(db: Session, case_id: uuid.UUID) -> RiskComponent:
    rows = db.execute(
        select(Anomaly.severity, func.count())
        .where(Anomaly.case_id == case_id, Anomaly.dismissed_at.is_(None))
        .group_by(Anomaly.severity)
    ).all()
    counts = {severity: int(count) for severity, count in rows}
    raw = sum(_ANOMALY_POINTS.get(sev, 0.0) * count for sev, count in counts.items())
    cap = _CAPS["anomalies"]

    return RiskComponent(
        key="anomalies",
        label="Statistical anomalies",
        points=min(raw, cap),
        cap=cap,
        rationale=(
            f"{sum(counts.values())} undismissed anomalies detected across the case's evidence. "
            "Anomalies an investigator has dismissed are excluded, so reviewing them lowers the "
            "score."
        ),
        inputs={
            "counts": {sev.value: count for sev, count in counts.items()},
            "excludes_dismissed": True,
            "uncapped_points": round(raw, 2),
        },
    )


def _intel_component(db: Session, case_id: uuid.UUID) -> RiskComponent:
    rows = db.execute(
        select(ThreatIndicator.severity, func.count(func.distinct(IndicatorMatch.entity_id)))
        .join(ThreatIndicator, ThreatIndicator.id == IndicatorMatch.indicator_id)
        .where(IndicatorMatch.case_id == case_id)
        .group_by(ThreatIndicator.severity)
    ).all()
    counts = {severity: int(count) for severity, count in rows}
    raw = sum(_INTEL_POINTS.get(sev, 0.0) * count for sev, count in counts.items())
    cap = _CAPS["threat_intelligence"]

    malicious = counts.get(IndicatorSeverity.malicious, 0)
    return RiskComponent(
        key="threat_intelligence",
        label="Threat intelligence matches",
        points=min(raw, cap),
        cap=cap,
        rationale=(
            f"{malicious} indicator(s) in this case are recorded as malicious by an intelligence "
            "source, and "
            f"{counts.get(IndicatorSeverity.suspicious, 0)} as suspicious. A match means a third "
            "party independently observed the value in malicious activity, which is stronger "
            "corroboration than an internal finding."
            if counts
            else "No extracted indicator matched a known intelligence record."
        ),
        inputs={
            "counts": {sev.value: count for sev, count in counts.items()},
            "counted_by": "distinct entity",
            "uncapped_points": round(raw, 2),
        },
    )


def _cross_case_component(db: Session, case_id: uuid.UUID) -> RiskComponent:
    edges = db.execute(
        select(
            func.count(),
            func.coalesce(func.max(CorrelationEdge.score), 0.0),
            func.count(
                func.distinct(
                    func.least(CorrelationEdge.source_case_id, CorrelationEdge.target_case_id)
                )
            ),
        ).where(
            CorrelationEdge.is_cross_case.is_(True),
            (CorrelationEdge.source_case_id == case_id)
            | (CorrelationEdge.target_case_id == case_id),
        )
    ).one()
    count, best, linked_cases = int(edges[0]), float(edges[1]), int(edges[2])
    cap = _CAPS["cross_case"]

    # Scaled by strength rather than count: one strong, well-explained link is more significant
    # than twenty weak ones through a shared mail relay.
    raw = min(best * 8.0 + min(count, 10) * 0.4, cap)

    return RiskComponent(
        key="cross_case",
        label="Cross-case links",
        points=raw,
        cap=cap,
        rationale=(
            f"{count} correlation edge(s) link this case to {max(linked_cases - 1, 0)} other "
            f"case(s), the strongest scoring {best:.2f}. A case connected to others may be part of "
            "a campaign rather than an isolated incident."
            if count
            else "No shared indicators connect this case to any other."
        ),
        inputs={
            "edge_count": count,
            "strongest_edge_score": round(best, 4),
            "formula": "min(strongest * 8 + min(edges, 10) * 0.4, cap)",
        },
    )


def _integrity_component(db: Session, case_id: uuid.UUID) -> RiskComponent:
    rows = db.execute(
        select(Evidence.integrity_status, func.count())
        .where(
            Evidence.case_id == case_id,
            Evidence.status != EvidenceStatus.disposed,
        )
        .group_by(Evidence.integrity_status)
    ).all()
    counts = {status: int(count) for status, count in rows}
    failed = sum(counts.get(status, 0) for status in _INTEGRITY_FAILURES)
    unverified = counts.get(IntegrityStatus.pending, 0)
    cap = _CAPS["integrity"]

    raw = min(failed * cap + unverified * 1.0, cap)

    return RiskComponent(
        key="integrity",
        label="Evidence integrity",
        points=raw,
        cap=cap,
        rationale=(
            f"{failed} item(s) failed integrity verification and {unverified} have not yet been "
            "verified. A single verification failure takes this component to its ceiling: it puts "
            "the reliability of the case's evidence in question regardless of what that evidence "
            "contains."
            if failed or unverified
            else "Every item in this case verifies against its recorded hash."
        ),
        inputs={
            "counts": {status.value: count for status, count in counts.items()},
            "failed": failed,
            "awaiting_verification": unverified,
            "failure_states": [status.value for status in _INTEGRITY_FAILURES],
        },
    )


def _high_value_indicator_component(db: Session, case_id: uuid.UUID) -> RiskComponent:
    rows = db.execute(
        select(Entity.type, func.count(func.distinct(Entity.id)))
        .join(EntityOccurrence, EntityOccurrence.entity_id == Entity.id)
        .where(
            EntityOccurrence.case_id == case_id,
            Entity.type.in_(_HIGH_VALUE_TYPES),
        )
        .group_by(Entity.type)
    ).all()
    counts = {entity_type: int(count) for entity_type, count in rows}
    cap = _CAPS["high_value_indicators"]
    raw = min(sum(min(count, 3) * 2.0 for count in counts.values()), cap)

    return RiskComponent(
        key="high_value_indicators",
        label="Monetisation indicators",
        points=raw,
        cap=cap,
        rationale=(
            "The case contains "
            + ", ".join(
                f"{count} {entity_type.value.replace('_', ' ')}(s)"
                for entity_type, count in counts.items()
            )
            + ". Payment and file-hash indicators point to monetisation or reusable attacker "
            "tooling, both of which raise the likelihood of organised rather than opportunistic "
            "activity."
            if counts
            else "No payment, wallet or file-hash indicators were extracted."
        ),
        inputs={
            "counts": {
                entity_type.value: count for entity_type, count in counts.items()
            },
            "per_type_cap": 3,
        },
    )


def _recent_activity_component(db: Session, case_id: uuid.UUID) -> RiskComponent:
    since = utcnow() - RECENT_ACTIVITY_WINDOW
    recent = int(
        db.scalar(
            select(func.count())
            .select_from(Evidence)
            .where(Evidence.case_id == case_id, Evidence.created_at >= since)
        )
        or 0
    )
    cap = _CAPS["recent_activity"]
    raw = min(recent * 1.0, cap)

    return RiskComponent(
        key="recent_activity",
        label="Recent ingestion activity",
        points=raw,
        cap=cap,
        rationale=(
            f"{recent} item(s) were ingested in the last {RECENT_ACTIVITY_WINDOW.days} days. "
            "Active cases are ranked slightly higher so that triage favours work in progress over "
            "dormant matters."
            if recent
            else f"No evidence ingested in the last {RECENT_ACTIVITY_WINDOW.days} days."
        ),
        inputs={
            "window_days": RECENT_ACTIVITY_WINDOW.days,
            "items_ingested": recent,
        },
    )


def _case_severity_component(case: Case) -> RiskComponent:
    points = _CASE_SEVERITY_POINTS.get(case.severity, 0.0)
    return RiskComponent(
        key="case_severity",
        label="Assigned case severity",
        points=points,
        cap=_CAPS["case_severity"],
        rationale=(
            f"An investigator classified this case as {case.severity.value} at intake. This is a "
            "human judgement about the reported incident, weighted modestly because the remaining "
            "components measure what the evidence itself turned out to contain."
        ),
        inputs={
            "assigned_severity": case.severity.value,
            "points_per_severity": {
                sev.value: points for sev, points in _CASE_SEVERITY_POINTS.items()
            },
        },
    )


def assess_case(db: Session, case: Case) -> RiskAssessment:
    """Compute a case's risk score with a full component breakdown."""
    return RiskAssessment(
        case_id=case.id,
        components=[
            _finding_component(db, case.id),
            _anomaly_component(db, case.id),
            _intel_component(db, case.id),
            _cross_case_component(db, case.id),
            _integrity_component(db, case.id),
            _high_value_indicator_component(db, case.id),
            _recent_activity_component(db, case.id),
            _case_severity_component(case),
        ],
    )


def score_case(db: Session, case: Case) -> RiskAssessment:
    """Compute, cache on the case, and snapshot a risk score.

    The snapshot exists so a score can be defended after the fact. A report generated in March
    citing a risk of 82 must remain explicable in September, when the live score has moved because
    more evidence arrived - and without a historical record, that number would look like an error.
    """
    assessment = assess_case(db, case)
    breakdown = assessment.as_breakdown()

    previous = case.risk_score
    case.risk_score = assessment.score
    case.risk_breakdown = breakdown
    case.risk_computed_at = utcnow()

    # Snapshots record change, not every recomputation: an unchanged score adds a row that says
    # nothing, and the history becomes unreadable at the point when someone needs it.
    if previous is None or abs(float(previous) - assessment.score) >= 0.01:
        db.add(
            CaseRiskSnapshot(
                case_id=case.id,
                score=assessment.score,
                breakdown=breakdown,
                model_version=MODEL_VERSION,
            )
        )

    db.flush()
    logger.info(
        "case_risk_scored",
        case=case.reference,
        score=assessment.score,
        band=assessment.band,
        previous=float(previous) if previous is not None else None,
    )
    return assessment
