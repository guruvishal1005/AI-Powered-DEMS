"""Insight generation: turning recorded facts into things worth an investigator's attention.

An insight has two parts, and keeping them apart is the entire point of this module:

``observed``
    What the evidence records. Every clause is traceable to a persisted row, and the artifacts it
    came from are listed in ``evidence_refs`` with locators, so a reader can open the source.

``interpretation``
    What those facts might mean. Inference, labelled as inference, phrased so that alternative
    explanations remain visible.

The split exists because a forensic report must distinguish what was found from what an investigator
concluded, and software that blurs the two will eventually put an inference in front of a court
wearing the clothes of a fact. Here the boundary is a schema constraint rather than a writing
convention: they are separate columns, rendered under separate headings, and no generator is
permitted to write an inference into ``observed``.

Insights are also ranked, because an investigation that produces four hundred of them has produced
none. ``rank_score`` combines severity with corroboration, so an item supported by three independent
artifacts outranks a lone signal of the same nominal severity.
"""

from __future__ import annotations

import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.intelligence import risk
from app.intelligence.llm import (
    DisabledLLMProvider,
    NarrativeRequest,
    get_provider,
    narrate_safely,
)
from app.models.analysis import (
    AnalysisFinding,
    Anomaly,
    CorrelationEdge,
    Entity,
    EntityOccurrence,
    Insight,
    Observation,
)
from app.models.case import Case
from app.models.enums import (
    SEVERITY_WEIGHT,
    EvidenceStatus,
    IndicatorSeverity,
    InsightKind,
    InsightProvenance,
    IntegrityStatus,
    Severity,
)
from app.models.evidence import Evidence
from app.models.intel import IndicatorMatch, ThreatIndicator

logger = get_logger(__name__)

GENERATOR_VERSION = "1"

# An entity in this many or more artifacts is a pivot: the thread that ties a case together and
# usually the most productive next step for an investigator.
PIVOT_MIN_EVIDENCE = 3


@dataclass(slots=True)
class DraftInsight:
    """A candidate insight before persistence."""

    kind: InsightKind
    provenance: InsightProvenance
    severity: Severity
    title: str
    observed: str
    dedupe_key: str
    generator: str
    interpretation: str | None = None
    confidence: float = 1.0
    evidence_refs: list[dict[str, Any]] = field(default_factory=list)
    entity_refs: list[dict[str, Any]] = field(default_factory=list)
    case_refs: list[dict[str, Any]] = field(default_factory=list)
    basis: dict[str, Any] = field(default_factory=dict)
    #: Values that legitimately appear in this insight's facts, so narration validation can tell an
    #: identifier that was already established from one a model invented.
    permitted_terms: set[str] = field(default_factory=set)

    @property
    def rank_score(self) -> float:
        """Severity, raised by corroboration and by confidence.

        Corroboration is deliberately sub-linear: the jump from one supporting artifact to two is
        the significant one, and a signal appearing in twenty artifacts is often background noise
        rather than twenty times the signal.
        """
        base = float(SEVERITY_WEIGHT.get(self.severity, 0)) * 20.0
        corroboration = min(len(self.evidence_refs), 6) * 3.0
        cross_case = 8.0 if len(self.case_refs) > 1 else 0.0
        return round((base + corroboration + cross_case) * self.confidence, 2)


def _evidence_ref(evidence: Evidence, note: str | None = None) -> dict[str, Any]:
    """A citation an investigator can follow back to the artifact."""
    ref: dict[str, Any] = {
        "evidence_id": str(evidence.id),
        "reference": evidence.reference,
        "title": evidence.title,
    }
    if note:
        ref["note"] = note
    return ref


def correlation_insights(db: Session, case: Case) -> list[DraftInsight]:
    """Surface the strongest links between artifacts inside this case."""
    edges = db.scalars(
        select(CorrelationEdge)
        .where(
            CorrelationEdge.is_cross_case.is_(False),
            (CorrelationEdge.source_case_id == case.id),
        )
        .order_by(CorrelationEdge.score.desc())
        .limit(10)
    ).all()

    drafts: list[DraftInsight] = []
    for edge in edges:
        source = db.get(Evidence, edge.source_evidence_id)
        target = db.get(Evidence, edge.target_evidence_id)
        if source is None or target is None:  # pragma: no cover - cascade keeps these present
            continue

        terms = edge.basis.get("shared_terms", [])
        values = [str(term.get("value")) for term in terms[:5] if term.get("value")]
        rarest = terms[0] if terms else {}
        remainder = len(terms) - len(values)

        drafts.append(
            DraftInsight(
                kind=InsightKind.correlation,
                provenance=InsightProvenance.statistical,
                severity=Severity.medium if edge.score >= 0.7 else Severity.low,
                title=f"{source.reference} and {target.reference} share {len(terms)} indicators",
                observed=(
                    f"{source.reference} ({source.title}) and {target.reference} "
                    f"({target.title}) both contain "
                    + ", ".join(values)
                    + (f" and {remainder} further values" if remainder > 0 else "")
                    + ". "
                    + (
                        f"The most distinctive of these, {rarest.get('value')}, appears in "
                        f"{rarest.get('document_frequency')} of "
                        f"{rarest.get('corpus_size')} registered items."
                        if rarest
                        else ""
                    )
                ),
                interpretation=(
                    "Shared indicators of this rarity usually mean the two artifacts document the "
                    "same activity or the same actor. They can also mean both simply reference "
                    "common infrastructure, so confirm that the shared values are specific to the "
                    "incident before treating the link as established."
                ),
                confidence=round(min(edge.score, 0.95), 2),
                evidence_refs=[
                    _evidence_ref(source, "shares the indicators listed"),
                    _evidence_ref(target, "shares the indicators listed"),
                ],
                entity_refs=[
                    {
                        "entity_id": term.get("entity_id"),
                        "type": term.get("type"),
                        "value": term.get("value"),
                        "document_frequency": term.get("document_frequency"),
                    }
                    for term in terms[:10]
                ],
                basis={
                    "correlation_edge_id": str(edge.id),
                    "score": edge.score,
                    "method": edge.basis.get("method"),
                    "formula": edge.basis.get("formula"),
                    "shared_terms": terms[:10],
                },
                dedupe_key=f"correlation:{edge.id}",
                generator="correlation_insights",
                permitted_terms=set(values)
                | {source.reference, target.reference},
            )
        )

    return drafts


def cross_case_insights(db: Session, case: Case) -> list[DraftInsight]:
    """Report links to other investigations.

    The highest-value output of the platform: a connection nobody made manually, between cases that
    may be different officers' work and would otherwise never be compared.
    """
    edges = db.scalars(
        select(CorrelationEdge)
        .where(
            CorrelationEdge.is_cross_case.is_(True),
            (CorrelationEdge.source_case_id == case.id)
            | (CorrelationEdge.target_case_id == case.id),
        )
        .order_by(CorrelationEdge.score.desc())
    ).all()
    if not edges:
        return []

    grouped: dict[uuid.UUID, list[CorrelationEdge]] = defaultdict(list)
    for edge in edges:
        other = edge.target_case_id if edge.source_case_id == case.id else edge.source_case_id
        grouped[other].append(edge)

    drafts: list[DraftInsight] = []
    for other_case_id, case_edges in grouped.items():
        other_case = db.get(Case, other_case_id)
        if other_case is None:  # pragma: no cover
            continue

        shared: dict[str, dict[str, Any]] = {}
        for edge in case_edges:
            for term in edge.basis.get("shared_terms", []):
                value = str(term.get("value"))
                if value not in shared or term.get("document_frequency", 99) < shared[
                    value
                ].get("document_frequency", 99):
                    shared[value] = term

        rarest = sorted(
            shared.values(), key=lambda term: term.get("document_frequency", 99)
        )[:5]
        best = max(edge.score for edge in case_edges)

        evidence_ids = {
            reference
            for edge in case_edges
            for reference in (edge.source_evidence_id, edge.target_evidence_id)
        }
        items = db.scalars(select(Evidence).where(Evidence.id.in_(evidence_ids))).all()

        drafts.append(
            DraftInsight(
                kind=InsightKind.cross_case_link,
                provenance=InsightProvenance.statistical,
                severity=Severity.high if best >= 0.7 else Severity.medium,
                title=f"Shared indicators link this case to {other_case.reference}",
                observed=(
                    f"{len(case_edges)} pair(s) of artifacts across this case and "
                    f"{other_case.reference} ({other_case.title}) contain the same values. The "
                    "most distinctive are "
                    + ", ".join(
                        f"{term.get('value')} "
                        f"(in {term.get('document_frequency')} of "
                        f"{term.get('corpus_size')} items)"
                        for term in rarest
                    )
                    + f". {other_case.reference} is recorded as "
                    f"{other_case.incident_type.value.replace('_', ' ')} with status "
                    f"{other_case.status.value.replace('_', ' ')}."
                ),
                interpretation=(
                    "Indicators this specific recurring across separate investigations is "
                    "consistent with a single actor or campaign behind both. Before treating the "
                    "cases as related, confirm the shared values are not common infrastructure and "
                    "check whether both cases simply drew evidence from the same source system."
                ),
                confidence=round(min(best, 0.9), 2),
                evidence_refs=[_evidence_ref(item) for item in items][:10],
                entity_refs=[
                    {
                        "entity_id": term.get("entity_id"),
                        "type": term.get("type"),
                        "value": term.get("value"),
                        "document_frequency": term.get("document_frequency"),
                    }
                    for term in rarest
                ],
                case_refs=[
                    {"case_id": str(case.id), "reference": case.reference},
                    {
                        "case_id": str(other_case.id),
                        "reference": other_case.reference,
                        "title": other_case.title,
                        "status": other_case.status.value,
                    },
                ],
                basis={
                    "edge_count": len(case_edges),
                    "strongest_score": best,
                    "method": "IDF-weighted shared indicators across case boundaries",
                    "shared_indicator_count": len(shared),
                },
                dedupe_key=f"cross_case:{other_case_id}",
                generator="cross_case_insights",
                permitted_terms={str(term.get("value")) for term in rarest}
                | {other_case.reference, case.reference},
            )
        )

    return drafts


def anomaly_insights(db: Session, case: Case) -> list[DraftInsight]:
    """Promote the significant anomalies into ranked insights."""
    anomalies = db.scalars(
        select(Anomaly)
        .where(
            Anomaly.case_id == case.id,
            Anomaly.dismissed_at.is_(None),
            Anomaly.severity.in_([Severity.medium, Severity.high, Severity.critical]),
        )
        .order_by(Anomaly.created_at.desc())
        .limit(25)
    ).all()

    drafts: list[DraftInsight] = []
    for anomaly in anomalies:
        evidence = (
            db.get(Evidence, anomaly.evidence_id) if anomaly.evidence_id else None
        )
        measurement = (
            f"Measured {anomaly.observed_value} against a baseline of "
            f"{anomaly.baseline_value} over {anomaly.sample_size} samples, using "
            f"{anomaly.method}."
            if anomaly.observed_value is not None and anomaly.baseline_value is not None
            else f"Detected by {anomaly.method}."
        )

        drafts.append(
            DraftInsight(
                kind=InsightKind.anomaly,
                provenance=InsightProvenance.statistical,
                severity=anomaly.severity,
                title=anomaly.title,
                observed=f"{anomaly.description} {measurement}",
                interpretation=_interpretation_for(anomaly),
                confidence=0.8,
                evidence_refs=[_evidence_ref(evidence)] if evidence else [],
                basis={
                    "anomaly_id": str(anomaly.id),
                    "kind": anomaly.kind.value,
                    "method": anomaly.method,
                    "threshold": anomaly.threshold,
                    "observed_value": anomaly.observed_value,
                    "baseline_value": anomaly.baseline_value,
                    "deviation": anomaly.deviation,
                    "sample_size": anomaly.sample_size,
                    "detector": anomaly.detector,
                    "detector_version": anomaly.detector_version,
                },
                dedupe_key=f"anomaly:{anomaly.id}",
                generator="anomaly_insights",
                permitted_terms={evidence.reference} if evidence else set(),
            )
        )

    return drafts


def _interpretation_for(anomaly: Anomaly) -> str:
    """The inference side of an anomaly insight.

    Combines the analyzer's own explanation, where the anomaly was promoted from a finding, with the
    per-kind guidance below. Both are inference, so both belong here rather than in ``observed`` -
    an analyzer saying a failure is "consistent with spoofing" is expert interpretation, however
    well founded, and mixing it into the facts would make the split decorative.
    """
    parts: list[str] = []

    narrative = (anomaly.attributes or {}).get("analyzer_narrative")
    if isinstance(narrative, str) and narrative.strip():
        parts.append(narrative.strip())

    caveat = (anomaly.attributes or {}).get("method_caveat")
    if isinstance(caveat, str) and caveat.strip():
        parts.append(caveat.strip())

    parts.append(_anomaly_guidance(anomaly))
    return " ".join(parts)


def _anomaly_guidance(anomaly: Anomaly) -> str:
    """Per-kind guidance on what an anomaly may mean, and what would disprove it.

    Each entry names the innocent explanation as well as the suspicious one. An interpretation that
    only offers the incriminating reading is not analysis, it is confirmation bias with a schema.
    """
    guidance = {
        "temporal_burst": (
            "Concentrated activity in a short window is characteristic of automated tooling, bulk "
            "exfiltration or a scripted attack. It is equally consistent with a scheduled backup "
            "or batch job, so establish what normally runs in that window before drawing a "
            "conclusion."
        ),
        "off_hours_activity": (
            "Activity outside working hours can indicate access by someone avoiding observation, "
            "or automation. Confirm the subject's actual working pattern and the source system's "
            "timezone first, since both routinely explain this."
        ),
        "failed_login_burst": (
            "Repeated authentication failures from one source indicate a credential attack. "
            "Whether it succeeded determines the scope of the incident, so check for a subsequent "
            "successful authentication from the same source and for any change to that account."
        ),
        "mime_extension_mismatch": (
            "A file whose actual format contradicts its extension is a common delivery technique "
            "for executable content. It also happens through careless renaming, so examine the "
            "content itself rather than relying on the mismatch alone."
        ),
        "high_entropy_content": (
            "Localised high entropy indicates encrypted, compressed or packed data. In a document "
            "or executable that often means an embedded payload; in an archive or media file it is "
            "entirely normal."
        ),
        "timestamp_inconsistency": (
            "Timestamps that cannot be reconciled suggest either an incorrect system clock or "
            "modification after collection. This bears directly on whether the artifact can be "
            "relied on, so resolve it before building on anything the artifact contains."
        ),
        "email_spoofing_indicator": (
            "Header and authentication anomalies indicate the message did not originate where it "
            "claims. Established sender-authentication failure is strong support for a spoofing or "
            "impersonation finding."
        ),
        "volume_outlier": (
            "An unusual data volume can indicate exfiltration or a deliberately malformed "
            "artifact. Compare against what this source normally produces before concluding."
        ),
        "access_outside_scope": (
            "Access to resources outside the subject's normal pattern can indicate reconnaissance "
            "or privilege misuse. Verify what access was legitimately granted before treating it "
            "as unauthorised."
        ),
    }
    return guidance.get(
        anomaly.kind.value,
        "Review the recorded measurement against the case's own baseline before drawing a "
        "conclusion from it.",
    )


def integrity_insights(db: Session, case: Case) -> list[DraftInsight]:
    """Report evidence whose integrity is in question.

    Ranked critical without qualification. Every other insight is about what the evidence shows;
    this one is about whether the evidence can be shown at all, and it must never be buried under a
    list of interesting correlations.
    """
    failed = db.scalars(
        select(Evidence).where(
            Evidence.case_id == case.id,
            Evidence.integrity_status.in_(
                [
                    IntegrityStatus.hash_mismatch,
                    IntegrityStatus.decryption_failed,
                    IntegrityStatus.object_missing,
                ]
            ),
        )
    ).all()
    if not failed:
        return []

    explanations = {
        IntegrityStatus.hash_mismatch: (
            "the stored bytes no longer hash to the value recorded at acquisition"
        ),
        IntegrityStatus.decryption_failed: (
            "the encrypted object failed its authentication tag, meaning the ciphertext itself was "
            "altered"
        ),
        IntegrityStatus.object_missing: "the stored object is absent from the backend",
    }

    return [
        DraftInsight(
            kind=InsightKind.integrity,
            provenance=InsightProvenance.derived,
            severity=Severity.critical,
            title=f"{len(failed)} item(s) in this case failed integrity verification",
            observed=(
                "Verification failed for "
                + "; ".join(
                    f"{item.reference} "
                    f"({explanations.get(item.integrity_status, 'verification failed')})"
                    for item in failed[:8]
                )
                + (f"; and {len(failed) - 8} more" if len(failed) > 8 else "")
                + ". Each item's last successful verification and the full custody history are "
                "recorded against it."
            ),
            interpretation=(
                "Evidence that does not verify against its acquisition hash cannot be relied on "
                "until the discrepancy is explained. The cause may be storage corruption rather "
                "than tampering, but the distinction has to be established and documented, and "
                "any finding that depends on these items should be treated as provisional until "
                "it is."
            ),
            evidence_refs=[
                _evidence_ref(item, item.integrity_status.value) for item in failed[:20]
            ],
            basis={
                "failed_count": len(failed),
                "statuses": sorted({item.integrity_status.value for item in failed}),
                "method": "SHA-256 comparison against the hash recorded at acquisition",
            },
            dedupe_key="integrity:failed",
            generator="integrity_insights",
            permitted_terms={item.reference for item in failed},
        )
    ]


def intel_insights(db: Session, case: Case) -> list[DraftInsight]:
    """Report indicators that a threat intelligence source considers malicious."""
    rows = db.execute(
        select(Entity, ThreatIndicator, func.count(func.distinct(IndicatorMatch.evidence_id)))
        .join(IndicatorMatch, IndicatorMatch.entity_id == Entity.id)
        .join(ThreatIndicator, ThreatIndicator.id == IndicatorMatch.indicator_id)
        .where(
            IndicatorMatch.case_id == case.id,
            ThreatIndicator.severity == IndicatorSeverity.malicious,
        )
        .group_by(Entity.id, ThreatIndicator.id)
        .order_by(func.count(func.distinct(IndicatorMatch.evidence_id)).desc())
        .limit(15)
    ).all()
    if not rows:
        return []

    drafts: list[DraftInsight] = []
    for entity, indicator, evidence_count in rows:
        items = db.scalars(
            select(Evidence)
            .join(IndicatorMatch, IndicatorMatch.evidence_id == Evidence.id)
            .where(
                IndicatorMatch.entity_id == entity.id,
                IndicatorMatch.case_id == case.id,
            )
            .distinct()
        ).all()

        attribution = ", ".join(
            part
            for part in (
                f"attributed to {indicator.threat_actor}" if indicator.threat_actor else "",
                f"associated with {indicator.malware_family}"
                if indicator.malware_family
                else "",
            )
            if part
        )

        drafts.append(
            DraftInsight(
                kind=InsightKind.entity_pivot,
                provenance=InsightProvenance.derived,
                severity=Severity.high,
                title=f"{entity.display_value} is a known malicious indicator",
                observed=(
                    f"The {entity.type.value.replace('_', ' ')} {entity.display_value} appears in "
                    f"{evidence_count} item(s) in this case and is recorded as malicious by "
                    f"{indicator.source}"
                    + (f", {attribution}" if attribution else "")
                    + f". Source description: {indicator.description or 'none supplied'}."
                ),
                interpretation=(
                    "A third-party intelligence match is independent corroboration that this value "
                    "has been observed in malicious activity elsewhere. Intelligence records do go "
                    "stale, so confirm the source's dates cover the period of this incident before "
                    "relying on the match."
                ),
                confidence=round(min(indicator.confidence, 0.95), 2),
                evidence_refs=[_evidence_ref(item) for item in items][:10],
                entity_refs=[
                    {
                        "entity_id": str(entity.id),
                        "type": entity.type.value,
                        "value": entity.display_value,
                    }
                ],
                basis={
                    "indicator_id": str(indicator.id),
                    "source": indicator.source,
                    "source_reference": indicator.source_reference,
                    "severity": indicator.severity.value,
                    "confidence": indicator.confidence,
                    "tags": indicator.tags,
                    "first_seen_at": indicator.first_seen_at.isoformat()
                    if indicator.first_seen_at
                    else None,
                    "last_seen_at": indicator.last_seen_at.isoformat()
                    if indicator.last_seen_at
                    else None,
                },
                dedupe_key=f"intel:{indicator.id}:{entity.id}",
                generator="intel_insights",
                permitted_terms={entity.display_value}
                | {item.reference for item in items},
            )
        )

    return drafts


def pivot_insights(db: Session, case: Case) -> list[DraftInsight]:
    """Identify the entities that tie the most artifacts together.

    A pivot is where an investigator should look next. Surfacing it explicitly saves the work of
    cross-referencing entity lists by eye, which is exactly the work software should absorb.
    """
    rows = db.execute(
        select(
            Entity,
            func.count(func.distinct(EntityOccurrence.evidence_id)).label("items"),
            func.sum(EntityOccurrence.occurrence_count).label("mentions"),
        )
        .join(EntityOccurrence, EntityOccurrence.entity_id == Entity.id)
        .where(EntityOccurrence.case_id == case.id)
        .group_by(Entity.id)
        .having(func.count(func.distinct(EntityOccurrence.evidence_id)) >= PIVOT_MIN_EVIDENCE)
        .order_by(func.count(func.distinct(EntityOccurrence.evidence_id)).desc())
        .limit(5)
    ).all()

    total_items = int(
        db.scalar(
            select(func.count()).select_from(Evidence).where(Evidence.case_id == case.id)
        )
        or 0
    )
    if not rows or total_items < PIVOT_MIN_EVIDENCE:
        return []

    drafts: list[DraftInsight] = []
    for entity, item_count, mentions in rows:
        items = db.scalars(
            select(Evidence)
            .join(EntityOccurrence, EntityOccurrence.evidence_id == Evidence.id)
            .where(
                EntityOccurrence.entity_id == entity.id,
                EntityOccurrence.case_id == case.id,
            )
            .distinct()
        ).all()

        coverage = item_count / total_items if total_items else 0.0
        drafts.append(
            DraftInsight(
                kind=InsightKind.entity_pivot,
                provenance=InsightProvenance.derived,
                severity=Severity.low if coverage < 0.5 else Severity.medium,
                title=(
                    f"{entity.display_value} appears across {item_count} of "
                    f"{total_items} items"
                ),
                observed=(
                    f"The {entity.type.value.replace('_', ' ')} {entity.display_value} was "
                    f"extracted from {item_count} of the {total_items} items in this case, with "
                    f"{int(mentions or 0)} total mentions. Across the whole platform it appears in "
                    f"{entity.document_frequency} item(s) and {entity.case_count} case(s)."
                ),
                interpretation=(
                    "An entity present in most of a case's evidence is usually either central to "
                    "the incident or part of the environment it happened in. Its rarity across the "
                    "rest of the platform is what separates the two: a value confined to this case "
                    "is a stronger lead than one appearing everywhere."
                ),
                evidence_refs=[_evidence_ref(item) for item in items][:12],
                entity_refs=[
                    {
                        "entity_id": str(entity.id),
                        "type": entity.type.value,
                        "value": entity.display_value,
                        "document_frequency": entity.document_frequency,
                        "case_count": entity.case_count,
                    }
                ],
                basis={
                    "items_containing": item_count,
                    "case_items": total_items,
                    "coverage": round(coverage, 3),
                    "total_mentions": int(mentions or 0),
                    "corpus_document_frequency": entity.document_frequency,
                    "method": "distinct evidence count per entity within the case",
                },
                dedupe_key=f"pivot:{entity.id}",
                generator="pivot_insights",
                permitted_terms={entity.display_value}
                | {item.reference for item in items},
            )
        )

    return drafts


def temporal_insights(db: Session, case: Case) -> list[DraftInsight]:
    """Describe the shape of the case's timeline: its span, density and gaps."""
    row = db.execute(
        select(
            func.count(),
            func.min(Observation.occurred_at),
            func.max(Observation.occurred_at),
        ).where(Observation.case_id == case.id)
    ).one()
    count, earliest, latest = int(row[0]), row[1], row[2]
    if count < 10 or earliest is None or latest is None:
        return []

    span = latest - earliest
    assumed = int(
        db.scalar(
            select(func.count())
            .select_from(Observation)
            .where(
                Observation.case_id == case.id,
                Observation.timezone_assumed.is_(True),
            )
        )
        or 0
    )

    return [
        DraftInsight(
            kind=InsightKind.temporal_pattern,
            provenance=InsightProvenance.derived,
            severity=Severity.informational,
            title=f"Timeline spans {_describe_span(span)} across {count} events",
            observed=(
                f"{count} timestamped events were recovered from this case's evidence, running "
                f"from {earliest.isoformat()} to {latest.isoformat()}, a span of "
                f"{_describe_span(span)}."
                + (
                    f" {assumed} of these came from sources that recorded no timezone and are "
                    "stored as UTC."
                    if assumed
                    else " Every event carried an explicit timezone."
                )
            ),
            interpretation=(
                "The span establishes the window the evidence covers. Events outside it are "
                "unsupported by anything currently held, which may indicate a gap in acquisition "
                "worth closing."
                + (
                    " Because some timestamps had no timezone, ordering between sources may be "
                    "wrong by hours, and any sequence argument should be checked against a source "
                    "that does record one."
                    if assumed
                    else ""
                )
            ),
            basis={
                "event_count": count,
                "earliest": earliest.isoformat(),
                "latest": latest.isoformat(),
                "span_seconds": int(span.total_seconds()),
                "timezone_assumed_events": assumed,
                "method": "min/max of observation timestamps within the case",
            },
            dedupe_key="temporal:span",
            generator="temporal_insights",
        )
    ]


def coverage_insights(db: Session, case: Case) -> list[DraftInsight]:
    """Report what has *not* been established.

    Absence of analysis is invisible by nature - a case with unanalysed evidence looks exactly like
    one with nothing to find - and an investigator drawing conclusions from a partial picture is a
    real failure mode. Stating the gap explicitly is the only way to make it visible.
    """
    pending = db.scalars(
        select(Evidence).where(
            Evidence.case_id == case.id,
            Evidence.status.in_([EvidenceStatus.registered, EvidenceStatus.processing]),
        )
    ).all()
    unanalysed = [
        item
        for item in pending
        if not db.scalar(
            select(func.count())
            .select_from(AnalysisFinding)
            .where(AnalysisFinding.evidence_id == item.id)
        )
    ]
    if not unanalysed:
        return []

    return [
        DraftInsight(
            kind=InsightKind.coverage_gap,
            provenance=InsightProvenance.derived,
            severity=Severity.medium,
            title=f"{len(unanalysed)} item(s) have not completed analysis",
            observed=(
                f"{len(unanalysed)} item(s) in this case are still awaiting or undergoing "
                "analysis: "
                + ", ".join(item.reference for item in unanalysed[:10])
                + (f" and {len(unanalysed) - 10} more" if len(unanalysed) > 10 else "")
                + ". No findings, entities or timeline events from these items are included in "
                "anything else on this page."
            ),
            interpretation=(
                "The case's current findings are based on an incomplete picture. Correlation, "
                "timeline and risk output will change as these items complete, so conclusions "
                "drawn now should be revisited afterwards."
            ),
            evidence_refs=[
                _evidence_ref(item, item.status.value) for item in unanalysed[:20]
            ],
            basis={
                "pending_count": len(unanalysed),
                "statuses": sorted({item.status.value for item in unanalysed}),
                "method": "evidence with no persisted findings and a non-terminal status",
            },
            dedupe_key="coverage:pending_analysis",
            generator="coverage_insights",
            permitted_terms={item.reference for item in unanalysed},
        )
    ]


def risk_insight(db: Session, case: Case) -> list[DraftInsight]:
    """Explain the case's risk score in terms of its own components."""
    assessment = risk.assess_case(db, case)
    breakdown = assessment.as_breakdown()
    contributing = [
        component for component in assessment.components if component.points > 0
    ]
    if not contributing:
        return []

    return [
        DraftInsight(
            kind=InsightKind.risk_assessment,
            provenance=InsightProvenance.statistical,
            severity=(
                Severity.high
                if assessment.band in {"critical", "high"}
                else Severity.low
            ),
            title=f"Risk score {assessment.score:.0f} of 100 ({assessment.band})",
            observed=(
                f"The case scores {assessment.score:.1f} of a possible 100. "
                + " ".join(
                    f"{component.label}: {component.points:.1f} of {component.cap:.0f}."
                    for component in sorted(
                        contributing, key=lambda item: item.points, reverse=True
                    )[:5]
                )
            ),
            interpretation=(
                "This score orders cases for attention using a fixed weighted sum of forensic "
                "factors. It is not a measure of harm, culpability or evidentiary strength, and it "
                "should not appear in a report as a finding. Every component and its input is "
                "listed so the number can be checked rather than trusted."
            ),
            basis=breakdown,
            dedupe_key="risk:current",
            generator="risk_insight",
        )
    ]


def _describe_span(span: timedelta) -> str:
    days = span.days
    if days >= 365:
        return f"{days / 365.25:.1f} years"
    if days >= 1:
        return f"{days} day(s)"
    hours = span.total_seconds() / 3600
    if hours >= 1:
        return f"{hours:.1f} hours"
    return f"{span.total_seconds() / 60:.0f} minutes"


GENERATORS = (
    integrity_insights,
    intel_insights,
    cross_case_insights,
    anomaly_insights,
    correlation_insights,
    pivot_insights,
    temporal_insights,
    coverage_insights,
    risk_insight,
)


def generate_for_case(db: Session, case: Case, *, narrate: bool = True) -> dict[str, Any]:
    """Regenerate every insight for a case."""
    drafts: list[DraftInsight] = []
    failures: list[str] = []

    for generator in GENERATORS:
        try:
            drafts.extend(generator(db, case))
        except Exception as exc:
            failures.append(f"{generator.__name__}: {type(exc).__name__}: {exc}")
            logger.exception("insight_generator_failed", generator=generator.__name__)

    narrated = _narrate(drafts) if narrate else 0
    created, updated, removed = _persist(db, case, drafts)

    logger.info(
        "insights_generated",
        case=case.reference,
        drafts=len(drafts),
        created=created,
        updated=updated,
        removed=removed,
        narrated=narrated,
        failures=len(failures),
    )
    return {
        "drafted": len(drafts),
        "created": created,
        "updated": updated,
        "removed": removed,
        "narrated": narrated,
        "generator_failures": failures,
    }


def _narrate(drafts: list[DraftInsight]) -> int:
    """Attach optional model-written prose to the highest-ranked insights.

    Only the top few, and only if a provider is configured. Narration is cosmetic, so spending a
    model call on the fortieth insight nobody will read is waste, and the deterministic text is
    always what gets persisted in ``observed``.
    """
    provider = get_provider()
    if isinstance(provider, DisabledLLMProvider):
        return 0

    ranked = sorted(drafts, key=lambda draft: draft.rank_score, reverse=True)[:5]
    narrated = 0

    for draft in ranked:
        facts = [draft.observed]
        if draft.interpretation:
            facts.append(draft.interpretation)

        result = narrate_safely(
            provider,
            NarrativeRequest(
                subject=draft.title,
                facts=facts,
                permitted_terms=draft.permitted_terms,
            ),
        )
        if result is None:
            continue

        draft.basis = {
            **draft.basis,
            "llm_narrative": {
                "provider": result.provider,
                "model": result.model,
                "role": "phrasing only; introduced no facts",
            },
        }
        draft.basis["_narrative_text"] = result.text
        draft.basis["_narrative_model"] = result.model
        narrated += 1

    return narrated


def _persist(
    db: Session, case: Case, drafts: list[DraftInsight]
) -> tuple[int, int, int]:
    """Reconcile drafts against stored insights, preserving analyst decisions.

    Dismissals and pins are investigator decisions and survive regeneration. Everything else is
    recomputed: an insight whose supporting facts no longer hold must not linger, because a stale
    insight is worse than none - it reads as current.
    """
    existing = {
        insight.dedupe_key: insight
        for insight in db.scalars(select(Insight).where(Insight.case_id == case.id)).all()
    }

    created = 0
    updated = 0
    seen: set[str] = set()

    for draft in drafts:
        seen.add(draft.dedupe_key)
        narrative = draft.basis.pop("_narrative_text", None)
        model = draft.basis.pop("_narrative_model", None)
        provenance = (
            InsightProvenance.llm_assisted if narrative else draft.provenance
        )

        current = existing.get(draft.dedupe_key)
        if current is None:
            db.add(
                Insight(
                    case_id=case.id,
                    kind=draft.kind,
                    provenance=provenance,
                    severity=draft.severity,
                    confidence=draft.confidence,
                    title=draft.title[:240],
                    observed=draft.observed,
                    interpretation=draft.interpretation,
                    llm_narrative=narrative,
                    llm_model=model,
                    evidence_refs=draft.evidence_refs,
                    entity_refs=draft.entity_refs,
                    case_refs=draft.case_refs,
                    basis=draft.basis,
                    rank_score=draft.rank_score,
                    generator=draft.generator[:64],
                    generator_version=GENERATOR_VERSION,
                    dedupe_key=draft.dedupe_key[:128],
                )
            )
            created += 1
            continue

        current.kind = draft.kind
        current.provenance = provenance
        current.severity = draft.severity
        current.confidence = draft.confidence
        current.title = draft.title[:240]
        current.observed = draft.observed
        current.interpretation = draft.interpretation
        current.llm_narrative = narrative
        current.llm_model = model
        current.evidence_refs = draft.evidence_refs
        current.entity_refs = draft.entity_refs
        current.case_refs = draft.case_refs
        current.basis = draft.basis
        current.rank_score = draft.rank_score
        current.generator_version = GENERATOR_VERSION
        updated += 1

    removed = 0
    for key, insight in existing.items():
        if key in seen:
            continue
        if insight.dismissed_at is not None or insight.is_pinned:
            continue
        db.delete(insight)
        removed += 1

    db.flush()
    return created, updated, removed
