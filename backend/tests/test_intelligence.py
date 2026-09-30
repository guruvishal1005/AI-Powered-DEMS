"""Correlation, anomaly, risk and insight tests.

These build real cases by ingesting real artifacts and running the real analysis pipeline, then
assert on what the intelligence layer derives from them. Nothing is stubbed, because the properties
worth testing here only exist end to end: whether a rare shared wallet address outranks a shared
private IP depends on document frequencies that only exist once several artifacts have actually been
analysed.

The emphasis is on the guarantees that matter forensically rather than on line coverage:

* rarity actually changes the ranking, so a distinctive value beats a ubiquitous one;
* correlations that no longer hold are removed rather than left to go stale;
* anomalies record the arithmetic that produced them and stay silent on small samples;
* risk components sum to the published score;
* an analyst's dismissal survives recomputation;
* insights never state an inference in the ``observed`` field;
* the LLM boundary rejects prose that invents an identifier.
"""

from __future__ import annotations

import io
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.analysis.pipeline import analyze_evidence
from app.core.clock import utcnow
from app.intelligence import anomalies, correlation, insights, llm, risk, threatintel
from app.models.analysis import (
    Anomaly,
    CorrelationEdge,
    Entity,
    EntityOccurrence,
    Insight,
    Observation,
)
from app.models.case import Case
from app.models.enums import (
    AnomalyKind,
    Confidence,
    EntityType,
    EvidenceType,
    IncidentType,
    IndicatorSeverity,
    IndicatorType,
    InsightKind,
    InsightProvenance,
    IntegrityStatus,
    ObservationKind,
    Severity,
)
from app.models.evidence import Evidence
from app.models.intel import ThreatIndicator
from app.models.user import User
from app.services import case_service, evidence_service
from tests.conftest import context_for

# A wallet address shared between two cases. Distinctive by construction: it appears in exactly the
# artifacts these tests create, so its document frequency stays low and its IDF weight stays high.
SHARED_WALLET = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
SHARED_ATTACKER_IP = "203.0.113.66"

RANSOM_NOTE = f"""All your files have been encrypted with AES-256.
To obtain the decryption key you must transfer 4.5 BTC to {SHARED_WALLET}.
Contact us at recovery-desk@mail-drop.example within 72 hours.
Our infrastructure: {SHARED_ATTACKER_IP}
After the deadline the decryption key is destroyed permanently.
""".encode()

EXTORTION_EMAIL = f"""Received: from relay.attacker-infra.example
\t(attacker-vps.example [{SHARED_ATTACKER_IP}])
\tby mx.victim.example (Postfix) with ESMTP id 9F8E7D6C
\tfor <finance@victim.example>; Mon, 15 Jan 2024 10:30:00 +0000
Authentication-Results: mx.victim.example; spf=fail smtp.mailfrom=mail-drop.example;
\tdkim=none; dmarc=fail
From: "Recovery Desk" <recovery-desk@trusted-vendor.example>
Reply-To: <recovery-desk@mail-drop.example>
To: finance@victim.example
Subject: Your files
Date: Mon, 15 Jan 2024 10:29:00 +0000
Message-ID: <extortion-1@mail-drop.example>
Content-Type: text/plain

Payment of 4.5 BTC to {SHARED_WALLET} restores your data.
""".encode()

# A second case's artifact sharing only the wallet, which is what should produce a cross-case link.
SECOND_CASE_NOTE = f"""Victim reports funds were transferred following an extortion demand.
The beneficiary address supplied by the offender was {SHARED_WALLET}.
Internal ticketing host 192.168.1.10 recorded the report.
""".encode()

# Shares only a private address that appears in most artifacts, and should therefore not correlate.
UNRELATED_NOTE = b"""Routine asset inventory export.
Internal ticketing host 192.168.1.10 recorded the report.
Nothing further of note.
"""

# Carries both the distinctive wallet and the ubiquitous internal host, so a single pair can be used
# to compare how the two are weighted against each other.
MIXED_NOTE = f"""Case handover summary.
The offender's beneficiary address was {SHARED_WALLET}.
Internal ticketing host 192.168.1.10 recorded the report.
""".encode()


def make_case(
    db: Session,
    investigator: User,
    analyst: User,
    *,
    title: str,
    incident_type: IncidentType = IncidentType.ransomware,
    severity: Severity = Severity.high,
) -> Case:
    ctx = context_for(investigator)
    case = case_service.create_case(
        db,
        ctx,
        title=title,
        summary=f"{title}. Created by the intelligence test suite.",
        incident_type=incident_type,
        severity=severity,
    )
    case_service.assign_user(db, ctx, case.id, user_id=analyst.id)
    db.flush()
    return case


def ingest_and_analyze(
    db: Session,
    user: User,
    case: Case,
    content: bytes,
    filename: str,
    *,
    evidence_type: EvidenceType | None = None,
    acquired_at: datetime | None = None,
) -> Evidence:
    """Register an artifact and run the real analyzers over it."""
    ctx = context_for(user)
    evidence = evidence_service.ingest_evidence(
        db,
        ctx,
        case_id=case.id,
        stream=io.BytesIO(content),
        original_filename=filename,
        evidence_type=evidence_type,
        acquired_at=acquired_at or datetime(2024, 2, 1, tzinfo=UTC),
        acquired_by_name="DC Rowan Idris",
    )
    analyze_evidence(db, ctx, evidence)
    db.flush()
    return evidence


@pytest.fixture
def ransomware_case(
    db: Session, investigator: User, analyst: User, storage_root: object
) -> tuple[Case, list[Evidence]]:
    """One case with two artifacts that share a wallet and an attacker address."""
    case = make_case(db, investigator, analyst, title="Ransomware deployment")
    items = [
        ingest_and_analyze(db, analyst, case, RANSOM_NOTE, "readme-decrypt.txt"),
        ingest_and_analyze(db, analyst, case, EXTORTION_EMAIL, "demand.eml"),
        ingest_and_analyze(db, analyst, case, UNRELATED_NOTE, "inventory.txt"),
    ]
    return case, items


class TestCorrelationScoring:
    def test_a_rare_shared_value_outweighs_a_ubiquitous_one(
        self, db: Session, investigator: User, analyst: User, storage_root: object
    ) -> None:
        """Rarity, not count, must drive the score.

        This is the property the whole engine exists for. Weighted equally, an artifact sharing only
        the organisation's own internal host would rank alongside one sharing a specific ransom
        wallet, and the ranking would be worthless. Both values are put in a single pair so the
        comparison is between two terms scored under identical conditions.
        """
        case = make_case(db, investigator, analyst, title="Rarity ordering")
        mixed_a = ingest_and_analyze(db, analyst, case, MIXED_NOTE, "handover-a.txt")
        ingest_and_analyze(db, analyst, case, MIXED_NOTE + b"Duplicate note.\n", "handover-b.txt")

        # Several artifacts carrying only the common internal address, so its document frequency
        # climbs while the wallet's stays low.
        for index in range(5):
            ingest_and_analyze(
                db,
                analyst,
                case,
                UNRELATED_NOTE + f"Record {index}\n".encode(),
                f"inventory-{index}.txt",
            )

        pairs = correlation.score_pairs_for_evidence(db, mixed_a)
        assert pairs

        terms = {
            term.value: term for pair in pairs for term in pair.terms
        }
        wallet = terms.get(SHARED_WALLET)
        common = terms.get("192.168.1.10")
        assert wallet is not None, "the wallet is shared and must be scored"
        assert common is not None, "the internal host is shared and must be scored"

        assert common.document_frequency > wallet.document_frequency
        assert wallet.idf > common.idf
        assert wallet.contribution > common.contribution, (
            "a distinctive wallet must contribute more than an address present in most of the "
            f"corpus: {wallet.contribution} vs {common.contribution}"
        )

    def test_a_small_corpus_still_produces_correlations(
        self, db: Session, investigator: User, analyst: User, storage_root: object
    ) -> None:
        """With two artifacts, textbook IDF gives every shared value a weight of zero.

        That would leave a fresh deployment unable to correlate anything - not because nothing is
        related, but because rarity is undefined with nothing to be rare against. The nominal corpus
        floor exists for exactly this case, and the substitution has to be visible in the basis.
        """
        case = make_case(db, investigator, analyst, title="Small corpus")
        first = ingest_and_analyze(db, analyst, case, RANSOM_NOTE, "note.txt")
        ingest_and_analyze(db, analyst, case, EXTORTION_EMAIL, "demand.eml")

        pairs = correlation.score_pairs_for_evidence(db, first)
        assert pairs, "two related artifacts must correlate even in a two-item corpus"

        term = next(term for term in pairs[0].terms if term.value == SHARED_WALLET)
        assert term.corpus_size == 2
        assert term.weighting_corpus_size == correlation.MIN_WEIGHTING_CORPUS
        assert term.idf > 0

        explanation = correlation.explain(pairs[0])
        assert "nominal corpus" in explanation, (
            "an explanation must disclose that weighting used a nominal corpus rather than the "
            "two items actually held"
        )

    def test_every_edge_records_the_arithmetic_behind_its_score(
        self, db: Session, ransomware_case: tuple[Case, list[Evidence]]
    ) -> None:
        """An edge that cannot be explained should not exist."""
        case, items = ransomware_case
        correlation.correlate_evidence(db, items[0])
        db.flush()

        edges = db.scalars(
            select(CorrelationEdge).where(CorrelationEdge.source_case_id == case.id)
        ).all()
        assert edges

        for edge in edges:
            assert edge.explanation, "every edge must carry prose explaining it"
            assert edge.basis["method"]
            assert edge.basis["formula"]
            assert edge.basis["shared_terms"]
            for term in edge.basis["shared_terms"]:
                # Each term must publish enough for a reader to recompute its own contribution.
                assert {
                    "value",
                    "document_frequency",
                    "corpus_size",
                    "weighting_corpus_size",
                    "idf",
                    "type_weight",
                } <= set(term)
                expected = round(
                    correlation.idf(
                        term["document_frequency"], term["weighting_corpus_size"]
                    )
                    * term["type_weight"],
                    4,
                )
                assert abs(term["contribution"] - expected) < 0.001

    def test_cross_case_links_are_marked_and_reported(
        self, db: Session, investigator: User, analyst: User, storage_root: object
    ) -> None:
        """A wallet shared across two investigations must surface as a cross-case link."""
        first = make_case(db, investigator, analyst, title="Ransomware, victim one")
        second = make_case(
            db,
            investigator,
            analyst,
            title="Fraudulent transfer, victim two",
            incident_type=IncidentType.financial_fraud,
        )

        source = ingest_and_analyze(db, analyst, first, RANSOM_NOTE, "note.txt")
        ingest_and_analyze(db, analyst, second, SECOND_CASE_NOTE, "statement.txt")

        correlation.correlate_evidence(db, source)
        db.flush()

        edges = db.scalars(
            select(CorrelationEdge).where(CorrelationEdge.is_cross_case.is_(True))
        ).all()
        assert edges, "the shared wallet should link the two cases"

        edge = edges[0]
        assert {edge.source_case_id, edge.target_case_id} == {first.id, second.id}
        assert SHARED_WALLET in {
            term["value"] for term in edge.basis["shared_terms"]
        }
        assert "different cases" in edge.explanation

        summary = correlation.cross_case_links(db, first.id)
        assert summary
        assert summary[0]["case_id"] == str(second.id)
        assert SHARED_WALLET in summary[0]["shared_indicators"]

    def test_an_edge_that_no_longer_holds_is_removed(
        self, db: Session, ransomware_case: tuple[Case, list[Evidence]]
    ) -> None:
        """Stale edges are worse than missing ones, because they read as current."""
        _case, items = ransomware_case
        correlation.correlate_evidence(db, items[0])
        db.flush()

        before = db.scalar(
            select(func.count())
            .select_from(CorrelationEdge)
            .where(
                (CorrelationEdge.source_evidence_id == items[0].id)
                | (CorrelationEdge.target_evidence_id == items[0].id)
            )
        )
        assert before

        # Simulate an improved analyzer that stops extracting the values that justified the edges.
        db.execute(
            EntityOccurrence.__table__.delete().where(
                EntityOccurrence.evidence_id == items[0].id
            )
        )
        db.flush()

        correlation.correlate_evidence(db, items[0])
        db.flush()

        after = db.scalar(
            select(func.count())
            .select_from(CorrelationEdge)
            .where(
                (CorrelationEdge.source_evidence_id == items[0].id)
                | (CorrelationEdge.target_evidence_id == items[0].id)
            )
        )
        assert after == 0, "edges must not outlive the entities that justified them"

    def test_recomputation_updates_rather_than_duplicates(
        self, db: Session, ransomware_case: tuple[Case, list[Evidence]]
    ) -> None:
        _case, items = ransomware_case
        correlation.correlate_evidence(db, items[0])
        db.flush()
        first_count = db.scalar(select(func.count()).select_from(CorrelationEdge))

        correlation.correlate_evidence(db, items[0])
        db.flush()
        second_count = db.scalar(select(func.count()).select_from(CorrelationEdge))

        assert first_count == second_count


class TestAnomalyDetection:
    def test_small_samples_produce_no_anomalies(
        self, db: Session, investigator: User, analyst: User, storage_root: object
    ) -> None:
        """A z-score over a handful of points is arithmetic, not evidence."""
        case = make_case(db, investigator, analyst, title="Thin evidence")
        ingest_and_analyze(db, analyst, case, UNRELATED_NOTE, "note.txt")

        found = anomalies.detect_temporal_bursts(db, case.id)
        assert found == []

    def test_burst_detection_reports_its_own_baseline(
        self, db: Session, investigator: User, analyst: User, storage_root: object
    ) -> None:
        """A detected burst must publish the baseline it was measured against."""
        case = make_case(db, investigator, analyst, title="Burst detection")
        evidence = ingest_and_analyze(db, analyst, case, UNRELATED_NOTE, "note.txt")

        base = datetime(2024, 1, 10, 3, 0, tzinfo=UTC)
        # A sparse background of one event per hour...
        for hour in range(12):
            db.add(
                _observation(case, evidence, base + timedelta(hours=hour), f"quiet {hour}")
            )
        # ...and one hour with a large spike.
        spike_hour = base + timedelta(hours=20)
        for minute in range(40):
            db.add(
                _observation(
                    case, evidence, spike_hour + timedelta(minutes=minute), f"spike {minute}"
                )
            )
        db.flush()

        found = anomalies.detect_temporal_bursts(db, case.id)
        assert len(found) == 1

        burst = found[0]
        assert burst.kind == AnomalyKind.temporal_burst
        assert burst.observed_value == 40.0
        assert burst.baseline_value is not None and burst.baseline_value < 5
        assert burst.deviation is not None and burst.deviation >= 3.0
        assert burst.threshold == anomalies.BURST_Z_THRESHOLD
        assert burst.sample_size and burst.sample_size >= 8
        assert "z-score" in burst.method
        assert burst.window_start == spike_hour

    def test_credential_attack_across_the_case_is_detected_and_escalated(
        self, db: Session, investigator: User, analyst: User, storage_root: object
    ) -> None:
        """Failures spread thinly across hosts are invisible per-file but visible per-case."""
        case = make_case(db, investigator, analyst, title="Credential attack")
        evidence = ingest_and_analyze(db, analyst, case, UNRELATED_NOTE, "note.txt")

        base = datetime(2024, 1, 10, 2, 0, tzinfo=UTC)
        for index in range(12):
            db.add(
                _observation(
                    case,
                    evidence,
                    base + timedelta(seconds=index * 20),
                    f"failed login {index}",
                    kind=ObservationKind.login_failure,
                    source_value=SHARED_ATTACKER_IP,
                    actor_value=f"user{index}",
                )
            )
        db.add(
            _observation(
                case,
                evidence,
                base + timedelta(minutes=6),
                "successful login",
                kind=ObservationKind.login_success,
                source_value=SHARED_ATTACKER_IP,
                actor_value="user3",
            )
        )
        db.flush()

        found = anomalies.detect_failed_login_bursts(db, case.id)
        assert len(found) == 1

        burst = found[0]
        assert burst.severity == Severity.critical, (
            "an attack followed by a success from the same source is materially worse than one "
            "that only produced failures"
        )
        assert burst.attributes["followed_by_success"] is True
        assert burst.attributes["password_spraying"] is True
        assert burst.attributes["distinct_accounts"] == 12
        # The description states what was recorded; what it implies belongs to the interpretation.
        assert "A successful authentication from the same source is also recorded" in (
            burst.description
        )
        assert "treated as having succeeded" not in burst.description

    def test_aggregated_observations_count_their_underlying_events(
        self, db: Session, investigator: User, analyst: User, storage_root: object
    ) -> None:
        """One aggregated row can stand for thousands of log lines.

        Counting rows rather than events would understate an attack by orders of magnitude, which
        is precisely the kind of quiet undercount that makes a detector worse than none.
        """
        case = make_case(db, investigator, analyst, title="Aggregated failures")
        evidence = ingest_and_analyze(db, analyst, case, UNRELATED_NOTE, "note.txt")

        base = datetime(2024, 1, 10, 2, 0, tzinfo=UTC)
        for index in range(5):
            observation = _observation(
                case,
                evidence,
                base + timedelta(minutes=index),
                f"aggregated failures {index}",
                kind=ObservationKind.login_failure,
                source_value="198.51.100.7",
                actor_value="admin",
            )
            observation.attributes = {"occurrence_count": 400}
            db.add(observation)
        db.flush()

        found = anomalies.detect_failed_login_bursts(db, case.id)
        assert len(found) == 1
        assert found[0].observed_value == 2000.0

    def test_content_dated_after_acquisition_is_flagged(
        self, db: Session, investigator: User, analyst: User, storage_root: object
    ) -> None:
        """Content cannot postdate its own collection."""
        case = make_case(db, investigator, analyst, title="Clock disagreement")
        evidence = ingest_and_analyze(
            db,
            analyst,
            case,
            UNRELATED_NOTE,
            "note.txt",
            acquired_at=datetime(2024, 1, 1, tzinfo=UTC),
        )

        for index in range(6):
            db.add(
                _observation(
                    case,
                    evidence,
                    datetime(2024, 3, 1, tzinfo=UTC) + timedelta(hours=index),
                    f"impossible {index}",
                )
            )
        db.flush()

        found = anomalies.detect_timestamp_inconsistencies(db, case.id)
        assert len(found) == 1
        assert found[0].kind == AnomalyKind.timestamp_inconsistency
        assert found[0].severity == Severity.high
        assert found[0].attributes["drift_seconds"] > 0
        assert "later than the item's recorded acquisition time" in found[0].description

    def test_a_dismissed_anomaly_survives_recomputation(
        self, db: Session, investigator: User, analyst: User, storage_root: object
    ) -> None:
        """Dismissal is an investigator's decision and must not be silently undone."""
        case = make_case(db, investigator, analyst, title="Dismissal persistence")
        evidence = ingest_and_analyze(db, analyst, case, UNRELATED_NOTE, "note.txt")

        base = datetime(2024, 1, 10, 2, 0, tzinfo=UTC)
        for index in range(12):
            db.add(
                _observation(
                    case,
                    evidence,
                    base + timedelta(seconds=index * 20),
                    f"failed login {index}",
                    kind=ObservationKind.login_failure,
                    source_value=SHARED_ATTACKER_IP,
                    actor_value=f"user{index}",
                )
            )
        db.flush()

        anomalies.detect_for_case(db, case.id)
        db.flush()

        stored = db.scalars(
            select(Anomaly).where(
                Anomaly.case_id == case.id,
                Anomaly.kind == AnomalyKind.failed_login_burst,
            )
        ).all()
        assert stored
        target = stored[0]
        target.dismissed_at = utcnow()
        target.dismissed_reason = "Authorised penetration test, confirmed with the client."
        db.flush()

        # Remove the supporting observations, so the anomaly would no longer be detected at all.
        db.execute(
            Observation.__table__.delete().where(Observation.case_id == case.id)
        )
        db.flush()

        anomalies.detect_for_case(db, case.id)
        db.flush()

        surviving = db.get(Anomaly, target.id)
        assert surviving is not None, (
            "a dismissed anomaly records a decision and must not be deleted by a later sweep"
        )
        assert surviving.dismissed_reason is not None

    def test_analyzer_findings_are_projected_without_being_recomputed(
        self, db: Session, ransomware_case: tuple[Case, list[Evidence]]
    ) -> None:
        """A promoted finding must carry its source, so the two views cannot disagree."""
        case, _items = ransomware_case
        found = anomalies.promote_analyzer_findings(db, case.id)

        for candidate in found:
            assert candidate.attributes["source_finding_code"]
            assert candidate.attributes["source_analyzer"]
            assert candidate.attributes["source_analyzer_version"]

    def test_one_failing_detector_does_not_silence_the_others(
        self, db: Session, ransomware_case: tuple[Case, list[Evidence]], monkeypatch
    ) -> None:
        """A total silent failure is indistinguishable from a case with nothing unusual in it."""
        case, _items = ransomware_case

        def exploding(db: Session, case_id: uuid.UUID) -> list[anomalies.DetectedAnomaly]:
            raise RuntimeError("detector blew up")

        monkeypatch.setattr(
            anomalies,
            "DETECTORS",
            (exploding, anomalies.promote_analyzer_findings),
        )

        result = anomalies.detect_for_case(db, case.id)
        assert result["detector_failures"], "the failure must be reported, not swallowed"
        assert "exploding" in result["detector_failures"][0]
        assert result["detected"] >= 0


def _observation(
    case: Case,
    evidence: Evidence,
    occurred_at: datetime,
    summary: str,
    *,
    kind: ObservationKind = ObservationKind.log_entry,
    source_value: str | None = None,
    actor_value: str | None = None,
) -> Observation:
    """A synthetic observation, for detectors that need a controlled distribution.

    Constructed directly rather than derived from a fixture file: reproducing a precise z-score
    from real log content would need a log crafted so carefully that the test's intent would be
    buried in the fixture.
    """
    return Observation(
        evidence_id=evidence.id,
        case_id=case.id,
        kind=kind,
        occurred_at=occurred_at,
        time_confidence=Confidence.high,
        summary=summary,
        source_value=source_value,
        actor_value=actor_value,
        analyzer="test_fixture",
        analyzer_version="1",
        locator={"synthetic": True},
        attributes={},
    )


class TestRiskScoring:
    def test_components_sum_to_the_published_score(
        self, db: Session, ransomware_case: tuple[Case, list[Evidence]]
    ) -> None:
        """A score whose parts do not add up cannot be defended."""
        case, _items = ransomware_case
        assessment = risk.assess_case(db, case)

        total = sum(component.points for component in assessment.components)
        assert abs(total - assessment.score) < 0.01
        assert 0 <= assessment.score <= 100

    def test_every_component_states_its_inputs(
        self, db: Session, ransomware_case: tuple[Case, list[Evidence]]
    ) -> None:
        case, _items = ransomware_case
        breakdown = risk.assess_case(db, case).as_breakdown()

        assert breakdown["maximum_possible"] == 100
        assert breakdown["method"]
        assert breakdown["caveat"]
        for component in breakdown["components"]:
            assert component["rationale"], f"{component['key']} must explain itself"
            assert component["points"] <= component["cap"]
            assert isinstance(component["inputs"], dict)

    def test_an_integrity_failure_dominates_its_component(
        self, db: Session, ransomware_case: tuple[Case, list[Evidence]]
    ) -> None:
        """Evidence that does not verify is a different class of problem to an interesting finding."""
        case, items = ransomware_case
        before = _component(risk.assess_case(db, case), "integrity")

        items[0].integrity_status = IntegrityStatus.hash_mismatch
        db.flush()

        after = _component(risk.assess_case(db, case), "integrity")
        assert after.points == after.cap
        assert after.points > before.points
        assert "reliability of the case's evidence" in after.rationale

    def test_dismissing_an_anomaly_lowers_the_score(
        self, db: Session, investigator: User, analyst: User, storage_root: object
    ) -> None:
        """Reviewing an anomaly must be able to reduce risk, or nobody will review any."""
        case = make_case(db, investigator, analyst, title="Dismissal lowers risk")
        evidence = ingest_and_analyze(db, analyst, case, UNRELATED_NOTE, "note.txt")

        db.add(
            Anomaly(
                case_id=case.id,
                evidence_id=evidence.id,
                kind=AnomalyKind.temporal_burst,
                severity=Severity.high,
                title="Synthetic burst",
                description="Injected for scoring purposes.",
                method="test fixture",
                detector="test",
            )
        )
        db.flush()

        before = _component(risk.assess_case(db, case), "anomalies").points
        assert before > 0

        stored = db.scalars(select(Anomaly).where(Anomaly.case_id == case.id)).all()
        for anomaly in stored:
            anomaly.dismissed_at = utcnow()
        db.flush()

        after = _component(risk.assess_case(db, case), "anomalies").points
        assert after < before

    def test_scoring_snapshots_only_on_change(
        self, db: Session, ransomware_case: tuple[Case, list[Evidence]]
    ) -> None:
        """A history full of identical rows is unreadable at the moment it is needed."""
        case, _items = ransomware_case
        from app.models.analysis import CaseRiskSnapshot

        risk.score_case(db, case)
        db.flush()
        first = db.scalar(
            select(func.count())
            .select_from(CaseRiskSnapshot)
            .where(CaseRiskSnapshot.case_id == case.id)
        )

        risk.score_case(db, case)
        db.flush()
        second = db.scalar(
            select(func.count())
            .select_from(CaseRiskSnapshot)
            .where(CaseRiskSnapshot.case_id == case.id)
        )

        assert first == second == 1
        assert case.risk_score is not None
        assert case.risk_breakdown["components"]


def _component(assessment: risk.RiskAssessment, key: str) -> risk.RiskComponent:
    return next(
        component for component in assessment.components if component.key == key
    )


class TestThreatIntelligence:
    def test_a_matching_indicator_is_recorded_and_attributed(
        self, db: Session, ransomware_case: tuple[Case, list[Evidence]]
    ) -> None:
        case, _items = ransomware_case
        db.add(
            ThreatIndicator(
                type=IndicatorType.crypto_wallet,
                canonical_value=SHARED_WALLET,
                severity=IndicatorSeverity.malicious,
                confidence=0.9,
                source="test_feed",
                source_reference="https://example.invalid/report",
                description="Wallet observed collecting ransom payments.",
                tags=["ransomware", "payment"],
                threat_actor="TEST-ACTOR",
                malware_family="TestLocker",
            )
        )
        db.flush()

        result = threatintel.check_case(db, case.id)
        assert result["matched"] == 1
        assert result["recorded"] >= 1
        assert result["provider_failures"] == []

        entity = db.scalars(
            select(Entity).where(Entity.canonical_value == SHARED_WALLET)
        ).one()
        assert entity.intel_severity == IndicatorSeverity.malicious
        assert "source:test_feed" in entity.intel_tags
        assert entity.intel_checked_at is not None

    def test_an_expired_indicator_does_not_match(
        self, db: Session, ransomware_case: tuple[Case, list[Evidence]]
    ) -> None:
        """Reputation decays; matching on a stale record produces confident nonsense."""
        case, _items = ransomware_case
        db.add(
            ThreatIndicator(
                type=IndicatorType.crypto_wallet,
                canonical_value=SHARED_WALLET,
                severity=IndicatorSeverity.malicious,
                confidence=0.9,
                source="stale_feed",
                description="Historic record.",
                expires_at=utcnow() - timedelta(days=1),
            )
        )
        db.flush()

        result = threatintel.check_case(db, case.id)
        assert result["matched"] == 0

    def test_checked_with_no_match_is_distinguishable_from_never_checked(
        self, db: Session, ransomware_case: tuple[Case, list[Evidence]]
    ) -> None:
        case, _items = ransomware_case
        threatintel.check_case(db, case.id)
        db.flush()

        entity = db.scalars(
            select(Entity).where(Entity.canonical_value == SHARED_WALLET)
        ).one()
        assert entity.intel_checked_at is not None
        assert entity.intel_severity is None

    def test_a_failing_provider_does_not_mark_values_as_clean(
        self, db: Session, ransomware_case: tuple[Case, list[Evidence]]
    ) -> None:
        """Saying "nothing is known about this" is a claim, and a failed lookup cannot support it."""
        case, _items = ransomware_case

        class BrokenProvider(threatintel.ThreatIntelProvider):
            name = "broken"

            def lookup(self, values):  # type: ignore[no-untyped-def]
                raise RuntimeError("feed unreachable")

        result = threatintel.check_case(db, case.id, providers=[BrokenProvider()])
        assert result["provider_failures"]

        entity = db.scalars(
            select(Entity).where(Entity.canonical_value == SHARED_WALLET)
        ).one()
        assert entity.intel_checked_at is None


class TestInsightGeneration:
    def test_observed_and_interpretation_stay_separate(
        self, db: Session, ransomware_case: tuple[Case, list[Evidence]]
    ) -> None:
        """The split is the point: a fact and an inference must never arrive merged."""
        case, items = ransomware_case
        correlation.correlate_evidence(db, items[0])
        anomalies.detect_for_case(db, case.id)
        db.flush()

        insights.generate_for_case(db, case)
        db.flush()

        stored = db.scalars(select(Insight).where(Insight.case_id == case.id)).all()
        assert stored

        hedges = ("may mean", "usually", "can also", "consistent with", "suggests", "likely")
        for insight in stored:
            assert insight.observed.strip()
            assert insight.evidence_refs is not None
            assert insight.basis, f"{insight.generator} produced no basis"
            # Interpretive language belongs in `interpretation`, never in `observed`.
            assert not any(hedge in insight.observed.lower() for hedge in hedges), (
                f"{insight.generator} put interpretive language in the observed field: "
                f"{insight.observed!r}"
            )

    def test_analyzer_explanations_land_in_interpretation_not_in_observed(
        self, db: Session, ransomware_case: tuple[Case, list[Evidence]]
    ) -> None:
        """An analyzer's expert explanation is inference, however well founded.

        The email analyzer says a sender-authentication failure is "consistent with spoofing". That
        is a conclusion, not a measurement, so it must appear on the interpretation side while the
        recorded verdicts stay on the observed side.
        """
        case, _items = ransomware_case
        anomalies.detect_for_case(db, case.id)
        db.flush()
        insights.generate_for_case(db, case)
        db.flush()

        spoofing = db.scalars(
            select(Anomaly).where(
                Anomaly.case_id == case.id,
                Anomaly.kind == AnomalyKind.email_spoofing_indicator,
            )
        ).all()
        assert spoofing, "the spoofed extortion email should raise a spoofing anomaly"
        assert any(
            anomaly.attributes.get("analyzer_narrative") for anomaly in spoofing
        ), "the analyzer's prose must be preserved, not discarded"

        insight = db.scalars(
            select(Insight).where(
                Insight.case_id == case.id,
                Insight.kind == InsightKind.anomaly,
                Insight.basis["kind"].as_string()
                == AnomalyKind.email_spoofing_indicator.value,
            )
        ).first()
        assert insight is not None
        assert insight.interpretation is not None
        assert "consistent with spoofing" in insight.interpretation
        assert "consistent with" not in insight.observed
        # The measurement itself must survive into the observed half.
        assert "email_headers" in insight.observed

    def test_evidence_refs_point_at_real_artifacts(
        self, db: Session, ransomware_case: tuple[Case, list[Evidence]]
    ) -> None:
        """A citation an investigator cannot follow is not a citation."""
        case, items = ransomware_case
        correlation.correlate_evidence(db, items[0])
        db.flush()
        insights.generate_for_case(db, case)
        db.flush()

        references = {item.reference for item in items}
        stored = db.scalars(select(Insight).where(Insight.case_id == case.id)).all()

        for insight in stored:
            for ref in insight.evidence_refs:
                assert uuid.UUID(ref["evidence_id"])
                assert ref["reference"] in references

    def test_integrity_failure_outranks_everything_else(
        self, db: Session, ransomware_case: tuple[Case, list[Evidence]]
    ) -> None:
        """Whether the evidence can be relied on comes before what it shows."""
        case, items = ransomware_case
        items[0].integrity_status = IntegrityStatus.hash_mismatch
        db.flush()

        insights.generate_for_case(db, case)
        db.flush()

        ranked = db.scalars(
            select(Insight)
            .where(Insight.case_id == case.id)
            .order_by(Insight.rank_score.desc())
        ).all()
        assert ranked
        assert ranked[0].kind == InsightKind.integrity
        assert ranked[0].severity == Severity.critical

    def test_unanalysed_evidence_is_reported_as_a_gap(
        self, db: Session, investigator: User, analyst: User, storage_root: object
    ) -> None:
        """A case with unanalysed evidence looks exactly like one with nothing to find."""
        case = make_case(db, investigator, analyst, title="Partial coverage")
        evidence_service.ingest_evidence(
            db,
            context_for(analyst),
            case_id=case.id,
            stream=io.BytesIO(RANSOM_NOTE),
            original_filename="unanalysed.txt",
            acquired_at=datetime(2024, 2, 1, tzinfo=UTC),
            acquired_by_name="DC Rowan Idris",
        )
        db.flush()

        insights.generate_for_case(db, case)
        db.flush()

        gaps = db.scalars(
            select(Insight).where(
                Insight.case_id == case.id,
                Insight.kind == InsightKind.coverage_gap,
            )
        ).all()
        assert gaps, "an incomplete picture must be stated, not implied"
        assert "incomplete" in gaps[0].interpretation.lower()

    def test_a_dismissed_insight_survives_regeneration(
        self, db: Session, ransomware_case: tuple[Case, list[Evidence]]
    ) -> None:
        case, items = ransomware_case
        correlation.correlate_evidence(db, items[0])
        db.flush()
        insights.generate_for_case(db, case)
        db.flush()

        stored = db.scalars(select(Insight).where(Insight.case_id == case.id)).all()
        target = stored[0]
        target.dismissed_at = utcnow()
        target.dismissed_reason = "Known internal infrastructure."
        db.flush()

        insights.generate_for_case(db, case)
        db.flush()

        assert db.get(Insight, target.id) is not None

    def test_regeneration_does_not_duplicate(
        self, db: Session, ransomware_case: tuple[Case, list[Evidence]]
    ) -> None:
        case, items = ransomware_case
        correlation.correlate_evidence(db, items[0])
        db.flush()

        insights.generate_for_case(db, case)
        db.flush()
        first = db.scalar(
            select(func.count()).select_from(Insight).where(Insight.case_id == case.id)
        )

        insights.generate_for_case(db, case)
        db.flush()
        second = db.scalar(
            select(func.count()).select_from(Insight).where(Insight.case_id == case.id)
        )

        assert first == second

    def test_insights_are_deterministic_without_a_language_model(
        self, db: Session, ransomware_case: tuple[Case, list[Evidence]]
    ) -> None:
        """With no provider configured, nothing may claim to be LLM assisted."""
        case, items = ransomware_case
        correlation.correlate_evidence(db, items[0])
        db.flush()
        insights.generate_for_case(db, case)
        db.flush()

        stored = db.scalars(select(Insight).where(Insight.case_id == case.id)).all()
        for insight in stored:
            assert insight.llm_narrative is None
            assert insight.llm_model is None
            assert insight.provenance in {
                InsightProvenance.derived,
                InsightProvenance.statistical,
            }


class TestLanguageModelBoundary:
    def test_prose_inventing_an_identifier_is_rejected(self) -> None:
        """The failure that matters most: an invented address looks exactly like a real one."""
        request = llm.NarrativeRequest(
            subject="Correlation",
            facts=["Evidence EV-1 and EV-2 both contain 203.0.113.66."],
        )
        accepted, reason = llm.validate_narrative(
            "The artifacts share 203.0.113.66 and also 198.51.100.23.", request
        )
        assert accepted is False
        assert reason is not None and "198.51.100.23" in reason

    def test_prose_restating_supplied_facts_is_accepted(self) -> None:
        request = llm.NarrativeRequest(
            subject="Correlation",
            facts=["Evidence EV-1 and EV-2 both contain 203.0.113.66."],
        )
        accepted, reason = llm.validate_narrative(
            "Both artifacts reference the address 203.0.113.66.", request
        )
        assert accepted is True
        assert reason is None

    def test_speculative_language_is_rejected(self) -> None:
        """A summary that assigns blame has converted an observation into an allegation."""
        request = llm.NarrativeRequest(
            subject="Correlation", facts=["Two artifacts share an address."]
        )
        accepted, reason = llm.validate_narrative(
            "This proves that the account holder is responsible for the intrusion.", request
        )
        assert accepted is False
        assert reason is not None

    def test_the_default_provider_narrates_nothing(self) -> None:
        provider = llm.get_provider()
        assert isinstance(provider, llm.DisabledLLMProvider)
        assert provider.narrate(llm.NarrativeRequest(subject="x", facts=["y"])) is None
        assert provider.health()["available"] is False

    def test_a_provider_that_raises_is_contained(self) -> None:
        """Narration is cosmetic and must never be able to break analysis."""

        class Exploding(llm.LLMProvider):
            name = "exploding"
            model = "test"

            def narrate(self, request: llm.NarrativeRequest) -> llm.NarrativeResult | None:
                raise RuntimeError("model unreachable")

        request = llm.NarrativeRequest(subject="x", facts=["y"])
        assert llm.narrate_safely(Exploding(), request) is None

    def test_a_narrative_result_carries_only_prose(self) -> None:
        """Structural guarantee: there is nowhere in the return type to put a forensic fact."""
        fields = set(llm.NarrativeResult.__slots__)
        assert fields == {"text", "model", "provider", "tokens_used"}


class TestEntityNormalization:
    def test_the_same_value_from_two_artifacts_is_one_entity(
        self, db: Session, ransomware_case: tuple[Case, list[Evidence]]
    ) -> None:
        """Correlation depends on identity: two rows for one wallet would find no link at all."""
        _case, items = ransomware_case

        rows = db.scalars(
            select(Entity).where(
                Entity.canonical_value == SHARED_WALLET,
                Entity.type == EntityType.crypto_wallet,
            )
        ).all()
        assert len(rows) == 1

        occurrences = db.scalars(
            select(EntityOccurrence).where(EntityOccurrence.entity_id == rows[0].id)
        ).all()
        evidence_ids = {occurrence.evidence_id for occurrence in occurrences}
        assert len(evidence_ids) >= 2
        assert evidence_ids <= {item.id for item in items}

    def test_document_frequency_tracks_the_corpus(
        self, db: Session, ransomware_case: tuple[Case, list[Evidence]]
    ) -> None:
        _case, _items = ransomware_case
        entity = db.scalars(
            select(Entity).where(Entity.canonical_value == SHARED_WALLET)
        ).one()
        assert entity.document_frequency >= 2
        assert entity.case_count >= 1
