"""End-to-end analysis pipeline tests.

These drive the real path: register evidence through the ingestion service, run the pipeline over
the encrypted stored object, and assert on rows that actually landed in PostgreSQL. Nothing is
stubbed, so what these tests cover is the join between storage, decryption, analysis and
persistence - which is exactly where the unit-level analyzer tests cannot reach.
"""

from __future__ import annotations

import io
import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.analysis.pipeline import analyze_evidence
from app.models.analysis import (
    AnalysisFinding,
    AnalysisRun,
    Entity,
    EntityOccurrence,
    Observation,
    observation_entities,
)
from app.models.case import Case
from app.models.custody import CustodyEvent
from app.models.enums import (
    AnalysisStatus,
    CustodyAction,
    EntityType,
    EvidenceStatus,
    EvidenceType,
    IncidentType,
    ObservationKind,
    Severity,
)
from app.models.evidence import Evidence
from app.models.user import User
from app.services import case_service, evidence_service
from tests.conftest import context_for

PHISHING_EMAIL = b"""Received: from relay.attacker-infra.example
\t(attacker-vps.example [203.0.113.66])
\tby mx.victim.example (Postfix) with ESMTP id 9F8E7D6C
\tfor <finance@victim.example>; Mon, 15 Jan 2024 10:30:00 +0000
Authentication-Results: mx.victim.example; spf=fail smtp.mailfrom=vendor-billing.example;
\tdkim=none; dmarc=fail
From: "Accounts" <billing@trusted-vendor.example>
Reply-To: <payments@vendor-billing.example>
To: finance@victim.example
Subject: Updated remittance details
Date: Mon, 15 Jan 2024 10:29:00 +0000
Message-ID: <case1-msg@vendor-billing.example>
Content-Type: text/plain

Please wire payment to the new account. Confirm to 203.0.113.66.
Wallet: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
"""

AUTH_LOG = "\n".join(
    [
        *[
            f"Jan 15 09:{minute:02d}:00 web01 sshd[{2000 + minute}]: Failed password for "
            f"invalid user admin from 203.0.113.66 port 5{minute:02d} ssh2"
            for minute in range(10, 25)
        ],
        "Jan 15 09:26:00 web01 sshd[2100]: Accepted password for deploy from 203.0.113.66 "
        "port 52600 ssh2",
    ]
).encode()


@pytest.fixture
def case(db: Session, investigator: User, analyst: User) -> Case:
    """An active case with the analyst assigned to it.

    The assignment is deliberate rather than incidental: case access is scoped in SQL, so an
    analyst who has not been assigned genuinely cannot see the case, and these tests would fail
    for an authorisation reason that has nothing to do with analysis.
    """
    ctx = context_for(investigator)
    case = case_service.create_case(
        db,
        ctx,
        title="Vendor invoice fraud",
        summary="Finance received altered remittance details from a spoofed vendor address.",
        incident_type=IncidentType.financial_fraud,
        severity=Severity.high,
    )
    case_service.assign_user(db, ctx, case.id, user_id=analyst.id)
    db.flush()
    return case


def ingest(
    db: Session,
    user: User,
    case: Case,
    content: bytes,
    filename: str,
    *,
    evidence_type: EvidenceType | None = None,
    acquired_at: datetime | None = None,
) -> Evidence:
    return evidence_service.ingest_evidence(
        db,
        context_for(user),
        case_id=case.id,
        stream=io.BytesIO(content),
        original_filename=filename,
        evidence_type=evidence_type,
        acquired_at=acquired_at or datetime(2024, 2, 1, tzinfo=UTC),
        acquired_by_name="DC Rowan Idris",
    )


class TestPipelinePersistence:
    def test_analysis_persists_entities_observations_and_findings(
        self, db: Session, analyst: User, case: Case, storage_root: object
    ) -> None:
        evidence = ingest(db, analyst, case, PHISHING_EMAIL, "spoofed.eml")
        ctx = context_for(analyst)

        summary = analyze_evidence(db, ctx, evidence)
        db.flush()

        assert "email_headers" in summary["analyzers_run"]
        assert "file_metadata" in summary["analyzers_run"]
        assert summary["analyzers_failed"] == []
        assert summary["entities"] > 0

        entities = db.scalars(
            select(Entity)
            .join(EntityOccurrence, EntityOccurrence.entity_id == Entity.id)
            .where(EntityOccurrence.evidence_id == evidence.id)
        ).all()
        by_type: dict[EntityType, set[str]] = {}
        for entity in entities:
            by_type.setdefault(entity.type, set()).add(entity.display_value)

        assert "billing@trusted-vendor.example" in by_type[EntityType.email_address]
        assert "203.0.113.66" in by_type[EntityType.ip_address]
        assert "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa" in by_type[EntityType.crypto_wallet]

        findings = db.scalars(
            select(AnalysisFinding).where(AnalysisFinding.evidence_id == evidence.id)
        ).all()
        codes = {finding.code for finding in findings}
        assert "email.authentication_failed" in codes
        assert "email.reply_to_mismatch" in codes

        observations = db.scalars(
            select(Observation).where(Observation.evidence_id == evidence.id)
        ).all()
        assert {ObservationKind.email_sent, ObservationKind.email_received} <= {
            observation.kind for observation in observations
        }

    def test_every_occurrence_records_where_it_was_seen(
        self, db: Session, analyst: User, case: Case, storage_root: object
    ) -> None:
        evidence = ingest(db, analyst, case, PHISHING_EMAIL, "spoofed.eml")
        analyze_evidence(db, context_for(analyst), evidence)
        db.flush()

        occurrences = db.scalars(
            select(EntityOccurrence).where(EntityOccurrence.evidence_id == evidence.id)
        ).all()
        assert occurrences
        for occurrence in occurrences:
            # Provenance is the whole basis of the platform's credibility: an extracted value that
            # cannot be pointed back at a place in the artifact is not evidence of anything.
            assert occurrence.locator, f"occurrence {occurrence.id} has no locator"
            assert occurrence.analyzer
            assert occurrence.analyzer_version

    def test_observations_link_to_the_entities_they_involve(
        self, db: Session, analyst: User, case: Case, storage_root: object
    ) -> None:
        evidence = ingest(db, analyst, case, PHISHING_EMAIL, "spoofed.eml")
        analyze_evidence(db, context_for(analyst), evidence)
        db.flush()

        sent = db.scalars(
            select(Observation).where(
                Observation.evidence_id == evidence.id,
                Observation.kind == ObservationKind.email_sent,
            )
        ).first()
        assert sent is not None

        linked = db.execute(
            select(Entity.display_value)
            .join(observation_entities, observation_entities.c.entity_id == Entity.id)
            .where(observation_entities.c.observation_id == sent.id)
        ).scalars().all()
        # Without this join the timeline and the relationship graph cannot be connected, so a
        # timeline event would have no path back to the actors involved in it.
        assert "billing@trusted-vendor.example" in linked

    def test_analysis_records_a_run_per_analyzer_with_timing(
        self, db: Session, analyst: User, case: Case, storage_root: object
    ) -> None:
        evidence = ingest(db, analyst, case, PHISHING_EMAIL, "spoofed.eml")
        analyze_evidence(db, context_for(analyst), evidence)
        db.flush()

        runs = db.scalars(
            select(AnalysisRun).where(AnalysisRun.evidence_id == evidence.id)
        ).all()
        assert len(runs) >= 2
        for run in runs:
            assert run.status is AnalysisStatus.completed
            assert run.analyzer_version
            assert run.duration_ms is not None
            assert run.completed_at is not None

    def test_evidence_is_marked_analysed_and_carries_metadata(
        self, db: Session, analyst: User, case: Case, storage_root: object
    ) -> None:
        evidence = ingest(db, analyst, case, PHISHING_EMAIL, "spoofed.eml")
        analyze_evidence(db, context_for(analyst), evidence)
        db.flush()

        assert evidence.status is EvidenceStatus.analyzed
        assert evidence.analysis_completed_at is not None
        assert "email_headers" in evidence.extracted_metadata
        assert evidence.extracted_metadata["file_metadata"]["hashes"]["sha256"]

    def test_analysis_is_recorded_in_the_chain_of_custody(
        self, db: Session, analyst: User, case: Case, storage_root: object
    ) -> None:
        evidence = ingest(db, analyst, case, PHISHING_EMAIL, "spoofed.eml")
        analyze_evidence(db, context_for(analyst), evidence)
        db.flush()

        actions = db.scalars(
            select(CustodyEvent.action)
            .where(CustodyEvent.evidence_id == evidence.id)
            .order_by(CustodyEvent.sequence)
        ).all()
        # Automated examination is still an examination, and a defensible custody record has to
        # show that the system read the evidence, not only that people did.
        assert CustodyAction.analyzed in actions

    def test_reanalysis_replaces_results_instead_of_duplicating_them(
        self, db: Session, analyst: User, case: Case, storage_root: object
    ) -> None:
        evidence = ingest(db, analyst, case, PHISHING_EMAIL, "spoofed.eml")
        ctx = context_for(analyst)

        first = analyze_evidence(db, ctx, evidence)
        db.flush()

        def counts() -> tuple[int, int, int]:
            return (
                db.scalar(
                    select(func.count())
                    .select_from(EntityOccurrence)
                    .where(EntityOccurrence.evidence_id == evidence.id)
                )
                or 0,
                db.scalar(
                    select(func.count())
                    .select_from(Observation)
                    .where(Observation.evidence_id == evidence.id)
                )
                or 0,
                db.scalar(
                    select(func.count())
                    .select_from(AnalysisFinding)
                    .where(AnalysisFinding.evidence_id == evidence.id)
                )
                or 0,
            )

        before = counts()
        second = analyze_evidence(db, ctx, evidence)
        db.flush()

        assert second["entities"] == first["entities"]
        assert counts() == before

    def test_log_analysis_produces_timeline_events_from_content(
        self, db: Session, analyst: User, case: Case, storage_root: object
    ) -> None:
        evidence = ingest(
            db,
            analyst,
            case,
            AUTH_LOG,
            "auth.log",
            evidence_type=EvidenceType.system_log,
            acquired_at=datetime(2024, 2, 10, tzinfo=UTC),
        )
        analyze_evidence(db, context_for(analyst), evidence)
        db.flush()

        observations = db.scalars(
            select(Observation)
            .where(Observation.evidence_id == evidence.id)
            .order_by(Observation.occurred_at)
        ).all()
        assert observations
        # Events must be dated from the log's own content, not from when it was uploaded.
        assert all(observation.occurred_at.year == 2024 for observation in observations)
        assert all(observation.timezone_assumed for observation in observations)

        finding = db.scalars(
            select(AnalysisFinding).where(
                AnalysisFinding.evidence_id == evidence.id,
                AnalysisFinding.code == "log.credential_attack",
            )
        ).first()
        assert finding is not None
        assert finding.severity is Severity.critical
        assert finding.attributes["source_ip"] == "203.0.113.66"

    def test_entities_are_shared_across_evidence_and_counted(
        self, db: Session, analyst: User, case: Case, storage_root: object
    ) -> None:
        email = ingest(db, analyst, case, PHISHING_EMAIL, "spoofed.eml")
        log = ingest(
            db, analyst, case, AUTH_LOG, "auth.log", evidence_type=EvidenceType.system_log
        )
        ctx = context_for(analyst)
        analyze_evidence(db, ctx, email)
        analyze_evidence(db, ctx, log)
        db.flush()

        address = db.scalars(
            select(Entity).where(
                Entity.type == EntityType.ip_address,
                Entity.canonical_value == "203.0.113.66",
            )
        ).all()
        # One canonical entity row, referenced from both artifacts. This is what makes the same
        # address in an email and in a log resolve to a single node rather than two.
        assert len(address) == 1

        occurrences = db.scalars(
            select(EntityOccurrence).where(EntityOccurrence.entity_id == address[0].id)
        ).all()
        assert {occurrence.evidence_id for occurrence in occurrences} == {email.id, log.id}
        assert address[0].document_frequency >= 2

    def test_single_analyzer_failure_does_not_lose_other_results(
        self, db: Session, analyst: User, case: Case, storage_root: object, monkeypatch
    ) -> None:
        evidence = ingest(db, analyst, case, PHISHING_EMAIL, "spoofed.eml")
        ctx = context_for(analyst)

        from app.analysis import registry

        email_analyzer = registry.get("email_headers")

        def explode(artifact: object) -> None:
            raise RuntimeError("simulated parser crash")

        monkeypatch.setattr(email_analyzer, "analyze", explode)

        summary = analyze_evidence(db, ctx, evidence)
        db.flush()

        # The point of isolating analyzers: the universal analyzer's results must survive a
        # different analyzer crashing, and the crash must be visible rather than silent.
        assert "email_headers" in summary["analyzers_failed"]
        assert "file_metadata" in summary["analyzers_run"]

        failed = db.scalars(
            select(AnalysisRun).where(
                AnalysisRun.evidence_id == evidence.id,
                AnalysisRun.status == AnalysisStatus.failed,
            )
        ).all()
        assert len(failed) == 1
        assert "simulated parser crash" in failed[0].error

        assert db.scalar(
            select(func.count())
            .select_from(EntityOccurrence)
            .where(EntityOccurrence.evidence_id == evidence.id)
        )

    def test_analysis_of_a_specific_analyzer_only_runs_that_one(
        self, db: Session, analyst: User, case: Case, storage_root: object
    ) -> None:
        evidence = ingest(db, analyst, case, PHISHING_EMAIL, "spoofed.eml")
        summary = analyze_evidence(
            db, context_for(analyst), evidence, only="file_metadata"
        )
        db.flush()

        assert summary["analyzers_run"] == ["file_metadata"]


class TestAnalysisTasks:
    def test_analyze_task_runs_the_pipeline_for_a_queued_item(
        self, db: Session, analyst: User, case: Case, storage_root: object
    ) -> None:
        from app.jobs.registry import get_task, load_tasks

        load_tasks()
        evidence = ingest(db, analyst, case, PHISHING_EMAIL, "spoofed.eml")

        spec = get_task("evidence.analyze")
        result = spec.func(db, context_for(analyst), {"evidence_id": str(evidence.id)})
        db.flush()

        assert result is not None
        assert result["entities"] > 0
        assert evidence.analysis_completed_at is not None

    def test_analyze_task_rejects_a_missing_evidence_id(
        self, db: Session, analyst: User
    ) -> None:
        from app.jobs.registry import get_task, load_tasks

        load_tasks()
        spec = get_task("evidence.analyze")
        with pytest.raises(ValueError, match="requires an evidence_id"):
            spec.func(db, context_for(analyst), {})

    def test_pending_sweep_queues_unanalysed_items_once(
        self, db: Session, analyst: User, case: Case, storage_root: object
    ) -> None:
        from app.jobs.registry import get_task, load_tasks
        from app.models.ops import Job

        load_tasks()
        evidence = ingest(db, analyst, case, PHISHING_EMAIL, "spoofed.eml")
        ctx = context_for(analyst)

        # Ingestion already queued analysis for this item, so the sweep must find nothing to add.
        already = db.scalar(
            select(func.count())
            .select_from(Job)
            .where(Job.task == "evidence.analyze", Job.evidence_id == evidence.id)
        )
        assert already == 1

        spec = get_task("evidence.analyze_pending")
        result = spec.func(db, ctx, {})
        db.flush()

        assert result is not None
        # Deduplication is what stops a periodic sweep from queueing the same work repeatedly.
        assert result["queued"] == 0

    def test_reanalyze_case_fans_out_one_job_per_item(
        self, db: Session, analyst: User, case: Case, storage_root: object
    ) -> None:
        from app.jobs.registry import get_task, load_tasks
        from app.models.ops import Job

        load_tasks()
        first = ingest(db, analyst, case, PHISHING_EMAIL, "spoofed.eml")
        second = ingest(
            db, analyst, case, AUTH_LOG, "auth.log", evidence_type=EvidenceType.system_log
        )
        ctx = context_for(analyst)

        # Clear the jobs ingestion queued so the fan-out is measured on its own.
        db.query(Job).filter(Job.task == "evidence.analyze").delete()
        db.flush()

        spec = get_task("evidence.reanalyze_case")
        result = spec.func(db, ctx, {"case_id": str(case.id)})
        db.flush()

        assert result is not None
        assert result["items"] == 2
        assert result["queued"] == 2

        queued = db.scalars(
            select(Job.evidence_id).where(Job.task == "evidence.analyze")
        ).all()
        assert set(queued) == {first.id, second.id}

    def test_a_new_version_gets_its_own_analysis_job(
        self, db: Session, analyst: User, case: Case, storage_root: object
    ) -> None:
        from app.models.ops import Job

        evidence = ingest(db, analyst, case, PHISHING_EMAIL, "spoofed.eml")
        ctx = context_for(analyst)

        evidence_service.add_version(
            db,
            ctx,
            evidence.id,
            stream=io.BytesIO(PHISHING_EMAIL + b"\nX-Reprocessed: true\n"),
            original_filename="spoofed-v2.eml",
            reason="Re-exported from the mail server with full headers",
        )
        db.flush()

        keys = db.scalars(
            select(Job.dedupe_key).where(
                Job.task == "evidence.analyze", Job.evidence_id == evidence.id
            )
        ).all()
        # Deduplication must not suppress a new version's analysis: replacing the content is
        # precisely the case where the item has to be analysed again.
        assert len(keys) == 2
        assert len(set(keys)) == 2

    def test_unknown_evidence_id_raises_not_found(self, db: Session, analyst: User) -> None:
        from app.core.errors import NotFound
        from app.jobs.registry import get_task, load_tasks

        load_tasks()
        spec = get_task("evidence.analyze")
        with pytest.raises(NotFound):
            spec.func(db, context_for(analyst), {"evidence_id": str(uuid.uuid4())})
