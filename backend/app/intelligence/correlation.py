"""Evidence correlation by shared indicators, weighted by rarity.

Two artifacts are related if they share indicators, but not all shared indicators are equally
informative. A private address like ``192.168.1.1`` appears in half the logs on the network and
tells you almost nothing; a specific Bitcoin wallet appearing in two separate cases tells you a
great deal. Weighting every shared value equally would drown the second signal in the first, so
each shared entity contributes according to how rare it is across the whole corpus.

The weighting is inverse document frequency, the same idea used in text retrieval:

.. math:: idf = \\log\\left(\\frac{N + 1}{df + 1}\\right)

where ``N`` is the number of evidence items in the corpus and ``df`` the number containing that
entity. A value in every artifact contributes nothing; a value in two contributes a lot. The
smoothing (``+1`` on both terms) keeps a brand-new entity from producing an infinite weight when
the corpus is small.

Small corpora need one further adjustment. With three artifacts, every shared value has
``df == N`` and therefore weight zero, so a fresh deployment would produce no correlations at all -
not because nothing is related, but because rarity is undefined when there is nothing to be rare
against. ``N`` is therefore floored at :data:`MIN_WEIGHTING_CORPUS`: until the platform holds that
many items, weighting proceeds against a nominal corpus of that size, and once it holds more the
real number takes over. Both figures are recorded on every term, so an explanation always shows
which was used.

Every edge stores its full arithmetic in ``basis``: which entities matched, each one's document
frequency, each one's weight, and the resulting total. That is what allows the interface to explain
a link rather than assert one, and what lets an opposing expert check the reasoning. An edge whose
score cannot be explained should not exist.
"""

from __future__ import annotations

import math
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.core.clock import utcnow
from app.core.logging import get_logger
from app.models.analysis import CorrelationEdge, Entity, EntityOccurrence
from app.models.enums import CorrelationKind, EntityType
from app.models.evidence import Evidence

logger = get_logger(__name__)

ENGINE_VERSION = "1"

# Below this, a link is too weak to be worth an investigator's attention. Set by what the maths
# produces: a single moderately common shared value lands around 0.2, and edges at that level are
# noise in any corpus of realistic size.
MIN_EDGE_SCORE = 0.35

# Entity types whose values identify something specific enough to be worth correlating on. Types
# excluded here are not unimportant - they are simply too generic to establish a link by themselves.
_CORRELATABLE = frozenset(
    {
        EntityType.ip_address,
        EntityType.domain,
        EntityType.url,
        EntityType.email_address,
        EntityType.phone_number,
        EntityType.username,
        EntityType.account,
        EntityType.file_hash,
        EntityType.crypto_wallet,
        EntityType.payment_card,
        EntityType.mac_address,
        EntityType.device_identifier,
        EntityType.registry_key,
        EntityType.location,
        EntityType.person,
        EntityType.organization,
        EntityType.cve,
    }
)

# Per-type multipliers applied on top of rarity. Rarity alone cannot distinguish between a value
# that is rare *because it is meaningless* (a one-off filename) and one that is rare because it
# genuinely identifies a party. These reflect how strongly a shared value of each type implies a
# real connection, and they are recorded per-edge so the weighting is auditable rather than hidden.
_TYPE_WEIGHTS: dict[EntityType, float] = {
    EntityType.file_hash: 1.6,
    EntityType.crypto_wallet: 1.5,
    EntityType.payment_card: 1.5,
    EntityType.device_identifier: 1.4,
    EntityType.email_address: 1.3,
    EntityType.account: 1.2,
    EntityType.username: 1.1,
    EntityType.mac_address: 1.2,
    EntityType.url: 1.1,
    EntityType.ip_address: 1.0,
    EntityType.domain: 0.9,
    EntityType.phone_number: 1.2,
    EntityType.location: 0.8,
    EntityType.registry_key: 0.7,
    EntityType.person: 0.7,
    EntityType.organization: 0.6,
    EntityType.cve: 0.6,
}

# An entity present in more than this share of the corpus is treated as background: shared
# infrastructure, a corporate mail domain, the organisation's own address range. Excluding these
# is what stops every artifact correlating with every other one through the company's own MX host.
# Measured against the *real* corpus, because ubiquity is a fact about what the platform holds.
UBIQUITY_RATIO = 0.6
MIN_CORPUS_FOR_UBIQUITY = 8

# The nominal corpus size used for weighting until the real one exceeds it. Chosen as roughly the
# smallest corpus in which document frequency starts to mean anything: below this, "appears in two
# of three items" says more about how little has been ingested than about the value itself.
MIN_WEIGHTING_CORPUS = 25


@dataclass(slots=True)
class SharedTerm:
    """One entity shared between two artifacts, with the arithmetic that scored it."""

    entity_id: uuid.UUID
    entity_type: EntityType
    value: str
    document_frequency: int
    #: How many items the platform actually holds. Used in prose, because "in 2 of 3 items" is what
    #: an investigator can verify.
    corpus_size: int
    #: The ``N`` actually fed to the IDF calculation - the real corpus, or the nominal floor while
    #: the platform is still small. Published so a weight can always be recomputed.
    weighting_corpus_size: int
    idf: float
    type_weight: float
    contribution: float

    def as_basis(self) -> dict[str, Any]:
        return {
            "entity_id": str(self.entity_id),
            "type": self.entity_type.value,
            "value": self.value,
            "document_frequency": self.document_frequency,
            "corpus_size": self.corpus_size,
            "weighting_corpus_size": self.weighting_corpus_size,
            "idf": round(self.idf, 4),
            "type_weight": self.type_weight,
            "contribution": round(self.contribution, 4),
        }


@dataclass(slots=True)
class ScoredPair:
    """A candidate correlation between two evidence items."""

    source_evidence_id: uuid.UUID
    target_evidence_id: uuid.UUID
    source_case_id: uuid.UUID
    target_case_id: uuid.UUID
    terms: list[SharedTerm] = field(default_factory=list)

    @property
    def is_cross_case(self) -> bool:
        return self.source_case_id != self.target_case_id

    @property
    def raw_score(self) -> float:
        return sum(term.contribution for term in self.terms)

    @property
    def score(self) -> float:
        """Squash the additive total into 0-1 so scores are comparable between corpora.

        A saturating curve rather than a hard cap: ten shared indicators should rank above three,
        but the difference between ten and twenty matters far less than the difference between one
        and three, and a linear sum would let one enormous case dominate every ranking.
        """
        return round(1.0 - math.exp(-self.raw_score / 2.0), 4)


def idf(document_frequency: int, corpus_size: int) -> float:
    """Inverse document frequency with add-one smoothing on both terms."""
    return math.log((corpus_size + 1) / (document_frequency + 1))


def corpus_size(db: Session) -> int:
    """How many evidence items the platform holds."""
    return int(db.scalar(select(func.count()).select_from(Evidence)) or 0)


def weighting_corpus_size(actual: int) -> int:
    """The ``N`` to weight against, floored while the corpus is too small to be informative."""
    return max(actual, MIN_WEIGHTING_CORPUS)


def _entity_document_frequencies(
    db: Session, entity_ids: set[uuid.UUID]
) -> dict[uuid.UUID, int]:
    """Count distinct evidence items containing each entity.

    Computed from ``entity_occurrences`` rather than read from the denormalised counter on
    ``entities``, because the score has to reflect the corpus as it is right now: a stale counter
    would silently distort every weight derived from it.
    """
    if not entity_ids:
        return {}
    rows = db.execute(
        select(
            EntityOccurrence.entity_id,
            func.count(func.distinct(EntityOccurrence.evidence_id)),
        )
        .where(EntityOccurrence.entity_id.in_(entity_ids))
        .group_by(EntityOccurrence.entity_id)
    ).all()
    return {entity_id: int(count) for entity_id, count in rows}


def _shared_entity_rows(
    db: Session, evidence_id: uuid.UUID
) -> list[tuple[uuid.UUID, EntityType, str, uuid.UUID, uuid.UUID]]:
    """Every other artifact that shares a correlatable entity with this one.

    One query rather than a per-entity loop: correlating an artifact with fifty indicators would
    otherwise issue fifty round trips, and this runs on every ingestion.
    """
    mine = (
        select(EntityOccurrence.entity_id)
        .join(Entity, Entity.id == EntityOccurrence.entity_id)
        .where(
            EntityOccurrence.evidence_id == evidence_id,
            Entity.type.in_(_CORRELATABLE),
        )
        .distinct()
        .subquery()
    )

    rows = db.execute(
        select(
            Entity.id,
            Entity.type,
            Entity.display_value,
            EntityOccurrence.evidence_id,
            EntityOccurrence.case_id,
        )
        .join(Entity, Entity.id == EntityOccurrence.entity_id)
        .where(
            EntityOccurrence.entity_id.in_(select(mine.c.entity_id)),
            EntityOccurrence.evidence_id != evidence_id,
        )
        .distinct()
    ).all()
    return [
        (entity_id, entity_type, value, other_evidence, other_case)
        for entity_id, entity_type, value, other_evidence, other_case in rows
    ]


def score_pairs_for_evidence(db: Session, evidence: Evidence) -> list[ScoredPair]:
    """Score this artifact against every other one that shares an indicator with it."""
    total = corpus_size(db)
    weighting_total = weighting_corpus_size(total)
    rows = _shared_entity_rows(db, evidence.id)
    if not rows:
        return []

    frequencies = _entity_document_frequencies(
        db, {entity_id for entity_id, _t, _v, _e, _c in rows}
    )

    ubiquity_cutoff = (
        total * UBIQUITY_RATIO if total >= MIN_CORPUS_FOR_UBIQUITY else float("inf")
    )

    pairs: dict[uuid.UUID, ScoredPair] = {}
    for entity_id, entity_type, value, other_evidence_id, other_case_id in rows:
        frequency = frequencies.get(entity_id, 1)
        if frequency > ubiquity_cutoff:
            # Background infrastructure. Skipped rather than down-weighted, because a value in
            # most of the corpus carries no information about any particular pair.
            continue

        weight = _TYPE_WEIGHTS.get(entity_type, 0.5)
        term_idf = idf(frequency, weighting_total)
        contribution = term_idf * weight
        if contribution <= 0:
            continue

        pair = pairs.get(other_evidence_id)
        if pair is None:
            # Canonical ordering by UUID keeps an undirected relationship from being stored twice
            # under two different orientations.
            first, second = sorted([evidence.id, other_evidence_id], key=str)
            first_case = evidence.case_id if first == evidence.id else other_case_id
            second_case = other_case_id if second == other_evidence_id else evidence.case_id
            pair = ScoredPair(
                source_evidence_id=first,
                target_evidence_id=second,
                source_case_id=first_case,
                target_case_id=second_case,
            )
            pairs[other_evidence_id] = pair

        pair.terms.append(
            SharedTerm(
                entity_id=entity_id,
                entity_type=entity_type,
                value=value,
                document_frequency=frequency,
                corpus_size=total,
                weighting_corpus_size=weighting_total,
                idf=term_idf,
                type_weight=weight,
                contribution=contribution,
            )
        )

    return [pair for pair in pairs.values() if pair.score >= MIN_EDGE_SCORE]


def explain(pair: ScoredPair) -> str:
    """Prose explaining the edge, in the terms an investigator would use.

    Written as an explanation rather than a verdict. A shared indicator is a fact; that the two
    artifacts are *connected* is an inference, and the wording keeps that distinction visible.
    """
    ranked = sorted(pair.terms, key=lambda term: term.contribution, reverse=True)
    if not ranked:  # pragma: no cover - a pair without terms is never scored
        return ""

    top = ranked[:3]
    described = ", ".join(
        f"{term.entity_type.value.replace('_', ' ')} {term.value!r} "
        f"(in {term.document_frequency} of {term.corpus_size} items)"
        for term in top
    )
    remainder = len(ranked) - len(top)
    scope = (
        "These items belong to different cases, so this is a cross-case link."
        if pair.is_cross_case
        else "Both items belong to the same case."
    )

    weighting = (
        f"across all {ranked[0].corpus_size} registered items"
        if ranked[0].weighting_corpus_size == ranked[0].corpus_size
        else (
            f"against a nominal corpus of {ranked[0].weighting_corpus_size} items, because the "
            f"{ranked[0].corpus_size} currently held are too few for rarity to be meaningful"
        )
    )
    return (
        f"These two items share {len(ranked)} indicator(s): {described}"
        + (f", and {remainder} more" if remainder > 0 else "")
        + f". Scoring weights each shared value by how rare it is {weighting}, so values that "
        f"appear everywhere contribute little and distinctive ones contribute most. {scope}"
    )


def persist_edges(db: Session, pairs: list[ScoredPair]) -> int:
    """Upsert correlation edges, replacing any previous score for the same pair.

    Upsert rather than delete-then-insert: an edge's identity is the pair of artifacts and the kind
    of link, so recomputation should update the score in place. Deleting first would briefly leave
    a case with no correlations, and any concurrent read would see an empty graph.
    """
    if not pairs:
        return 0

    now = utcnow()
    written = 0

    for pair in pairs:
        kind = (
            CorrelationKind.cross_case
            if pair.is_cross_case
            else CorrelationKind.shared_indicator
        )
        ranked = sorted(pair.terms, key=lambda term: term.contribution, reverse=True)
        basis = {
            "method": "IDF-weighted shared indicators",
            "formula": "score = 1 - exp(-sum(idf(df, N) * type_weight) / 2)",
            "raw_score": round(pair.raw_score, 4),
            "corpus_size": ranked[0].corpus_size if ranked else 0,
            "weighting_corpus_size": ranked[0].weighting_corpus_size if ranked else 0,
            "weighting_floor": MIN_WEIGHTING_CORPUS,
            "shared_terms": [term.as_basis() for term in ranked[:40]],
            "shared_term_count": len(ranked),
            "engine_version": ENGINE_VERSION,
        }

        statement = (
            pg_insert(CorrelationEdge)
            .values(
                kind=kind,
                source_evidence_id=pair.source_evidence_id,
                target_evidence_id=pair.target_evidence_id,
                source_case_id=pair.source_case_id,
                target_case_id=pair.target_case_id,
                is_cross_case=pair.is_cross_case,
                score=pair.score,
                shared_entity_count=len(pair.terms),
                basis=basis,
                explanation=explain(pair),
                computed_at=now,
                computer_version=ENGINE_VERSION,
            )
            .on_conflict_do_update(
                constraint="uq_correlation_edges_source_target_kind",
                set_={
                    "score": pair.score,
                    "shared_entity_count": len(pair.terms),
                    "basis": basis,
                    "explanation": explain(pair),
                    "computed_at": now,
                    "computer_version": ENGINE_VERSION,
                    "is_cross_case": pair.is_cross_case,
                },
            )
        )
        db.execute(statement)
        written += 1

    db.flush()
    return written


def correlate_evidence(db: Session, evidence: Evidence) -> dict[str, Any]:
    """Compute and store correlations for one artifact."""
    pairs = score_pairs_for_evidence(db, evidence)
    written = persist_edges(db, pairs)
    cross_case = sum(1 for pair in pairs if pair.is_cross_case)

    _prune_stale_edges(db, evidence.id, pairs)

    logger.info(
        "correlation_computed",
        evidence=evidence.reference,
        edges=written,
        cross_case=cross_case,
    )
    return {
        "evidence": evidence.reference,
        "edges": written,
        "cross_case_edges": cross_case,
        "top_score": max((pair.score for pair in pairs), default=0.0),
    }


def _prune_stale_edges(
    db: Session, evidence_id: uuid.UUID, keep: list[ScoredPair]
) -> int:
    """Delete edges that no longer meet the threshold.

    Necessary because re-analysis can *remove* entities - an improved analyzer that stops
    extracting a false positive, for instance - and an edge justified only by that entity would
    otherwise persist forever with a stale explanation that no longer matches the evidence.
    """
    keep_targets = {
        (pair.source_evidence_id, pair.target_evidence_id) for pair in keep
    }
    existing = db.scalars(
        select(CorrelationEdge).where(
            (CorrelationEdge.source_evidence_id == evidence_id)
            | (CorrelationEdge.target_evidence_id == evidence_id)
        )
    ).all()

    removed = 0
    for edge in existing:
        if (edge.source_evidence_id, edge.target_evidence_id) not in keep_targets:
            db.delete(edge)
            removed += 1
    if removed:
        db.flush()
    return removed


def rebuild_all(db: Session, *, limit: int | None = None) -> dict[str, Any]:
    """Recompute correlations across the corpus.

    Needed because rarity is a global property: adding evidence changes ``N`` and the document
    frequency of everything it contains, so scores computed earlier drift out of date. Running
    periodically keeps every edge consistent with one view of the corpus.
    """
    query = select(Evidence).order_by(Evidence.created_at)
    if limit is not None:
        query = query.limit(limit)

    items = db.scalars(query).all()
    edges = 0
    for evidence in items:
        edges += persist_edges(db, score_pairs_for_evidence(db, evidence))

    logger.info("correlation_rebuilt", items=len(items), edges=edges)
    return {"items": len(items), "edges": edges}


def cross_case_links(db: Session, case_id: uuid.UUID) -> list[dict[str, Any]]:
    """Every other case linked to this one, strongest link first.

    Cross-case links are the highest-value output of the correlation engine: they connect
    investigations that nobody had connected manually, which is exactly what an evidence platform
    should surface and a spreadsheet never will.
    """
    edges = db.scalars(
        select(CorrelationEdge)
        .where(
            CorrelationEdge.is_cross_case.is_(True),
            (CorrelationEdge.source_case_id == case_id)
            | (CorrelationEdge.target_case_id == case_id),
        )
        .order_by(CorrelationEdge.score.desc())
    ).all()

    grouped: dict[uuid.UUID, list[CorrelationEdge]] = defaultdict(list)
    for edge in edges:
        other = (
            edge.target_case_id if edge.source_case_id == case_id else edge.source_case_id
        )
        grouped[other].append(edge)

    summaries: list[dict[str, Any]] = []
    for other_case_id, case_edges in grouped.items():
        shared_values = {
            term["value"]
            for edge in case_edges
            for term in edge.basis.get("shared_terms", [])
        }
        summaries.append(
            {
                "case_id": str(other_case_id),
                "edge_count": len(case_edges),
                "max_score": max(edge.score for edge in case_edges),
                "shared_indicator_count": len(shared_values),
                "shared_indicators": sorted(shared_values)[:20],
            }
        )

    return sorted(summaries, key=lambda item: item["max_score"], reverse=True)
