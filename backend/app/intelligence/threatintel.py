"""Threat intelligence lookup behind a provider boundary.

The MVP ships a curated offline feed, and that is a deliberate choice rather than a shortcut.
Sending indicators extracted from evidence to a third-party API is an operational security decision
with legal weight: a lookup of a victim's own address range tells the provider what is being
investigated, and in some jurisdictions that disclosure needs authorisation. A forensic platform
should therefore be useful with no outbound connectivity at all, and gain live feeds only when an
operator explicitly configures one.

:class:`ThreatIntelProvider` is the seam. Matching, persistence and scoring depend only on this
interface, so a MISP or AbuseIPDB adapter is a new class plus configuration - no changes to the
matcher, the schema or the risk engine.

Every match is attributed to its source and stored as its own row. Two feeds disagreeing about the
same value is a fact an investigator needs to see, not a conflict to resolve silently.
"""

from __future__ import annotations

import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.core.clock import utcnow
from app.core.logging import get_logger
from app.models.analysis import Entity, EntityOccurrence
from app.models.enums import (
    EntityType,
    IndicatorSeverity,
    IndicatorType,
)
from app.models.intel import IndicatorMatch, ThreatIndicator

logger = get_logger(__name__)

# Extracted entity types that can be looked up, mapped to the indicator vocabulary. Types absent
# from this mapping are simply not intelligence-checkable: no feed publishes lists of usernames.
_ENTITY_TO_INDICATOR: dict[EntityType, IndicatorType] = {
    EntityType.ip_address: IndicatorType.ip_address,
    EntityType.domain: IndicatorType.domain,
    EntityType.url: IndicatorType.url,
    EntityType.file_hash: IndicatorType.file_hash,
    EntityType.email_address: IndicatorType.email_address,
    EntityType.crypto_wallet: IndicatorType.crypto_wallet,
}


@dataclass(slots=True)
class IndicatorRecord:
    """A provider's statement about one value.

    Providers return these; they never touch the database. That keeps an adapter for a remote
    service from being able to write anything but intelligence, which is the point of the boundary.
    """

    type: IndicatorType
    value: str
    severity: IndicatorSeverity
    confidence: float
    description: str
    source: str
    source_reference: str | None = None
    tags: list[str] = field(default_factory=list)
    threat_actor: str | None = None
    malware_family: str | None = None
    first_seen_at: datetime | None = None
    last_seen_at: datetime | None = None


class ThreatIntelProvider(ABC):
    """A source of indicator reputation.

    Implementations must be side-effect free with respect to case data. They receive values and
    return statements about them; they cannot create findings, alter entities or write custody
    records. An adapter for an external service therefore cannot corrupt the evidence record even
    if the service returns something malformed or hostile.
    """

    name: str
    #: Whether this provider transmits looked-up values off the host. Surfaced in the admin
    #: interface because an operator must be able to see, at a glance, whether enabling a provider
    #: discloses what they are investigating.
    transmits_externally: bool = False

    @abstractmethod
    def lookup(
        self, values: dict[IndicatorType, set[str]]
    ) -> list[IndicatorRecord]:  # pragma: no cover - interface
        """Return what this provider knows about the given values.

        Batched by design: a per-value interface invites N+1 network calls, and every remote feed
        worth using supports bulk queries.
        """

    def health(self) -> dict[str, Any]:
        """Provider status for the admin surface."""
        return {"name": self.name, "available": True}


class LocalFeedProvider(ThreatIntelProvider):
    """Indicators from the platform's own ``threat_indicators`` table.

    Populated by the seeder and by manual curation, so the platform is fully functional offline.
    Because the local table is also the cache that remote adapters write into, this provider is
    what makes intelligence available when a remote feed is unreachable.
    """

    name = "local_feed"
    transmits_externally = False

    def __init__(self, db: Session) -> None:
        self._db = db

    def lookup(self, values: dict[IndicatorType, set[str]]) -> list[IndicatorRecord]:
        if not values:
            return []

        conditions = [
            (ThreatIndicator.type == indicator_type)
            & (ThreatIndicator.canonical_value.in_(sorted(candidates)))
            for indicator_type, candidates in values.items()
            if candidates
        ]
        if not conditions:
            return []

        clause = conditions[0]
        for condition in conditions[1:]:
            clause = clause | condition

        now = utcnow()
        indicators = self._db.scalars(
            select(ThreatIndicator).where(
                clause,
                ThreatIndicator.is_active.is_(True),
                # An expired indicator is deliberately not a match. Reputation decays: an address
                # that hosted a phishing kit two years ago is very likely a different tenant now,
                # and matching on it would generate confident nonsense.
                (ThreatIndicator.expires_at.is_(None)) | (ThreatIndicator.expires_at > now),
            )
        ).all()

        return [
            IndicatorRecord(
                type=indicator.type,
                value=indicator.canonical_value,
                severity=indicator.severity,
                confidence=indicator.confidence,
                description=indicator.description,
                source=indicator.source,
                source_reference=indicator.source_reference,
                tags=[str(tag) for tag in (indicator.tags or [])],
                threat_actor=indicator.threat_actor,
                malware_family=indicator.malware_family,
                first_seen_at=indicator.first_seen_at,
                last_seen_at=indicator.last_seen_at,
            )
            for indicator in indicators
        ]

    def health(self) -> dict[str, Any]:
        total = int(
            self._db.scalar(
                select(func.count())
                .select_from(ThreatIndicator)
                .where(ThreatIndicator.is_active.is_(True))
            )
            or 0
        )
        return {
            "name": self.name,
            "available": True,
            "active_indicators": total,
            "transmits_externally": False,
        }


_PROVIDER_FACTORIES: dict[str, Any] = {LocalFeedProvider.name: LocalFeedProvider}


def register_provider(name: str, factory: Any) -> None:
    """Register a provider implementation under a configuration key."""
    _PROVIDER_FACTORIES[name] = factory


def build_providers(db: Session, names: list[str] | None = None) -> list[ThreatIntelProvider]:
    """Instantiate the configured providers.

    Defaults to the local feed alone. A deployment that wants external lookups has to say so,
    because the default must never be one that silently discloses indicators.
    """
    selected = names or [LocalFeedProvider.name]
    providers: list[ThreatIntelProvider] = []
    for name in selected:
        factory = _PROVIDER_FACTORIES.get(name)
        if factory is None:
            logger.warning("threat_intel_provider_unknown", provider=name)
            continue
        providers.append(factory(db))
    return providers


def _case_entities(
    db: Session, case_id: uuid.UUID
) -> list[tuple[uuid.UUID, EntityType, str, uuid.UUID, int, str | None]]:
    """Every checkable entity in a case, with the artifact each occurrence came from."""
    rows = db.execute(
        select(
            Entity.id,
            Entity.type,
            Entity.canonical_value,
            EntityOccurrence.evidence_id,
            EntityOccurrence.occurrence_count,
            EntityOccurrence.context,
        )
        .join(EntityOccurrence, EntityOccurrence.entity_id == Entity.id)
        .where(
            EntityOccurrence.case_id == case_id,
            Entity.type.in_(_ENTITY_TO_INDICATOR.keys()),
        )
    ).all()
    return [
        (row[0], row[1], row[2], row[3], int(row[4] or 1), row[5]) for row in rows
    ]


def check_case(
    db: Session, case_id: uuid.UUID, *, providers: list[ThreatIntelProvider] | None = None
) -> dict[str, Any]:
    """Look up every checkable indicator in a case and record the matches."""
    entities = _case_entities(db, case_id)
    if not entities:
        return {"checked": 0, "matched": 0, "recorded": 0}

    by_type: dict[IndicatorType, set[str]] = {}
    for _id, entity_type, value, _evidence, _count, _context in entities:
        indicator_type = _ENTITY_TO_INDICATOR[entity_type]
        by_type.setdefault(indicator_type, set()).add(value)

    active = providers if providers is not None else build_providers(db)
    records: list[IndicatorRecord] = []
    failures: list[str] = []
    for provider in active:
        try:
            records.extend(provider.lookup(by_type))
        except Exception as exc:
            failures.append(f"{provider.name}: {type(exc).__name__}")
            logger.exception("threat_intel_lookup_failed", provider=provider.name)

    if not records:
        # Only safe to mark values as "checked, clean" when every provider actually answered. If a
        # feed errored, saying nothing is known about a value would be a claim we cannot support.
        if not failures:
            _clear_intel_marks(db, [entity[0] for entity in entities])
        return {
            "checked": sum(len(values) for values in by_type.values()),
            "matched": 0,
            "recorded": 0,
            "providers": [provider.name for provider in active],
            "provider_failures": failures,
        }

    indicator_ids = _upsert_indicators(db, records)
    recorded = _record_matches(
        db, case_id, entities, records, indicator_ids, clear_unmatched=not failures
    )

    return {
        "checked": sum(len(values) for values in by_type.values()),
        "matched": len({record.value for record in records}),
        "recorded": recorded,
        "providers": [provider.name for provider in active],
        "provider_failures": failures,
    }


def _upsert_indicators(
    db: Session, records: list[IndicatorRecord]
) -> dict[tuple[IndicatorType, str, str], uuid.UUID]:
    """Ensure every returned record exists locally, and return their ids.

    Remote providers write through to the local table so their answers are cached, attributable and
    still present if the service later becomes unreachable.
    """
    now = utcnow()
    identifiers: dict[tuple[IndicatorType, str, str], uuid.UUID] = {}

    for record in records:
        key = (record.type, record.value, record.source)
        if key in identifiers:
            continue

        statement = (
            pg_insert(ThreatIndicator)
            .values(
                id=uuid.uuid4(),
                type=record.type,
                canonical_value=record.value,
                severity=record.severity,
                confidence=record.confidence,
                source=record.source,
                source_reference=record.source_reference,
                description=record.description,
                tags=record.tags,
                threat_actor=record.threat_actor,
                malware_family=record.malware_family,
                first_seen_at=record.first_seen_at or now,
                last_seen_at=record.last_seen_at or now,
                is_active=True,
            )
            .on_conflict_do_update(
                constraint="uq_threat_indicators_type_value_source",
                set_={
                    "severity": record.severity,
                    "confidence": record.confidence,
                    "description": record.description,
                    "tags": record.tags,
                    "threat_actor": record.threat_actor,
                    "malware_family": record.malware_family,
                    "last_seen_at": record.last_seen_at or now,
                    "is_active": True,
                },
            )
            .returning(ThreatIndicator.id)
        )
        identifiers[key] = db.execute(statement).scalar_one()

    db.flush()
    return identifiers


def _record_matches(
    db: Session,
    case_id: uuid.UUID,
    entities: list[tuple[uuid.UUID, EntityType, str, uuid.UUID, int, str | None]],
    records: list[IndicatorRecord],
    indicator_ids: dict[tuple[IndicatorType, str, str], uuid.UUID],
    *,
    clear_unmatched: bool,
) -> int:
    """Attach matches to the entity occurrences that produced them, and mark the entities."""
    by_value: dict[tuple[IndicatorType, str], list[IndicatorRecord]] = {}
    for record in records:
        by_value.setdefault((record.type, record.value), []).append(record)

    matched_entities: dict[uuid.UUID, list[IndicatorRecord]] = {}
    recorded = 0

    for entity_id, entity_type, value, evidence_id, count, context in entities:
        indicator_type = _ENTITY_TO_INDICATOR[entity_type]
        hits = by_value.get((indicator_type, value))
        if not hits:
            continue

        matched_entities.setdefault(entity_id, []).extend(hits)

        for record in hits:
            indicator_id = indicator_ids[(record.type, record.value, record.source)]
            statement = (
                pg_insert(IndicatorMatch)
                .values(
                    id=uuid.uuid4(),
                    indicator_id=indicator_id,
                    entity_id=entity_id,
                    evidence_id=evidence_id,
                    case_id=case_id,
                    occurrence_count=count,
                    context=context,
                )
                .on_conflict_do_update(
                    constraint="uq_indicator_matches_indicator_id_evidence_id",
                    set_={"occurrence_count": count, "context": context},
                )
            )
            db.execute(statement)
            recorded += 1

    _apply_intel_marks(db, matched_entities)
    if clear_unmatched:
        _clear_intel_marks(
            db,
            [entity[0] for entity in entities if entity[0] not in matched_entities],
        )
    db.flush()
    return recorded


def _apply_intel_marks(
    db: Session, matched: dict[uuid.UUID, list[IndicatorRecord]]
) -> None:
    """Denormalise the worst verdict onto each entity.

    Cached on the entity so a list of two hundred indicators can be rendered with its reputation
    without a join per row; the authoritative, attributable detail stays in ``indicator_matches``.
    """
    if not matched:
        return

    ranking = {
        IndicatorSeverity.benign: 0,
        IndicatorSeverity.suspicious: 1,
        IndicatorSeverity.malicious: 2,
    }
    now = utcnow()
    entities = db.scalars(select(Entity).where(Entity.id.in_(matched.keys()))).all()

    for entity in entities:
        hits = matched[entity.id]
        worst = max(hits, key=lambda record: ranking.get(record.severity, 0))
        tags = sorted(
            {tag for record in hits for tag in record.tags}
            | {f"source:{record.source}" for record in hits}
        )
        entity.intel_severity = worst.severity
        entity.intel_tags = tags
        entity.intel_checked_at = now


def _clear_intel_marks(db: Session, entity_ids: list[uuid.UUID]) -> None:
    """Record that these values were checked and nothing was known about them.

    "Checked, no match" is materially different from "never checked", and only the first justifies
    an interface telling an investigator that a value is not on any list.
    """
    if not entity_ids:
        return
    now = utcnow()
    for entity in db.scalars(select(Entity).where(Entity.id.in_(entity_ids))).all():
        entity.intel_severity = None
        entity.intel_tags = []
        entity.intel_checked_at = now
