"""Entity normalisation and global resolution.

Correlation is only as good as normalisation. ``Alice@Example.COM`` and ``alice@example.com`` are
the same account, ``2001:0db8:0000::1`` and ``2001:db8::1`` are the same host, and if they resolve
to different rows then the link between two artifacts is silently lost. Every value therefore
passes through a per-type canonicaliser before it reaches the database, while the form it was
originally written in is preserved for display and for quoting in reports.

The counters maintained here are what make correlation *weighted* rather than naive:

``occurrence_count``
    Total sightings, across everything.
``document_frequency``
    How many distinct evidence items contain the value. This drives inverse-document-frequency
    weighting, so a domain appearing in every artifact scores near zero while one appearing in
    exactly two scores highly - which is the difference between finding a real link and drowning
    in matches on ``google.com``.
``case_count``
    How many distinct cases contain it, which is what surfaces cross-case connections.
"""

from __future__ import annotations

import ipaddress
import re
import uuid
from dataclasses import dataclass

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.analysis.base import ExtractedEntity
from app.core.clock import utcnow
from app.core.logging import get_logger
from app.models.analysis import Entity, EntityOccurrence
from app.models.enums import EntityType

logger = get_logger(__name__)

MAX_VALUE_LENGTH = 512
_WHITESPACE = re.compile(r"\s+")
_NON_DIGITS = re.compile(r"[^\d+]")


@dataclass(frozen=True, slots=True)
class ResolvedEntity:
    entity: Entity
    created: bool


def canonicalise(entity_type: EntityType, value: str) -> str | None:
    """Reduce a value to its comparison form, or ``None`` if it is not usable.

    Returning ``None`` is how an analyzer's over-eager match gets discarded: a "domain" that does
    not parse as one, or an address that is not a valid IP, is better dropped than recorded as an
    entity that will never correlate with anything real.
    """
    cleaned = _WHITESPACE.sub(" ", value).strip()
    if not cleaned:
        return None
    cleaned = cleaned[:MAX_VALUE_LENGTH]

    match entity_type:
        case EntityType.ip_address:
            try:
                # Normalises IPv6 to its compressed form and rejects malformed addresses.
                return str(ipaddress.ip_address(cleaned.strip("[]")))
            except ValueError:
                return None

        case EntityType.email_address:
            candidate = cleaned.strip("<>").lower()
            if candidate.count("@") != 1:
                return None
            local, _, domain = candidate.partition("@")
            if not local or "." not in domain:
                return None
            return f"{local}@{_idna(domain)}"

        case EntityType.domain:
            candidate = cleaned.lower().rstrip(".")
            if "." not in candidate or " " in candidate:
                return None
            return _idna(candidate)

        case EntityType.url:
            # Scheme and host are case-insensitive; the path is not, and lowercasing it would
            # merge genuinely different resources.
            if "://" not in cleaned:
                return None
            scheme, _, rest = cleaned.partition("://")
            host, sep, path = rest.partition("/")
            return f"{scheme.lower()}://{host.lower()}{sep}{path}"

        case EntityType.file_hash:
            candidate = cleaned.lower()
            if not re.fullmatch(r"[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64}|[0-9a-f]{128}", candidate):
                return None
            return candidate

        case EntityType.mac_address:
            candidate = re.sub(r"[^0-9a-fA-F]", "", cleaned).lower()
            if len(candidate) != 12:
                return None
            return ":".join(candidate[i : i + 2] for i in range(0, 12, 2))

        case EntityType.phone_number:
            candidate = _NON_DIGITS.sub("", cleaned)
            digits = candidate.lstrip("+")
            if not 7 <= len(digits) <= 15:
                return None
            return candidate

        case EntityType.crypto_wallet:
            # Base58 and bech32 addresses are case-sensitive in general; only bech32 is safely
            # lowercased, and it is already conventionally written that way.
            return cleaned

        case EntityType.cve:
            candidate = cleaned.upper()
            return candidate if re.fullmatch(r"CVE-\d{4}-\d{4,7}", candidate) else None

        case EntityType.file_path | EntityType.registry_key:
            return cleaned.replace("\\", "/") if entity_type is EntityType.file_path else cleaned

        case EntityType.username | EntityType.account:
            return cleaned.lower()

        case _:
            return cleaned


def _idna(domain: str) -> str:
    """Convert an internationalised domain to its ASCII form.

    Homograph domains are a standard phishing technique, so a Cyrillic lookalike must resolve to
    its punycode form; otherwise it would appear identical to the legitimate domain in the
    interface while never correlating with it.
    """
    try:
        return domain.encode("idna").decode("ascii")
    except (UnicodeError, UnicodeDecodeError):
        return domain


def resolve_entity(
    session: Session, entity_type: EntityType, canonical: str, display: str
) -> ResolvedEntity:
    """Find or create the global entity row for a canonical value.

    Uses an upsert rather than a read-then-insert because analysis runs concurrently across
    workers, and two analyzers finding the same address at the same moment must converge on one
    row rather than one of them failing on the unique constraint.
    """
    stmt = (
        pg_insert(Entity)
        .values(
            type=entity_type,
            canonical_value=canonical,
            display_value=display[:MAX_VALUE_LENGTH],
            first_seen_at=utcnow(),
            last_seen_at=utcnow(),
            occurrence_count=0,
            document_frequency=0,
            case_count=0,
            intel_tags=[],
            attributes={},
        )
        .on_conflict_do_nothing(index_elements=["type", "canonical_value"])
        .returning(Entity.id)
    )
    inserted_id = session.execute(stmt).scalar_one_or_none()

    if inserted_id is not None:
        entity = session.get(Entity, inserted_id)
        assert entity is not None
        return ResolvedEntity(entity=entity, created=True)

    entity = session.execute(
        select(Entity)
        .where(Entity.type == entity_type)
        .where(Entity.canonical_value == canonical)
    ).scalar_one()
    return ResolvedEntity(entity=entity, created=False)


def record_occurrence(
    session: Session,
    *,
    extracted: ExtractedEntity,
    evidence_id: uuid.UUID,
    case_id: uuid.UUID,
    analysis_run_id: uuid.UUID | None,
    analyzer: str,
    analyzer_version: str,
) -> EntityOccurrence | None:
    """Persist one sighting, creating the global entity if needed.

    Returns ``None`` when the value did not survive canonicalisation, which is the mechanism by
    which a regex false positive is discarded instead of polluting the graph.
    """
    canonical = canonicalise(extracted.type, extracted.value)
    if canonical is None:
        return None

    resolved = resolve_entity(session, extracted.type, canonical, extracted.value)
    entity = resolved.entity

    occurrence = EntityOccurrence(
        entity_id=entity.id,
        evidence_id=evidence_id,
        case_id=case_id,
        analysis_run_id=analysis_run_id,
        analyzer=analyzer,
        analyzer_version=analyzer_version,
        locator=extracted.locator,
        excerpt=(extracted.excerpt or "")[:2000] or None,
        context=extracted.context,
        confidence=extracted.confidence,
        occurrence_count=extracted.occurrence_count,
    )
    session.add(occurrence)

    now = utcnow()
    entity.last_seen_at = now
    if entity.first_seen_at is None:
        entity.first_seen_at = now
    entity.occurrence_count += extracted.occurrence_count
    return occurrence


def refresh_counters(session: Session, entity_ids: set[uuid.UUID]) -> None:
    """Recompute rarity counters for the entities just touched.

    Derived from the occurrence table rather than incremented in place. Incrementing looks
    cheaper but drifts the moment analysis is re-run over the same artifact, and a rarity weight
    that has drifted quietly corrupts every correlation score built on it.
    """
    if not entity_ids:
        return

    rows = session.execute(
        select(
            EntityOccurrence.entity_id,
            func.count(func.distinct(EntityOccurrence.evidence_id)),
            func.count(func.distinct(EntityOccurrence.case_id)),
            func.coalesce(func.sum(EntityOccurrence.occurrence_count), 0),
        )
        .where(EntityOccurrence.entity_id.in_(entity_ids))
        .group_by(EntityOccurrence.entity_id)
    ).all()

    counters = {
        entity_id: (documents, cases, total) for entity_id, documents, cases, total in rows
    }
    for entity in (
        session.execute(select(Entity).where(Entity.id.in_(entity_ids))).scalars().all()
    ):
        documents, cases, total = counters.get(entity.id, (0, 0, 0))
        entity.document_frequency = documents
        entity.case_count = cases
        entity.occurrence_count = int(total)


def clear_occurrences(
    session: Session, evidence_id: uuid.UUID, analyzer: str | None = None
) -> set[uuid.UUID]:
    """Remove prior occurrences for an item before re-analysis, returning affected entity ids.

    Re-running an analyzer must replace its previous output, not append to it: otherwise every
    re-run would inflate ``occurrence_count`` and make a value look progressively rarer or more
    common than it is.
    """
    stmt = select(EntityOccurrence).where(EntityOccurrence.evidence_id == evidence_id)
    if analyzer is not None:
        stmt = stmt.where(EntityOccurrence.analyzer == analyzer)

    affected: set[uuid.UUID] = set()
    for occurrence in session.execute(stmt).scalars().all():
        affected.add(occurrence.entity_id)
        session.delete(occurrence)
    session.flush()
    return affected
