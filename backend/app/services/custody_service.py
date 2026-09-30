"""Chain-of-custody reads and verification.

Writing to a custody chain is the exclusive job of :func:`app.audit.writer.append_custody`, and
nothing in this module writes. That is intentional: a single append path is what makes the
"append-only" claim checkable, and it means every custody event in the system was produced by the
same hashing and signing code.

What this module adds is the reading side, including the part that makes the chain worth having -
replaying it and reporting whether it verifies, so the interface can show a chain's state rather
than simply displaying a list of events and implying they are trustworthy.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import Select, func, or_, select
from sqlalchemy.orm import Session, joinedload

from app.audit.chain import ChainVerification, verify_custody_chain
from app.core.clock import utcnow
from app.core.context import RequestContext
from app.core.pagination import PageParams, paginate
from app.models.custody import CustodyEvent
from app.models.enums import CustodyAction
from app.models.evidence import Evidence
from app.security.scoping import scope_case_ids
from app.services import case_service, evidence_service


@dataclass(frozen=True, slots=True)
class ChainIssue:
    """One problem found while replaying a chain."""

    kind: str
    sequence: int
    record_id: str
    detail: str


@dataclass(frozen=True, slots=True)
class ChainStatus:
    """A custody chain's verification state, as presented to an investigator."""

    evidence_id: uuid.UUID
    evidence_reference: str
    event_count: int
    intact: bool
    head_hash: str | None
    # Whether the denormalised head on the evidence row agrees with the chain's actual head. A
    # disagreement means events were removed from the tail, which replaying alone cannot reveal.
    head_matches_record: bool
    signatures_checked: int
    signatures_valid: int
    breaks: list[ChainIssue]
    summary: str
    verified_at: datetime

    @property
    def trustworthy(self) -> bool:
        return self.intact and self.head_matches_record


def _base_query() -> Select[tuple[CustodyEvent]]:
    return select(CustodyEvent).options(joinedload(CustodyEvent.actor))


def list_for_evidence(
    db: Session, ctx: RequestContext, evidence_id: uuid.UUID
) -> list[CustodyEvent]:
    """Full custody history for one item, oldest first.

    Deliberately unpaginated. A custody chain is a single document that must be read in order to
    mean anything, and paginating it would invite a reader to draw conclusions from a fragment.
    """
    evidence_service.get_evidence(db, ctx, evidence_id)
    return list(
        db.execute(
            _base_query()
            .where(CustodyEvent.evidence_id == evidence_id)
            .order_by(CustodyEvent.sequence)
        )
        .unique()
        .scalars()
        .all()
    )


def list_for_case(
    db: Session,
    ctx: RequestContext,
    params: PageParams,
    *,
    case_id: uuid.UUID | None = None,
    evidence_id: uuid.UUID | None = None,
    actions: list[CustodyAction] | None = None,
    actor_id: uuid.UUID | None = None,
    occurred_after: datetime | None = None,
    occurred_before: datetime | None = None,
    search: str | None = None,
) -> tuple[list[CustodyEvent], int]:
    """Custody activity across a case or the whole platform, newest first."""
    stmt = scope_case_ids(_base_query(), ctx, CustodyEvent.case_id)

    if case_id:
        case_service.get_case(db, ctx, case_id)
        stmt = stmt.where(CustodyEvent.case_id == case_id)
    if evidence_id:
        evidence_service.get_evidence(db, ctx, evidence_id)
        stmt = stmt.where(CustodyEvent.evidence_id == evidence_id)
    if actions:
        stmt = stmt.where(CustodyEvent.action.in_(actions))
    if actor_id:
        stmt = stmt.where(CustodyEvent.actor_id == actor_id)
    if occurred_after:
        stmt = stmt.where(CustodyEvent.occurred_at >= occurred_after)
    if occurred_before:
        stmt = stmt.where(CustodyEvent.occurred_at <= occurred_before)
    if search:
        pattern = f"%{search.strip()}%"
        stmt = stmt.where(
            or_(
                CustodyEvent.actor_label.ilike(pattern),
                CustodyEvent.reason.ilike(pattern),
                CustodyEvent.notes.ilike(pattern),
            )
        )

    stmt = stmt.order_by(CustodyEvent.recorded_at.desc(), CustodyEvent.sequence.desc())
    return paginate(db, stmt, params)


def verify_chain(db: Session, ctx: RequestContext, evidence_id: uuid.UUID) -> ChainStatus:
    """Replay an item's custody chain and report whether it verifies."""
    evidence = evidence_service.get_evidence(db, ctx, evidence_id)
    return chain_status(db, evidence)


def chain_status(db: Session, evidence: Evidence) -> ChainStatus:
    """Replay a loaded item's chain. Assumes access has already been established.

    Separate from :func:`verify_chain` so background verification can sweep every item without
    each pass re-running the authorization query for a context that already bypasses it.
    """
    verification: ChainVerification = verify_custody_chain(db, evidence.id)
    head_matches = verification.head_hash == evidence.custody_head_hash

    breaks = [
        ChainIssue(
            kind=item.kind,
            sequence=item.sequence,
            record_id=item.record_id,
            detail=item.detail,
        )
        for item in verification.breaks
    ]
    if not head_matches:
        # Replaying alone cannot detect truncation: a chain missing its last events still
        # verifies internally. The denormalised head on the evidence row is the second witness.
        breaks.append(
            ChainIssue(
                kind="head_mismatch",
                sequence=verification.last_sequence or 0,
                record_id=str(evidence.id),
                detail=(
                    "The chain's final entry does not match the head hash recorded on the "
                    "evidence item, which indicates one or more events were removed from the "
                    "end of the chain."
                ),
            )
        )

    return ChainStatus(
        evidence_id=evidence.id,
        evidence_reference=evidence.reference,
        event_count=verification.entries_checked,
        intact=verification.intact,
        head_hash=verification.head_hash,
        head_matches_record=head_matches,
        signatures_checked=verification.signatures_checked,
        signatures_valid=verification.signatures_valid,
        breaks=breaks,
        summary=verification.summary if head_matches else "chain tail has been truncated",
        verified_at=utcnow(),
    )


def action_counts(
    db: Session, ctx: RequestContext, *, case_id: uuid.UUID | None = None
) -> dict[str, int]:
    """Custody event totals by action, for the case activity panel."""
    stmt = scope_case_ids(
        select(CustodyEvent.action, func.count()).group_by(CustodyEvent.action),
        ctx,
        CustodyEvent.case_id,
    )
    if case_id:
        stmt = stmt.where(CustodyEvent.case_id == case_id)
    counts = {action.value: 0 for action in CustodyAction}
    for action, count in db.execute(stmt).all():
        counts[action.value] = count
    return counts
