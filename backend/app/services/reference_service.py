"""Human-readable reference allocation.

References like ``CT-2026-0042`` are what investigators actually quote, so they must be
sequential, gap-tolerant and unique. The sequence is derived from the highest existing
suffix for the year rather than from a database sequence object, because that keeps numbering
meaningful after a draft case is deleted, and because it survives a database restore without
needing the sequence counters to be restored in step.

Allocation runs under an advisory lock per (prefix, year) so two concurrent registrations
cannot be handed the same number.
"""

from __future__ import annotations

import hashlib

from sqlalchemy import Integer, cast, func, select
from sqlalchemy.orm import InstrumentedAttribute, Session

from app.core.clock import utcnow
from app.core.ids import (
    format_alert_ref,
    format_case_ref,
    format_evidence_ref,
    format_report_ref,
)
from app.models.alert import Alert
from app.models.case import Case
from app.models.evidence import Evidence
from app.models.report import Report

REFERENCE_LOCK_NAMESPACE = 0x43545246  # "CTRF"


def _lock(session: Session, prefix: str, year: int) -> None:
    digest = hashlib.sha256(f"{prefix}:{year}".encode()).digest()[:4]
    key = int.from_bytes(digest, "big", signed=True)
    session.execute(select(func.pg_advisory_xact_lock(REFERENCE_LOCK_NAMESPACE, key)))


def _next_sequence(
    session: Session, column: InstrumentedAttribute[str], prefix: str, year: int
) -> int:
    """Highest numeric suffix currently in use for this prefix and year, plus one."""
    pattern = f"{prefix}-{year:04d}-%"
    highest = session.execute(
        select(func.max(cast(func.split_part(column, "-", 3), Integer))).where(column.like(pattern))
    ).scalar()
    return (highest or 0) + 1


def next_case_reference(session: Session) -> str:
    year = utcnow().year
    _lock(session, "CT", year)
    return format_case_ref(year, _next_sequence(session, Case.reference, "CT", year))


def next_evidence_reference(session: Session) -> str:
    year = utcnow().year
    _lock(session, "E", year)
    return format_evidence_ref(year, _next_sequence(session, Evidence.reference, "E", year))


def next_report_reference(session: Session) -> str:
    year = utcnow().year
    _lock(session, "RPT", year)
    return format_report_ref(year, _next_sequence(session, Report.reference, "RPT", year))


def next_alert_reference(session: Session) -> str:
    year = utcnow().year
    _lock(session, "AL", year)
    return format_alert_ref(year, _next_sequence(session, Alert.reference, "AL", year))
