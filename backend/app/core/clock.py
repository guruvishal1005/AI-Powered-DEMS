"""Time utilities.

CYBERTRACE separates two notions of time and never conflates them:

``occurred_at``
    When something happened in the real world (an email was sent, a log line was
    written, evidence was seized). Sourced from evidence content or investigator input,
    therefore untrusted and possibly wrong or absent.

``recorded_at``
    When the platform observed it. Sourced from the server clock, authoritative, and
    used for every hash-chained record so ordering is defensible.
"""

from __future__ import annotations

from datetime import UTC, datetime


def utcnow() -> datetime:
    """Authoritative, timezone-aware server time."""
    return datetime.now(UTC)


def ensure_utc(value: datetime) -> datetime:
    """Normalise a datetime to UTC, treating naive input as UTC."""
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def isoformat(value: datetime) -> str:
    """RFC 3339 representation used inside canonical hash payloads."""
    return ensure_utc(value).isoformat().replace("+00:00", "Z")
