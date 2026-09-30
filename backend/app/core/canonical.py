"""Canonical serialisation for hash-chained records.

Chain verification only works if the bytes hashed today are byte-identical to the bytes
hashed when the record was written. That rules out ordinary JSON dumping, whose key
order and float formatting are not guaranteed stable. Rules enforced here:

* object keys sorted lexicographically
* no insignificant whitespace
* datetimes as RFC 3339 UTC with a ``Z`` suffix
* UUIDs, Decimals and Enums as strings
* floats as their shortest round-trip repr, with NaN and infinity rejected

Any change to this function invalidates every previously written chain, so it is
versioned by :data:`CANONICAL_VERSION` and recorded on each chained row.
"""

from __future__ import annotations

import json
import math
from datetime import date, datetime
from decimal import Decimal
from enum import Enum
from typing import Any
from uuid import UUID

from app.core.clock import isoformat

CANONICAL_VERSION = 1


def _normalise(value: Any) -> Any:
    if value is None or isinstance(value, bool | int | str):
        return value
    if isinstance(value, float):
        # Analyzer output legitimately contains measurements (entropy, confidence, scores),
        # so refusing floats outright would mean a chain append could fail at runtime on
        # ordinary data. Instead they are emitted as text using Python's shortest
        # round-trip repr, which is deterministic for IEEE-754 doubles and therefore safe
        # to re-derive during verification. Non-finite values have no stable meaning in a
        # forensic record and are refused.
        if not math.isfinite(value):
            raise TypeError("NaN and infinity cannot appear in a canonical payload")
        return repr(value)
    if isinstance(value, datetime):
        return isoformat(value)
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, Decimal):
        return format(value, "f")
    if isinstance(value, Enum):
        return _normalise(value.value)
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, dict):
        return {str(k): _normalise(v) for k, v in sorted(value.items(), key=lambda kv: str(kv[0]))}
    if isinstance(value, list | tuple):
        return [_normalise(item) for item in value]
    raise TypeError(f"unsupported type in canonical payload: {type(value)!r}")


def canonical_json(payload: dict[str, Any]) -> str:
    """Deterministic JSON text for hashing."""
    return json.dumps(
        _normalise(payload),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def canonical_bytes(payload: dict[str, Any]) -> bytes:
    return canonical_json(payload).encode("utf-8")


def jsonable(value: Any) -> Any:
    """Convert a value to something JSON-safe, for storage in a ``JSONB`` column.

    Shares the type rules above so that a before/after state recorded in an audit entry is
    represented the same way as one hashed into a chain payload. Unlike :func:`canonical_json`
    this is lenient: an unrecognised type is rendered with ``str()`` rather than raising, because
    failing to record an audit entry is worse than recording an imperfect one.
    """
    try:
        return _normalise(value)
    except TypeError:
        return str(value)
