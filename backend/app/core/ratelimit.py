"""In-process rate limiting.

A sliding-window counter held in memory. This is honest about its scope: it protects a single
API process, so a multi-process deployment would need shared state. The interface is kept
narrow (:meth:`RateLimiter.check`) precisely so that swapping in a Redis-backed
implementation later is a substitution rather than a rewrite.

It is a second line of defence in any case. The durable control is the per-account lockout in
:mod:`app.services.auth_service`, which is enforced in the database and therefore cannot be
bypassed by spreading attempts across processes.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class RateLimitDecision:
    allowed: bool
    retry_after_seconds: int


class RateLimiter:
    def __init__(self, *, limit: int, window_seconds: int, max_tracked_keys: int = 20_000) -> None:
        self._limit = limit
        self._window = window_seconds
        self._max_tracked = max_tracked_keys
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def check(self, key: str) -> RateLimitDecision:
        now = time.monotonic()
        cutoff = now - self._window

        with self._lock:
            # Bound memory: an attacker rotating source addresses must not be able to grow
            # this dictionary without limit.
            if len(self._hits) > self._max_tracked:
                self._evict_stale(cutoff)

            hits = self._hits[key]
            while hits and hits[0] < cutoff:
                hits.popleft()

            if len(hits) >= self._limit:
                retry_after = max(1, int(self._window - (now - hits[0])))
                return RateLimitDecision(allowed=False, retry_after_seconds=retry_after)

            hits.append(now)
            return RateLimitDecision(allowed=True, retry_after_seconds=0)

    def _evict_stale(self, cutoff: float) -> None:
        for key in [k for k, v in self._hits.items() if not v or v[-1] < cutoff]:
            del self._hits[key]

    def reset(self, key: str | None = None) -> None:
        with self._lock:
            if key is None:
                self._hits.clear()
            else:
                self._hits.pop(key, None)


# Authentication endpoints are the ones worth throttling at the edge.
auth_limiter = RateLimiter(limit=20, window_seconds=60)
