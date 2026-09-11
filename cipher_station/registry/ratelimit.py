# cipher_station/registry/ratelimit.py
"""
Simple in-memory token bucket per client IP for the public registry routes.
Stdlib-only; per-process (fine for a single-process station)."""

from __future__ import annotations

import threading
import time


class TokenBucket:
    def __init__(self, rate: float, capacity: float):
        self.rate = rate            # tokens per second
        self.capacity = capacity
        self.tokens = capacity
        self.updated = time.monotonic()

    def allow(self, cost: float = 1.0) -> bool:
        now = time.monotonic()
        self.tokens = min(self.capacity, self.tokens + (now - self.updated) * self.rate)
        self.updated = now
        if self.tokens >= cost:
            self.tokens -= cost
            return True
        return False


class RateLimiter:
    """Per-key (client IP) token buckets with lazy pruning."""

    def __init__(self, rate: float = 1.0, capacity: float = 10.0,
                 max_keys: int = 10_000):
        self.rate = rate
        self.capacity = capacity
        self.max_keys = max_keys
        self._buckets: dict[str, TokenBucket] = {}
        self._lock = threading.Lock()

    def allow(self, key: str, cost: float = 1.0) -> bool:
        with self._lock:
            bucket = self._buckets.get(key)
            if bucket is None:
                if len(self._buckets) >= self.max_keys:
                    # Drop the stalest buckets rather than grow unboundedly.
                    for stale in sorted(self._buckets,
                                        key=lambda k: self._buckets[k].updated)[:self.max_keys // 2]:
                        del self._buckets[stale]
                bucket = self._buckets[key] = TokenBucket(self.rate, self.capacity)
            return bucket.allow(cost)

    def reset(self) -> None:
        with self._lock:
            self._buckets.clear()
