"""
Adaptive Token-Bucket Rate Limiter & Backpressure Protection.
Protects the ingestion pipeline against webhook alert floods and resource exhaustion:
- Thread-safe Token Bucket implementation per tenant/source key.
- Dynamic burst capacity and fractional token refill calculation.
- Backpressure status inspection (tokens remaining, rejection counters).
- Standard Retry-After calculation for HTTP 429 responses.
"""
import time
import threading
from typing import Dict, Any, Optional, Tuple
from pydantic import BaseModel, Field


class RateLimitStatus(BaseModel):
    allowed: bool
    source_key: str
    tokens_remaining: float
    max_capacity: float
    retry_after_seconds: float = 0.0
    rejected_count: int = 0


class TokenBucket:
    """Thread-safe Token Bucket state for a single source identifier."""

    def __init__(self, capacity: float, refill_rate_per_sec: float):
        self.capacity = float(capacity)
        self.refill_rate = float(refill_rate_per_sec)
        self.tokens = float(capacity)
        self.last_refill_timestamp = time.time()
        self.rejected_count = 0
        self._lock = threading.Lock()

    def consume(self, tokens_needed: float = 1.0, current_time: Optional[float] = None) -> Tuple[bool, float, float]:
        """
        Attempts to consume tokens.
        Returns (allowed: bool, tokens_remaining: float, retry_after: float).
        """
        with self._lock:
            now = current_time if current_time is not None else time.time()
            elapsed = max(0.0, now - self.last_refill_timestamp)
            self.last_refill_timestamp = now

            # Refill tokens up to maximum capacity
            self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_rate)

            if self.tokens >= tokens_needed:
                self.tokens -= tokens_needed
                return True, self.tokens, 0.0
            else:
                self.rejected_count += 1
                missing_tokens = tokens_needed - self.tokens
                retry_after = missing_tokens / self.refill_rate if self.refill_rate > 0 else 1.0
                return False, self.tokens, round(retry_after, 2)


class IngestionRateLimiter:
    """
    Manages rate limits across different SIEM alert sources, clients, and tenants.
    """

    def __init__(
        self,
        default_capacity: float = 100.0,
        default_refill_rate: float = 20.0,
    ):
        self.default_capacity = default_capacity
        self.default_refill_rate = default_refill_rate
        self._buckets: Dict[str, TokenBucket] = {}
        self._lock = threading.Lock()

    def check_rate_limit(
        self,
        source_key: str = "default",
        tokens_needed: float = 1.0,
        capacity_override: Optional[float] = None,
        refill_rate_override: Optional[float] = None,
    ) -> RateLimitStatus:
        with self._lock:
            if source_key not in self._buckets:
                cap = capacity_override or self.default_capacity
                rate = refill_rate_override or self.default_refill_rate
                self._buckets[source_key] = TokenBucket(capacity=cap, refill_rate_per_sec=rate)
            bucket = self._buckets[source_key]

        allowed, remaining, retry_after = bucket.consume(tokens_needed)
        return RateLimitStatus(
            allowed=allowed,
            source_key=source_key,
            tokens_remaining=round(remaining, 2),
            max_capacity=bucket.capacity,
            retry_after_seconds=retry_after,
            rejected_count=bucket.rejected_count,
        )

    def get_stats(self) -> Dict[str, Any]:
        with self._lock:
            stats = {}
            for key, bucket in self._buckets.items():
                stats[key] = {
                    "capacity": bucket.capacity,
                    "refill_rate": bucket.refill_rate,
                    "tokens_available": round(bucket.tokens, 2),
                    "rejected_requests": bucket.rejected_count,
                }
            return stats

    def reset(self):
        with self._lock:
            self._buckets.clear()


ingestion_rate_limiter = IngestionRateLimiter()
