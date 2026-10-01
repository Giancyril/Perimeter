"""
Ingestion Pipeline Telemetry & Performance Metrics.
Provides thread-safe real-time operational telemetry for alert ingestion:
- Counters for total ingested, normalized, deduplicated, rate-limited, storm-suppressed, and DLQ-captured alerts.
- Per-source and per-severity distribution matrices.
- Microsecond-resolution latency distribution percentiles (mean, p50, p95, p99, max).
- Snapshot export for SOC monitoring dashboards and Prometheus-compatible metrics exporters.
"""
import time
import threading
from typing import Dict, Any, List, Optional
from collections import defaultdict


class IngestionTelemetry:
    """
    Thread-safe metrics aggregator for alert ingestion stages.
    """

    def __init__(self, latency_window_size: int = 1000):
        self._lock = threading.Lock()
        self._latency_window_size = latency_window_size
        self._start_time = time.time()

        # Operational counters
        self._total_received = 0
        self._total_normalized = 0
        self._total_deduplicated = 0
        self._total_rate_limited = 0
        self._total_storm_suppressed = 0
        self._total_dlq_routed = 0
        self._total_failed = 0

        # Categorical distributions
        self._by_source: Dict[str, int] = defaultdict(int)
        self._by_severity: Dict[str, int] = defaultdict(int)

        # Ring-buffer of recent processing latencies (in milliseconds)
        self._latencies_ms: List[float] = []

    def record_received(self, source_name: str = "unknown") -> None:
        with self._lock:
            self._total_received += 1
            self._by_source[str(source_name).lower()] += 1

    def record_normalized(self, severity: str = "medium", latency_ms: float = 0.0) -> None:
        with self._lock:
            self._total_normalized += 1
            self._by_severity[str(severity).lower()] += 1
            if latency_ms >= 0:
                self._latencies_ms.append(float(latency_ms))
                if len(self._latencies_ms) > self._latency_window_size:
                    self._latencies_ms.pop(0)

    def record_deduplicated(self) -> None:
        with self._lock:
            self._total_deduplicated += 1

    def record_rate_limited(self) -> None:
        with self._lock:
            self._total_rate_limited += 1

    def record_storm_suppressed(self) -> None:
        with self._lock:
            self._total_storm_suppressed += 1

    def record_dlq_routed(self) -> None:
        with self._lock:
            self._total_dlq_routed += 1

    def record_failed(self) -> None:
        with self._lock:
            self._total_failed += 1

    def compute_percentiles(self) -> Dict[str, float]:
        with self._lock:
            if not self._latencies_ms:
                return {"mean_ms": 0.0, "p50_ms": 0.0, "p95_ms": 0.0, "p99_ms": 0.0, "max_ms": 0.0}
            sorted_lat = sorted(self._latencies_ms)
            n = len(sorted_lat)
            def p(pct: float) -> float:
                idx = min(int(n * pct), n - 1)
                return round(sorted_lat[idx], 3)
            return {
                "mean_ms": round(sum(sorted_lat) / n, 3),
                "p50_ms": p(0.50),
                "p95_ms": p(0.95),
                "p99_ms": p(0.99),
                "max_ms": round(sorted_lat[-1], 3),
            }

    def get_snapshot(self) -> Dict[str, Any]:
        with self._lock:
            uptime_sec = max(1.0, time.time() - self._start_time)
            throughput_eps = round(self._total_received / uptime_sec, 2)
            lat_stats = self.compute_percentiles()
            return {
                "uptime_seconds": round(uptime_sec, 1),
                "throughput_events_per_sec": throughput_eps,
                "counters": {
                    "total_received": self._total_received,
                    "total_normalized": self._total_normalized,
                    "total_deduplicated": self._total_deduplicated,
                    "total_rate_limited": self._total_rate_limited,
                    "total_storm_suppressed": self._total_storm_suppressed,
                    "total_dlq_routed": self._total_dlq_routed,
                    "total_failed": self._total_failed,
                },
                "by_source": dict(self._by_source),
                "by_severity": dict(self._by_severity),
                "latency_stats": lat_stats,
            }

    def reset(self) -> None:
        with self._lock:
            self._start_time = time.time()
            self._total_received = 0
            self._total_normalized = 0
            self._total_deduplicated = 0
            self._total_rate_limited = 0
            self._total_storm_suppressed = 0
            self._total_dlq_routed = 0
            self._total_failed = 0
            self._by_source.clear()
            self._by_severity.clear()
            self._latencies_ms.clear()


ingestion_telemetry = IngestionTelemetry()
