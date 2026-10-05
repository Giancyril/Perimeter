"""
Correlation Engine Cluster Telemetry & Reduction Performance Monitor.
Calculates real-time alert compression ratios, correlation processing latencies (p50/p95/p99),
and entity pivot degree histograms for operational SOC metrics.
"""
from typing import Dict, List, Optional, Any
from collections import Counter
import time
import math
from backend.correlation.models import CorrelatedIncident
from backend.ingestion.models import SeverityLevel

class CorrelationTelemetry:
    """Tracks real-time performance and compression statistics for event correlation."""

    def __init__(self):
        self.total_alerts_ingested = 0
        self.total_alerts_suppressed = 0
        self.total_correlations_executed = 0
        self.correlation_latencies_ms: List[float] = []

    def record_correlation_latency(self, latency_ms: float) -> None:
        self.total_correlations_executed += 1
        self.correlation_latencies_ms.append(latency_ms)
        # Bounded buffer of last 2000 latency observations
        if len(self.correlation_latencies_ms) > 2000:
            self.correlation_latencies_ms = self.correlation_latencies_ms[-1000:]

    def get_latency_percentiles(self) -> Dict[str, float]:
        if not self.correlation_latencies_ms:
            return {"p50": 0.0, "p95": 0.0, "p99": 0.0, "avg": 0.0}

        sorted_lat = sorted(self.correlation_latencies_ms)
        n = len(sorted_lat)

        def pct(p: float) -> float:
            idx = int(math.ceil(p * n)) - 1
            return round(sorted_lat[max(0, min(n - 1, idx))], 2)

        return {
            "p50": pct(0.50),
            "p95": pct(0.95),
            "p99": pct(0.99),
            "avg": round(sum(sorted_lat) / n, 2),
        }

    def compute_summary(self, incidents: List[CorrelatedIncident]) -> Dict[str, Any]:
        total_incidents = len(incidents)
        total_correlated_alerts = sum(inc.alert_count for inc in incidents)
        total_processed = total_correlated_alerts + self.total_alerts_suppressed

        # Compression / Noise Reduction Ratio: (alerts - incidents) / alerts * 100
        reduction_rate = 0.0
        if total_correlated_alerts > 0:
            reduction_rate = round(((total_correlated_alerts - total_incidents) / total_correlated_alerts) * 100.0, 1)

        # Severity breakdown
        sev_counts = Counter(inc.severity.value for inc in incidents)

        # Top pivot entities
        entity_counter = Counter()
        for inc in incidents:
            for ent in inc.entities:
                entity_counter[f"{ent.entity_type.value}:{ent.value}"] += 1

        top_pivots = [
            {"entity": k, "incident_count": v}
            for k, v in entity_counter.most_common(5)
        ]

        return {
            "total_incidents": total_incidents,
            "total_alerts_correlated": total_correlated_alerts,
            "total_alerts_suppressed": self.total_alerts_suppressed,
            "noise_reduction_percentage": max(0.0, reduction_rate),
            "severity_distribution": dict(sev_counts),
            "latency_percentiles_ms": self.get_latency_percentiles(),
            "top_pivot_entities": top_pivots,
        }
