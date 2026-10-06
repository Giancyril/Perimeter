"""
Advanced Multi-Dimensional Alert Deduplication for Investigation Agent.

Collapses repetitive alert storms, port scan storms, and redundant EDR signals
into unified, time-windowed alert clusters with exact fingerprint and fuzzy
semantic aggregation. Tracks occurrence frequency and compression telemetry.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set

from backend.ingestion.models import NormalizedAlert


class DeduplicationStrategy(str, Enum):
    EXACT_FINGERPRINT = "EXACT_FINGERPRINT"
    SEMANTIC_CLUSTER = "SEMANTIC_CLUSTER"
    ENTITY_WINDOW = "ENTITY_WINDOW"


@dataclass
class DeduplicatedAlertCluster:
    cluster_id: str
    primary_alert: NormalizedAlert
    strategy: DeduplicationStrategy
    total_occurrences: int = 1
    first_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    source_alert_ids: List[str] = field(default_factory=list)
    aggregated_entities: Set[str] = field(default_factory=set)

    @property
    def compression_ratio(self) -> float:
        """Ratio of suppressed alerts to total raw alerts."""
        if self.total_occurrences <= 1:
            return 0.0
        return (self.total_occurrences - 1) / self.total_occurrences

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cluster_id": self.cluster_id,
            "primary_alert_id": self.primary_alert.alert_id,
            "rule_name": self.primary_alert.rule_name,
            "strategy": self.strategy.value,
            "total_occurrences": self.total_occurrences,
            "compression_ratio": round(self.compression_ratio, 3),
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "source_alert_ids": self.source_alert_ids,
            "aggregated_entities": sorted(list(self.aggregated_entities)),
        }


class AdvancedDeduplicator:
    """Multi-tiered alert deduplicator with sliding temporal aggregation."""

    def __init__(self, time_window_seconds: int = 600) -> None:
        self.time_window_seconds = time_window_seconds
        self._clusters: Dict[str, DeduplicatedAlertCluster] = {}
        self._total_ingested: int = 0

    def _parse_timestamp(self, ts: Any) -> datetime:
        if isinstance(ts, datetime):
            return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)
        if isinstance(ts, str):
            try:
                dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
            except Exception:
                pass
        return datetime.now(timezone.utc)

    def _compute_semantic_key(self, alert: NormalizedAlert) -> str:
        """Constructs a fuzzy key based on source, rule, and principal entities."""
        entity_keys = sorted(
            f"{e.type.value}:{e.value}"
            for e in alert.entities
            if e.role in ("SOURCE", "DESTINATION", "TARGET", "ACTOR")
        )
        entity_signature = "|".join(entity_keys) if entity_keys else "no-entity"
        raw_key = f"{alert.source.value}|{alert.rule_id}|{entity_signature}"
        return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()[:16]

    def process(self, alert: NormalizedAlert) -> DeduplicatedAlertCluster:
        """Ingests an alert and returns either an updated cluster or a new one."""
        self._total_ingested += 1
        alert_ts = self._parse_timestamp(alert.timestamp)
        cluster_key = self._compute_semantic_key(alert)

        entity_strings = {f"{e.type.value}:{e.value}" for e in alert.entities}

        if cluster_key in self._clusters:
            cluster = self._clusters[cluster_key]
            delta = (alert_ts - cluster.last_seen).total_seconds()
            if abs(delta) <= self.time_window_seconds:
                cluster.total_occurrences += 1
                if alert_ts > cluster.last_seen:
                    cluster.last_seen = alert_ts
                if alert_ts < cluster.first_seen:
                    cluster.first_seen = alert_ts
                cluster.source_alert_ids.append(alert.alert_id)
                cluster.aggregated_entities.update(entity_strings)
                return cluster

        new_cluster = DeduplicatedAlertCluster(
            cluster_id=f"cl-{cluster_key}",
            primary_alert=alert,
            strategy=DeduplicationStrategy.SEMANTIC_CLUSTER,
            total_occurrences=1,
            first_seen=alert_ts,
            last_seen=alert_ts,
            source_alert_ids=[alert.alert_id],
            aggregated_entities=entity_strings,
        )
        self._clusters[cluster_key] = new_cluster
        return new_cluster

    def batch_process(self, alerts: List[NormalizedAlert]) -> List[DeduplicatedAlertCluster]:
        """Processes a batch of alerts in chronological order."""
        sorted_alerts = sorted(alerts, key=lambda a: self._parse_timestamp(a.timestamp))
        for a in sorted_alerts:
            self.process(a)
        return list(self._clusters.values())

    def get_telemetry(self) -> Dict[str, Any]:
        """Provides operational metrics on noise reduction and deduplication efficiency."""
        total_clusters = len(self._clusters)
        suppressed = max(0, self._total_ingested - total_clusters)
        overall_compression = (
            (suppressed / self._total_ingested) if self._total_ingested > 0 else 0.0
        )
        return {
            "total_ingested": self._total_ingested,
            "unique_clusters": total_clusters,
            "suppressed_duplicates": suppressed,
            "overall_compression_ratio": round(overall_compression, 4),
            "window_seconds": self.time_window_seconds,
        }
