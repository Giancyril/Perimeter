"""
Alert Ingestion & Deduplication Engine.
Normalizes incoming alerts through the adapter registry, enforces deterministic SHA-256 deduplication,
and preserves the original intact raw payload for auditability and forensic trace.
"""
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
import threading
from backend.ingestion.models import (
    NormalizedAlert,
    IngestionResult,
    SeverityLevel,
    AlertSourceType,
    utc_now,
)
from backend.ingestion.adapters.registry import adapter_registry

class IngestionEngine:
    """Core alert ingestion pipeline with thread-safe deduplication and storage."""

    def __init__(self, dedup_window_seconds: int = 600):
        self.dedup_window_seconds = dedup_window_seconds
        self._alerts: Dict[str, NormalizedAlert] = {}            # alert_id -> NormalizedAlert
        self._fingerprints: Dict[str, str] = {}                  # fingerprint -> alert_id
        self._lock = threading.Lock()

    def ingest(self, payload: Dict[str, Any], explicit_source: Optional[str] = None) -> IngestionResult:
        """
        Ingests, normalizes, and deduplicates an incoming security alert.
        """
        adapter = adapter_registry.resolve_adapter(payload, explicit_source=explicit_source)
        normalized = adapter.normalize(payload)

        with self._lock:
            existing_id = self._fingerprints.get(normalized.fingerprint)

            if existing_id and existing_id in self._alerts:
                existing_alert = self._alerts[existing_id]
                existing_alert.duplicate_count += 1
                existing_alert.last_seen_at = utc_now()
                # Store latest payload updates if critical
                existing_alert.raw_payload = payload

                return IngestionResult(
                    status="deduplicated",
                    alert_id=existing_alert.alert_id,
                    fingerprint=existing_alert.fingerprint,
                    source=existing_alert.source,
                    was_duplicate=True,
                    duplicate_count=existing_alert.duplicate_count,
                    normalized_severity=existing_alert.normalized_severity,
                    summary=f"Deduplicated alert '{existing_alert.rule_name}' (count: {existing_alert.duplicate_count})",
                )

            # Register new unique alert
            self._alerts[normalized.alert_id] = normalized
            self._fingerprints[normalized.fingerprint] = normalized.alert_id

            return IngestionResult(
                status="ingested",
                alert_id=normalized.alert_id,
                fingerprint=normalized.fingerprint,
                source=normalized.source,
                was_duplicate=False,
                duplicate_count=1,
                normalized_severity=normalized.normalized_severity,
                summary=f"Ingested new alert '{normalized.rule_name}' with severity {normalized.normalized_severity.value.upper()}",
            )

    def get_alert(self, alert_id: str) -> Optional[NormalizedAlert]:
        with self._lock:
            return self._alerts.get(alert_id)

    def list_alerts(
        self,
        limit: int = 100,
        severity: Optional[SeverityLevel] = None,
        source: Optional[AlertSourceType] = None,
        host: Optional[str] = None,
        user: Optional[str] = None,
        ip: Optional[str] = None,
    ) -> List[NormalizedAlert]:
        with self._lock:
            results = list(self._alerts.values())

        if severity:
            results = [a for a in results if a.normalized_severity == severity]
        if source:
            results = [a for a in results if a.source == source]
        if host:
            results = [a for a in results if a.host and host.lower() in a.host.lower()]
        if user:
            results = [a for a in results if a.user and user.lower() in a.user.lower()]
        if ip:
            results = [a for a in results if a.source_ip == ip or a.destination_ip == ip]

        # Order by newest first
        results.sort(key=lambda a: a.last_seen_at, reverse=True)
        return results[:limit]

    def get_stats(self) -> Dict[str, Any]:
        with self._lock:
            alerts = list(self._alerts.values())

        total_unique = len(alerts)
        total_raw = sum(a.duplicate_count for a in alerts)
        dedup_ratio = round((total_raw - total_unique) / total_raw, 2) if total_raw > 0 else 0.0

        by_severity = {sev.value: 0 for sev in SeverityLevel}
        by_source = {}

        for a in alerts:
            by_severity[a.normalized_severity.value] += a.duplicate_count
            src_val = a.source.value
            by_source[src_val] = by_source.get(src_val, 0) + a.duplicate_count

        return {
            "total_unique_alerts": total_unique,
            "total_raw_events": total_raw,
            "deduplication_ratio": dedup_ratio,
            "by_severity": by_severity,
            "by_source": by_source,
        }

    def clear(self):
        """Reset storage for testing."""
        with self._lock:
            self._alerts.clear()
            self._fingerprints.clear()

# Global singleton
ingestion_engine = IngestionEngine()
