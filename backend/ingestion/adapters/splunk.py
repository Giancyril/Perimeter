"""
Splunk HTTP Event Collector (HEC) Adapter.
Normalizes Splunk HEC alert payloads (both raw events and pre-indexed events)
into the standard NormalizedAlert schema for unified processing:
- Handles Splunk HEC metadata envelope (time, host, source, sourcetype, index, event).
- Maps Splunk severity field conventions and custom alert severity metadata.
- Extracts source IPs, usernames, and hostnames from Splunk Common Information Model (CIM) fields.
- Classifies ingestion source as AlertSourceType.SPLUNK.
"""
from typing import Dict, Any, Optional
from backend.ingestion.base import AlertSourceAdapter
from backend.ingestion.models import (
    NormalizedAlert,
    SeverityLevel,
    AlertSourceType,
    EntityType,
    EntityRole,
    Entity,
    MitreAttackMetadata,
)


class SplunkAdapter(AlertSourceAdapter):
    """
    Adapter for Splunk HTTP Event Collector (HEC) alert payloads.
    Supports both search-based alerts and real-time streaming events.
    """

    @property
    def source_type(self) -> AlertSourceType:
        return AlertSourceType.SPLUNK

    # Splunk severity string -> SeverityLevel mapping (Splunk uses 1-5 urgency scale)
    _SPLUNK_URGENCY_MAP = {
        "informational": SeverityLevel.INFORMATIONAL,
        "low": SeverityLevel.LOW,
        "medium": SeverityLevel.MEDIUM,
        "high": SeverityLevel.HIGH,
        "critical": SeverityLevel.CRITICAL,
        "1": SeverityLevel.INFORMATIONAL,
        "2": SeverityLevel.LOW,
        "3": SeverityLevel.MEDIUM,
        "4": SeverityLevel.HIGH,
        "5": SeverityLevel.CRITICAL,
    }

    def can_handle(self, payload: Dict[str, Any]) -> bool:
        # Splunk HEC payloads have either 'event' or 'sourcetype' at root
        has_hec_envelope = "event" in payload or "sourcetype" in payload
        explicit_source = str(payload.get("source", "")).lower()
        return has_hec_envelope or "splunk" in explicit_source

    def normalize(self, payload: Dict[str, Any]) -> NormalizedAlert:
        import hashlib, uuid
        from backend.ingestion.models import utc_now

        # Unwrap HEC envelope
        event_data: Dict[str, Any] = payload.get("event", payload)
        if isinstance(event_data, str):
            event_data = {"raw": event_data}

        # HEC metadata
        host = payload.get("host") or event_data.get("host", "unknown")
        sourcetype = payload.get("sourcetype", event_data.get("sourcetype", "generic"))
        splunk_source = payload.get("source", event_data.get("source", "splunk"))
        splunk_time = payload.get("time") or event_data.get("_time", utc_now())

        # Alert identity
        rule_name = (
            event_data.get("search_name")
            or event_data.get("alert_name")
            or event_data.get("rule_name")
            or f"Splunk Alert: {sourcetype}"
        )
        rule_id = event_data.get("search_id") or event_data.get("rule_id") or f"SPLUNK-{uuid.uuid4().hex[:8].upper()}"

        # Severity
        raw_sev = (
            event_data.get("urgency")
            or event_data.get("severity")
            or event_data.get("alert_severity")
            or "medium"
        )
        normalized_severity = self._SPLUNK_URGENCY_MAP.get(str(raw_sev).lower(), SeverityLevel.MEDIUM)

        # Entity extraction (Splunk CIM fields)
        source_ip = event_data.get("src_ip") or event_data.get("src") or event_data.get("source_ip")
        dest_ip = event_data.get("dest_ip") or event_data.get("dest") or event_data.get("destination_ip")
        username = event_data.get("user") or event_data.get("username")
        process_name = event_data.get("process") or event_data.get("process_name")

        # Build entities
        entities = []
        if source_ip:
            entities.append(Entity(type=EntityType.IP, value=source_ip, role=EntityRole.SOURCE))
        if dest_ip:
            entities.append(Entity(type=EntityType.IP, value=dest_ip, role=EntityRole.DESTINATION))
        if host and host != "unknown":
            entities.append(Entity(type=EntityType.HOST, value=host, role=EntityRole.TARGET))
        if username:
            entities.append(Entity(type=EntityType.USER, value=username, role=EntityRole.RELATED))

        # Fingerprint
        fp_raw = f"splunk:{rule_id}:{host}:{source_ip}:{str(splunk_time)}"
        fingerprint = hashlib.sha256(fp_raw.encode()).hexdigest()

        alert_id = f"SPLUNK-{uuid.uuid4().hex[:12].upper()}"

        return NormalizedAlert(
            alert_id=alert_id,
            fingerprint=fingerprint,
            source=AlertSourceType.SPLUNK,
            rule_id=str(rule_id),
            rule_name=rule_name,
            rule_description=event_data.get("description", f"Splunk alert from sourcetype={sourcetype}"),
            raw_severity=str(raw_sev),
            normalized_severity=normalized_severity,
            timestamp=str(splunk_time),
            host=host,
            source_ip=source_ip,
            destination_ip=dest_ip,
            username=username,
            process_name=process_name,
            entities=entities,
            mitre_attack=MitreAttackMetadata(),
            raw_payload=str(payload)[:4096],
        )
