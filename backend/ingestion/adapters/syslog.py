"""
Syslog Alert Source Adapter.
Normalizes standard RFC 5424 / RFC 3164 Syslog messages into standard NormalizedAlerts.
"""
from typing import Dict, Any, List, Optional
import uuid
import re
from backend.ingestion.base import AlertSourceAdapter
from backend.ingestion.models import (
    NormalizedAlert,
    AlertSourceType,
    SeverityLevel,
    Entity,
    EntityType,
    EntityRole,
    utc_now,
)

class SyslogAdapter(AlertSourceAdapter):
    """Adapter for RFC 5424 / RFC 3164 Syslog alerts."""

    @property
    def source_type(self) -> AlertSourceType:
        return AlertSourceType.SYSLOG

    def can_handle(self, payload: Dict[str, Any]) -> bool:
        if not isinstance(payload, dict):
            return False
        if payload.get("source") == "syslog":
            return True
        if "facility" in payload and "severity" in payload and ("message" in payload or "msg" in payload):
            return True
        return False

    @staticmethod
    def map_syslog_severity(pri_or_sev: Any) -> SeverityLevel:
        """
        Maps standard Syslog severity (0-7):
        - 0 (Emergency), 1 (Alert), 2 (Critical) -> CRITICAL
        - 3 (Error) -> HIGH
        - 4 (Warning) -> MEDIUM
        - 5 (Notice) -> LOW
        - 6 (Informational), 7 (Debug) -> INFORMATIONAL
        """
        try:
            val = int(pri_or_sev)
        except (ValueError, TypeError):
            val = 4

        if val in [0, 1, 2]:
            return SeverityLevel.CRITICAL
        elif val == 3:
            return SeverityLevel.HIGH
        elif val == 4:
            return SeverityLevel.MEDIUM
        elif val == 5:
            return SeverityLevel.LOW
        else:
            return SeverityLevel.INFORMATIONAL

    def normalize(self, payload: Dict[str, Any]) -> NormalizedAlert:
        raw_sev = payload.get("severity", 4)
        normalized_severity = self.map_syslog_severity(raw_sev)
        message = str(payload.get("message") or payload.get("msg") or "Syslog event")
        app_name = str(payload.get("app_name") or payload.get("program") or "syslogd")
        host = str(payload.get("hostname") or payload.get("host") or "unknown-host")
        timestamp = str(payload.get("timestamp") or utc_now())
        alert_id = str(payload.get("id") or f"syslog-{uuid.uuid4().hex[:12]}")

        # Extract IPv4 from message if present
        ip_matches = re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", message)
        src_ip = ip_matches[0] if ip_matches else payload.get("src_ip")

        # Extract User if pattern matches user/for user
        user_match = re.search(r"(?:user|for)\s+([a-zA-Z0-9_\-\.]+)", message, re.IGNORECASE)
        user = user_match.group(1) if user_match else payload.get("user")

        entities: List[Entity] = []
        if host:
            entities.append(Entity(type=EntityType.HOST, value=host, role=EntityRole.TARGET))
        if src_ip:
            entities.append(Entity(type=EntityType.IP, value=src_ip, role=EntityRole.SOURCE))
        if user:
            entities.append(Entity(type=EntityType.USER, value=user, role=EntityRole.ACTOR))
        if app_name:
            entities.append(Entity(type=EntityType.PROCESS, value=app_name, role=EntityRole.ACTOR))

        fingerprint = self.compute_fingerprint(
            source=self.source_type.value,
            rule_id=app_name,
            source_ip=src_ip,
            user=user,
            host=host,
            process_name=app_name,
        )

        return NormalizedAlert(
            alert_id=alert_id,
            fingerprint=fingerprint,
            source=self.source_type,
            rule_id=app_name,
            rule_name=f"Syslog: {app_name}",
            rule_description=message[:200],
            raw_severity=str(raw_sev),
            normalized_severity=normalized_severity,
            timestamp=timestamp,
            ingested_at=utc_now(),
            first_seen_at=timestamp,
            last_seen_at=timestamp,
            duplicate_count=1,
            source_ip=src_ip,
            user=user,
            host=host,
            process_name=app_name,
            entities=entities,
            raw_payload=payload,
        )
