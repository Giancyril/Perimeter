"""
Generic SIEM / Webhook Alert Source Adapter.
Handles payloads that do not have a dedicated adapter, extracting common OCSF/ECS field aliases.
"""
from typing import Dict, Any, List, Optional
import uuid
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

class GenericAdapter(AlertSourceAdapter):
    """Fallback adapter for generic JSON alerts."""

    @property
    def source_type(self) -> AlertSourceType:
        return AlertSourceType.GENERIC

    def can_handle(self, payload: Dict[str, Any]) -> bool:
        return isinstance(payload, dict)

    @staticmethod
    def map_generic_severity(val: Any) -> SeverityLevel:
        if not val:
            return SeverityLevel.MEDIUM
        v = str(val).lower().strip()
        if v in ["critical", "crit", "fatal", "sev1", "1", "p1"]:
            return SeverityLevel.CRITICAL
        elif v in ["high", "err", "error", "sev2", "2", "p2"]:
            return SeverityLevel.HIGH
        elif v in ["medium", "med", "warn", "warning", "sev3", "3", "p3"]:
            return SeverityLevel.MEDIUM
        elif v in ["low", "info_high", "sev4", "4", "p4"]:
            return SeverityLevel.LOW
        else:
            return SeverityLevel.INFORMATIONAL

    def normalize(self, payload: Dict[str, Any]) -> NormalizedAlert:
        alert_id = str(payload.get("id") or payload.get("alert_id") or f"gen-{uuid.uuid4().hex[:12]}")
        source_name = str(payload.get("source") or "generic").lower()
        
        # Identify source type enum
        try:
            source_enum = AlertSourceType(source_name)
        except ValueError:
            source_enum = AlertSourceType.GENERIC

        rule_id = str(payload.get("rule_id") or payload.get("event_id") or "GEN-001")
        rule_name = str(payload.get("title") or payload.get("rule_name") or payload.get("name") or "Security Alert")
        rule_desc = str(payload.get("description") or payload.get("summary") or rule_name)

        raw_sev = payload.get("severity") or payload.get("level") or "medium"
        norm_sev = self.map_generic_severity(raw_sev)
        timestamp = str(payload.get("timestamp") or utc_now())

        src_ip = payload.get("src_ip") or payload.get("source_ip") or payload.get("client_ip")
        dst_ip = payload.get("dst_ip") or payload.get("destination_ip") or payload.get("server_ip")
        user = payload.get("user") or payload.get("username") or payload.get("account")
        host = payload.get("host") or payload.get("hostname") or payload.get("device_name")
        process_name = payload.get("process") or payload.get("process_name")
        file_hash = payload.get("file_hash") or payload.get("hash") or payload.get("sha256")

        entities: List[Entity] = []
        if src_ip:
            entities.append(Entity(type=EntityType.IP, value=str(src_ip), role=EntityRole.SOURCE))
        if dst_ip:
            entities.append(Entity(type=EntityType.IP, value=str(dst_ip), role=EntityRole.DESTINATION))
        if user:
            entities.append(Entity(type=EntityType.USER, value=str(user), role=EntityRole.ACTOR))
        if host:
            entities.append(Entity(type=EntityType.HOST, value=str(host), role=EntityRole.TARGET))
        if process_name:
            entities.append(Entity(type=EntityType.PROCESS, value=str(process_name), role=EntityRole.ACTOR))
        if file_hash:
            entities.append(Entity(type=EntityType.FILE_HASH, value=str(file_hash), role=EntityRole.RELATED))

        fingerprint = self.compute_fingerprint(
            source=source_name,
            rule_id=rule_id,
            source_ip=src_ip,
            destination_ip=dst_ip,
            user=user,
            host=host,
            process_name=process_name,
            file_hash=file_hash,
        )

        return NormalizedAlert(
            alert_id=alert_id,
            fingerprint=fingerprint,
            source=source_enum,
            rule_id=rule_id,
            rule_name=rule_name,
            rule_description=rule_desc,
            raw_severity=str(raw_sev),
            normalized_severity=norm_sev,
            timestamp=timestamp,
            ingested_at=utc_now(),
            first_seen_at=timestamp,
            last_seen_at=timestamp,
            duplicate_count=1,
            source_ip=src_ip,
            destination_ip=dst_ip,
            user=user,
            host=host,
            process_name=process_name,
            file_hash=file_hash,
            entities=entities,
            raw_payload=payload,
        )
