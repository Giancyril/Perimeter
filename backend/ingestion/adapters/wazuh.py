"""
Wazuh SIEM Alert Source Adapter.
Normalizes raw Wazuh HIDS/XDR alerts into standard OCSF/ECS NormalizedAlerts.
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
    MitreAttackMetadata,
    utc_now,
)

class WazuhAdapter(AlertSourceAdapter):
    """Adapter for Wazuh SIEM / OSSEC alert payloads."""

    @property
    def source_type(self) -> AlertSourceType:
        return AlertSourceType.WAZUH

    def can_handle(self, payload: Dict[str, Any]) -> bool:
        if not isinstance(payload, dict):
            return False
        # Direct source declaration or Wazuh payload signature
        if payload.get("source") == "wazuh":
            return True
        if "rule" in payload and isinstance(payload.get("rule"), dict):
            rule = payload["rule"]
            if "id" in rule and "level" in rule:
                return True
        return False

    @staticmethod
    def map_wazuh_level_to_severity(level: int) -> SeverityLevel:
        """
        Maps Wazuh 0-16 rule levels to standard severity:
        - 15-16: Critical (Ransomware, active root compromise, critical exploit)
        - 11-14: High (Multiple failed logins followed by success, privilege escalation, AV detection)
        - 7-10: Medium (Multiple failed logins, policy violation, configuration error)
        - 4-6: Low (Single failed login, network scan, service stopped)
        - 0-3: Informational (Routine daemon start, logoff, normal sudo command)
        """
        try:
            lvl = int(level)
        except (ValueError, TypeError):
            return SeverityLevel.MEDIUM

        if lvl >= 15:
            return SeverityLevel.CRITICAL
        elif lvl >= 11:
            return SeverityLevel.HIGH
        elif lvl >= 7:
            return SeverityLevel.MEDIUM
        elif lvl >= 4:
            return SeverityLevel.LOW
        else:
            return SeverityLevel.INFORMATIONAL

    def normalize(self, payload: Dict[str, Any]) -> NormalizedAlert:
        rule = payload.get("rule", {})
        rule_id = str(rule.get("id", "0"))
        rule_name = rule.get("description", "Unknown Wazuh Alert")
        rule_level = rule.get("level", 5)

        raw_severity = str(rule_level)
        normalized_severity = self.map_wazuh_level_to_severity(rule_level)

        timestamp = payload.get("timestamp") or utc_now()
        alert_id = str(payload.get("id") or f"wazuh-{uuid.uuid4().hex[:12]}")

        # Extract Agent / Host details
        agent = payload.get("agent", {})
        host_name = agent.get("name") or payload.get("hostname")
        host_ip = agent.get("ip")

        # Extract Network & User details from data block
        data = payload.get("data", {})
        src_ip = data.get("srcip") or payload.get("srcip")
        dst_ip = data.get("dstip") or host_ip
        src_user = data.get("srcuser")
        dst_user = data.get("dstuser") or data.get("user")
        user = dst_user or src_user

        src_port = None
        if "srcport" in data:
            try:
                src_port = int(data["srcport"])
            except (ValueError, TypeError):
                pass

        dst_port = None
        if "dstport" in data:
            try:
                dst_port = int(data["dstport"])
            except (ValueError, TypeError):
                pass

        # Extract Process details
        process_name = data.get("process") or payload.get("program_name") or data.get("command")
        process_pid = None
        if "pid" in data:
            try:
                process_pid = int(data["pid"])
            except (ValueError, TypeError):
                pass

        # Extract File Integrity / Hash details (Syscheck)
        syscheck = payload.get("syscheck", {})
        file_hash = (
            syscheck.get("sha256_after")
            or syscheck.get("md5_after")
            or data.get("sha256")
            or data.get("md5")
        )

        # Build Normalized Entities list
        entities: List[Entity] = []

        if src_ip:
            entities.append(Entity(
                type=EntityType.IP,
                value=str(src_ip),
                role=EntityRole.SOURCE,
                reputation="suspicious" if normalized_severity in [SeverityLevel.HIGH, SeverityLevel.CRITICAL] else "unknown",
                details={"port": src_port} if src_port else {},
            ))

        if dst_ip and dst_ip != src_ip:
            entities.append(Entity(
                type=EntityType.IP,
                value=str(dst_ip),
                role=EntityRole.DESTINATION,
                reputation="internal",
                details={"port": dst_port} if dst_port else {},
            ))

        if host_name:
            entities.append(Entity(
                type=EntityType.HOST,
                value=str(host_name),
                role=EntityRole.TARGET,
                reputation="internal",
                details={"agent_id": agent.get("id"), "agent_ip": host_ip},
            ))

        if user:
            entities.append(Entity(
                type=EntityType.USER,
                value=str(user),
                role=EntityRole.TARGET if dst_user else EntityRole.ACTOR,
                reputation="internal",
            ))

        if process_name:
            entities.append(Entity(
                type=EntityType.PROCESS,
                value=str(process_name),
                role=EntityRole.ACTOR,
                details={"pid": process_pid} if process_pid else {},
            ))

        if file_hash:
            entities.append(Entity(
                type=EntityType.FILE_HASH,
                value=str(file_hash),
                role=EntityRole.RELATED,
                details={"path": syscheck.get("path")},
            ))

        # MITRE ATT&CK Mapping
        mitre_data = rule.get("mitre", {})
        tactics = []
        techniques = []
        if isinstance(mitre_data, dict):
            tactics = mitre_data.get("tactic", [])
            if isinstance(tactics, str):
                tactics = [tactics]
            techniques = mitre_data.get("id", [])
            if isinstance(techniques, str):
                techniques = [techniques]
        mitre_attack = MitreAttackMetadata(
            tactics=tactics,
            techniques=techniques,
        ) if (tactics or techniques) else None

        # Compute deterministic fingerprint for deduplication
        fingerprint = self.compute_fingerprint(
            source=self.source_type.value,
            rule_id=rule_id,
            source_ip=src_ip,
            destination_ip=dst_ip,
            user=user,
            host=host_name,
            process_name=process_name,
            file_hash=file_hash,
        )

        return NormalizedAlert(
            alert_id=alert_id,
            fingerprint=fingerprint,
            source=self.source_type,
            rule_id=rule_id,
            rule_name=rule_name,
            rule_description=rule.get("description", "Wazuh Security Alert"),
            raw_severity=str(raw_severity),
            normalized_severity=normalized_severity,
            timestamp=str(timestamp),
            ingested_at=utc_now(),
            first_seen_at=str(timestamp),
            last_seen_at=str(timestamp),
            duplicate_count=1,
            source_ip=src_ip,
            destination_ip=dst_ip,
            source_port=src_port,
            destination_port=dst_port,
            user=user,
            host=host_name,
            process_name=process_name,
            process_pid=process_pid,
            file_hash=file_hash,
            entities=entities,
            mitre_attack=mitre_attack,
            raw_payload=payload,
        )
