"""
Normalized Alert Schema (OCSF / ECS aligned).
Defines standard schemas for all ingested security alerts across multiple SIEM sources.
"""
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
from enum import Enum
from pydantic import BaseModel, Field

def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()

class SeverityLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"

class AlertSourceType(str, Enum):
    WAZUH = "wazuh"
    SPLUNK = "splunk"
    ELASTIC = "elastic"
    SENTINEL = "sentinel"
    SYSLOG = "syslog"
    GENERIC = "generic"

class EntityType(str, Enum):
    IP = "ip"
    USER = "user"
    HOST = "host"
    PROCESS = "process"
    FILE_HASH = "file_hash"
    DOMAIN = "domain"
    URL = "url"

class EntityRole(str, Enum):
    SOURCE = "source"
    DESTINATION = "destination"
    ACTOR = "actor"
    TARGET = "target"
    RELATED = "related"

class Entity(BaseModel):
    type: EntityType
    value: str
    role: EntityRole = EntityRole.RELATED
    reputation: Optional[str] = None  # malicious, suspicious, clean, internal, unknown
    details: Dict[str, Any] = Field(default_factory=dict)

class MitreAttackMetadata(BaseModel):
    tactics: List[str] = Field(default_factory=list)
    techniques: List[str] = Field(default_factory=list)
    technique_names: List[str] = Field(default_factory=list)

class NormalizedAlert(BaseModel):
    alert_id: str = Field(..., description="Unique alert identifier")
    fingerprint: str = Field(..., description="Deterministic SHA-256 fingerprint for deduplication")
    source: AlertSourceType
    rule_id: str
    rule_name: str
    rule_description: str
    raw_severity: str
    normalized_severity: SeverityLevel
    timestamp: str
    ingested_at: str = Field(default_factory=utc_now)
    first_seen_at: str = Field(default_factory=utc_now)
    last_seen_at: str = Field(default_factory=utc_now)
    duplicate_count: int = 1

    # OCSF v1.1.0 Classification
    ocsf_class_uid: Optional[int] = None
    ocsf_category_uid: Optional[int] = None

    # Key entity shortcuts for fast filtering
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    user: Optional[str] = None
    host: Optional[str] = None
    process_name: Optional[str] = None
    process_pid: Optional[int] = None
    file_hash: Optional[str] = None

    # Full structured entity list
    entities: List[Entity] = Field(default_factory=list)

    # MITRE ATT&CK Mapping
    mitre_attack: Optional[MitreAttackMetadata] = None

    # Raw payload retained for auditability and forensic trace
    raw_payload: Dict[str, Any] = Field(..., description="Original intact raw alert payload")

class IngestionResult(BaseModel):
    status: str = "received"
    alert_id: str
    fingerprint: str
    source: AlertSourceType
    was_duplicate: bool
    duplicate_count: int
    normalized_severity: SeverityLevel
    incident_id: Optional[str] = Field(None, description="Incident ID the alert was correlated into (None for duplicates)")
    summary: str

