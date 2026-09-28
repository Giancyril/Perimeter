"""
Correlated Incident Domain Models.
Defines schemas for security incidents aggregated from multi-alert entity correlations and MITRE ATT&CK stages.
"""
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
from enum import Enum
from pydantic import BaseModel, Field
from backend.ingestion.models import NormalizedAlert, Entity, SeverityLevel, utc_now

class IncidentStatus(str, Enum):
    NEW = "new"
    ACTIVE = "active"
    INVESTIGATING = "investigating"
    PENDING_APPROVAL = "pending_approval"
    RESOLVED = "resolved"
    CLOSED = "closed"

class CorrelatedIncident(BaseModel):
    incident_id: str = Field(..., description="Unique incident ID (e.g. INC-2026-001)")
    title: str = Field(..., description="Deterministic, explainable incident title")
    status: IncidentStatus = IncidentStatus.NEW
    created_at: str = Field(default_factory=utc_now)
    updated_at: str = Field(default_factory=utc_now)
    window_start: str
    window_end: str
    
    # Aggregated alerts
    alert_count: int = 1
    alert_ids: List[str] = Field(default_factory=list)
    alerts: List[NormalizedAlert] = Field(default_factory=list)

    # Correlated entities
    entities: List[Entity] = Field(default_factory=list)
    primary_entity: Optional[str] = None

    # MITRE ATT&CK mapping
    tactics: List[str] = Field(default_factory=list)
    techniques: List[str] = Field(default_factory=list)
    attack_chain_span: int = Field(1, description="Number of distinct stages spanned in the MITRE kill-chain")

    # Explainability
    correlation_reasons: List[str] = Field(default_factory=list)

    # Initial deterministic severity floor
    deterministic_score: int = Field(..., ge=0, le=100)
    deterministic_floor: SeverityLevel
    severity: SeverityLevel
    
    owner: str = "Unassigned"
