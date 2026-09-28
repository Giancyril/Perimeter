"""
Phase 5: Evidence-Linked Incident Report Data Models.

Defines the structured report schema consumed by both the Markdown and PDF renderers.
All evidence traceability links are captured at build time; the report is immutable once built.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from backend.ingestion.models import SeverityLevel


class TimelineEvent(BaseModel):
    """A single timestamped evidence record in the incident timeline."""
    timestamp: datetime
    event_type: str          # "alert" | "log_entry" | "threat_intel_hit" | "lateral_movement"
    source: str              # "wazuh" | "siem" | "abuseipdb" | ...
    title: str
    description: str
    related_entities: List[str] = Field(default_factory=list)
    severity_impact: Optional[str] = None  # e.g. "escalated_to_high"
    raw_evidence_id: Optional[str] = None  # alert_id / log_id


class EntityTraceability(BaseModel):
    """Tracks which timeline events an entity appears in (evidence chain)."""
    entity_value: str
    entity_type: str   # ip / host / user / hash
    criticality: Optional[str] = None
    threat_verdict: Optional[str] = None
    abuse_score: Optional[int] = None
    timeline_event_indices: List[int] = Field(default_factory=list)


class SeverityAuditRecord(BaseModel):
    """Immutable record of how the final severity was determined."""
    deterministic_floor: str
    rule_override_reason: Optional[str]
    base_score: float
    asset_multiplier: float
    threat_intel_points: float
    mitre_multiplier: float
    lateral_movement_points: float
    raw_calculated_score: float
    llm_reasoning: Optional[str] = None
    floor_enforced: bool
    final_severity: str


class IncidentReport(BaseModel):
    """
    Structured, evidence-linked incident investigation report.
    Immutable snapshot generated at investigation completion.
    """
    report_id: str
    incident_id: str
    generated_at: datetime
    incident_title: str
    final_severity: SeverityLevel
    deterministic_floor: SeverityLevel
    status: str

    # Structured evidence chain
    timeline: List[TimelineEvent] = Field(default_factory=list)
    entities: List[EntityTraceability] = Field(default_factory=list)

    # Scoring audit
    severity_audit: SeverityAuditRecord

    # Investigation findings
    mitre_tactics: List[str] = Field(default_factory=list)
    mitre_techniques: List[str] = Field(default_factory=list)
    attack_chain_span: int = 0
    lateral_movement_paths: List[str] = Field(default_factory=list)
    adversarial_injection_detected: bool = False
    adversarial_injection_reason: Optional[str] = None

    # Recommended actions
    recommended_actions: List[str] = Field(default_factory=list)

    # Executive narrative (synthesized by LLM node)
    executive_summary: str = ""
