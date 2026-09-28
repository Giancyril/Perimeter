"""
Phase 4: Hybrid Severity Scoring Models.

Defines auditable scoring data models for deterministic calculation,
asset weighting, threat intel enrichment, kill-chain multipliers,
and LLM reasoning with strict floor enforcement.
"""
from enum import Enum
from typing import Dict, Any, Optional, List
from pydantic import BaseModel, Field
from backend.ingestion.models import SeverityLevel


class AssetCriticalityTier(str, Enum):
    TIER_0_CRITICAL = "critical"   # Domain Controllers, Root CAs, Key Vaults, Payment Processors
    TIER_1_HIGH = "high"           # Production databases, Kubernetes control plane, Core APIs
    TIER_2_MEDIUM = "medium"       # Internal web apps, jump hosts, developer staging
    TIER_3_LOW = "low"             # End-user workstations, test labs, ephemeral environments


class ScoringBreakdown(BaseModel):
    """Auditable mathematical breakdown of the deterministic severity calculation."""
    base_score: float = Field(..., description="Base score from alert severities and volume (0-40)")
    asset_multiplier: float = Field(..., description="Multiplier based on asset criticality tier (0.8x - 2.0x)")
    threat_intel_points: float = Field(..., description="Points added from external threat intel IOCs (0-25)")
    mitre_multiplier: float = Field(..., description="Multiplier based on ATT&CK kill-chain progression (1.0x - 1.6x)")
    lateral_movement_points: float = Field(..., description="Points added for multi-host east-west movement (0 or 20)")
    adversarial_injection_points: float = Field(..., description="Points added for detected prompt injection attempts (0 or 25)")
    raw_calculated_score: float = Field(..., description="Final composite raw score before clamping (0-100+)")
    deterministic_floor: SeverityLevel = Field(..., description="The non-downgradable severity floor")
    rule_floor_override: Optional[str] = Field(None, description="Rule-based minimum override if triggered")


class LLMReasoningResult(BaseModel):
    """Parsed output of LLM qualitative analysis and proposed severity."""
    suggested_severity: SeverityLevel
    confidence: float = Field(0.8, ge=0.0, le=1.0)
    justification: str = ""
    additional_risk_points: float = 0.0
    model_used: str = "gpt-4o"


class FinalSeverityResult(BaseModel):
    """
    Combined hybrid severity result.
    Enforces the core security invariant: final_severity >= deterministic_floor.
    """
    incident_id: str
    deterministic_floor: SeverityLevel
    raw_score: int
    final_score: int
    final_severity: SeverityLevel
    floor_enforced: bool = Field(
        False,
        description="True if LLM attempted to downgrade below the deterministic floor and was blocked"
    )
    audit_note: Optional[str] = None
    breakdown: ScoringBreakdown
    llm_reasoning: Optional[LLMReasoningResult] = None
