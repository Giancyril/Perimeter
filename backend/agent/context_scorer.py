"""
Contextual Evidence Confidence Scorer for Investigation Agent.

Evaluates evidence trustworthiness and investigative weight by factoring in:
- Asset criticality (tier 1 domain controller vs guest sandbox)
- Account privilege level (Domain Admin / SYSTEM vs standard user)
- Threat intelligence reputation (AbuseIPDB score, VirusTotal malicious detections)
- Multi-source corroboration and temporal recency decay.
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


class ConfidenceTier(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


class AssetTier(str, Enum):
    TIER_0_CROWN_JEWEL = "TIER_0_CROWN_JEWEL"  # Domain controllers, PKI, Vaults
    TIER_1_ENTERPRISE = "TIER_1_ENTERPRISE"      # Production servers, databases
    TIER_2_WORKSTATION = "TIER_2_WORKSTATION"    # Standard corporate endpoints
    TIER_3_SANDBOX = "TIER_3_SANDBOX"            # Dev/test environments, guest subnets


@dataclass
class ScoredEvidence:
    evidence_id: str
    context_score: float  # 0.0 to 100.0
    tier: ConfidenceTier
    factors: Dict[str, float] = field(default_factory=dict)
    summary: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "context_score": round(self.context_score, 2),
            "tier": self.tier.value,
            "factors": {k: round(v, 2) for k, v in self.factors.items()},
            "summary": self.summary,
        }


class ContextScorer:
    """Computes multi-factored contextual confidence scores for security evidence."""

    ASSET_TIER_WEIGHTS = {
        AssetTier.TIER_0_CROWN_JEWEL: 1.0,
        AssetTier.TIER_1_ENTERPRISE: 0.8,
        AssetTier.TIER_2_WORKSTATION: 0.5,
        AssetTier.TIER_3_SANDBOX: 0.2,
    }

    PRIVILEGE_WEIGHTS = {
        "SYSTEM": 1.0,
        "ROOT": 1.0,
        "DOMAIN ADMIN": 0.95,
        "ADMINISTRATOR": 0.90,
        "SERVICE_ACCOUNT": 0.70,
        "USER": 0.40,
        "GUEST": 0.20,
    }

    def score(
        self,
        evidence_id: str,
        asset_tier: AssetTier = AssetTier.TIER_2_WORKSTATION,
        privilege_level: str = "USER",
        abuse_confidence_score: Optional[int] = None,  # 0-100 from AbuseIPDB
        vt_positives: Optional[int] = None,          # VirusTotal detection count
        vt_total_engines: int = 70,
        corroborating_source_count: int = 1,
        age_in_hours: float = 0.0,
    ) -> ScoredEvidence:
        """Calculates normalized 0-100 context score from contextual observables."""
        # 1. Asset Impact Factor (weight: 25%)
        asset_factor = self.ASSET_TIER_WEIGHTS.get(asset_tier, 0.5) * 100.0

        # 2. Privilege Level Factor (weight: 20%)
        norm_priv = privilege_level.upper().strip()
        priv_weight = 0.40
        for k, v in self.PRIVILEGE_WEIGHTS.items():
            if k in norm_priv:
                priv_weight = max(priv_weight, v)
        privilege_factor = priv_weight * 100.0

        # 3. External Threat Intel Factor (weight: 30%)
        intel_scores: List[float] = []
        if abuse_confidence_score is not None:
            intel_scores.append(float(abuse_confidence_score))
        if vt_positives is not None and vt_total_engines > 0:
            vt_ratio = min(1.0, vt_positives / max(vt_total_engines, 1))
            intel_scores.append(vt_ratio * 100.0)

        threat_intel_factor = (
            sum(intel_scores) / len(intel_scores) if intel_scores else 40.0
        )

        # 4. Multi-Source Corroboration Factor (weight: 15%)
        # 1 source = 40, 2 sources = 70, 3+ sources = 100
        corroboration_factor = min(100.0, 40.0 + (corroborating_source_count - 1) * 30.0)

        # 5. Temporal Decay Factor (weight: 10% deduction)
        # Half-life of 48 hours for evidence freshness
        decay_factor = math.exp(-0.0144 * max(0.0, age_in_hours))  # ln(2)/48 ~ 0.0144
        recency_factor = min(100.0, max(20.0, decay_factor * 100.0))

        # Weighted composite score
        composite = (
            0.25 * asset_factor
            + 0.20 * privilege_factor
            + 0.30 * threat_intel_factor
            + 0.15 * corroboration_factor
            + 0.10 * recency_factor
        )
        final_score = min(100.0, max(0.0, composite))

        # Determine Tier
        if final_score >= 80.0:
            tier = ConfidenceTier.CRITICAL
        elif final_score >= 65.0:
            tier = ConfidenceTier.HIGH
        elif final_score >= 45.0:
            tier = ConfidenceTier.MEDIUM
        elif final_score >= 25.0:
            tier = ConfidenceTier.LOW
        else:
            tier = ConfidenceTier.INFORMATIONAL

        factors = {
            "asset_criticality": asset_factor,
            "privilege_level": privilege_factor,
            "threat_intelligence": threat_intel_factor,
            "multi_source_corroboration": corroboration_factor,
            "temporal_recency": recency_factor,
        }

        summary = (
            f"Evidence scored {round(final_score, 1)}/100 [{tier.value}]. "
            f"Asset: {asset_tier.value} (factor {round(asset_factor, 1)}), "
            f"Privilege: {norm_priv} (factor {round(privilege_factor, 1)}), "
            f"Intel: {round(threat_intel_factor, 1)}, Corroboration: {corroborating_source_count} sources."
        )

        return ScoredEvidence(
            evidence_id=evidence_id,
            context_score=final_score,
            tier=tier,
            factors=factors,
            summary=summary,
        )
