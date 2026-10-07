"""
Threat Actor Capability & Sophistication Weighting Engine for Severity Engine.

Augments deterministic and hybrid severity scores based on attributed threat
actor operational capabilities, sophistication tiers (Nation-State vs Commodity),
and observed weaponization (0-day exploits, EDR wipers, supply chain pivots).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class SophisticationTier(str, Enum):
    TIER_1_NATION_STATE = "TIER_1_NATION_STATE"          # Advanced persistent, strategic espionage/sabotage
    TIER_2_ORGANIZED_SYNDICATE = "TIER_2_ORGANIZED_SYNDICATE"  # Ransomware cartels, high-dollar financial crime
    TIER_3_OPPORTUNISTIC_CRIME = "TIER_3_OPPORTUNISTIC_CRIME"  # Access brokers, carding rings, botnet operators
    TIER_4_COMMODITY = "TIER_4_COMMODITY"                # Off-the-shelf malware, script-driven commodity attacks


@dataclass
class ActorCapabilitySpec:
    tier: SophisticationTier
    base_multiplier: float
    has_0day_exploit: bool = False
    has_wiper_capability: bool = False
    has_edr_evasion: bool = False


@dataclass
class ActorWeightedSeverity:
    base_score: float
    final_score: float
    actor_name: str
    tier: SophisticationTier
    capability_multiplier: float
    bonus_points: float
    justification: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "base_score": round(self.base_score, 2),
            "final_score": round(self.final_score, 2),
            "actor_name": self.actor_name,
            "tier": self.tier.value,
            "capability_multiplier": round(self.capability_multiplier, 3),
            "bonus_points": round(self.bonus_points, 2),
            "justification": self.justification,
        }


class ThreatActorWeightingEngine:
    """Calculates risk multipliers driven by threat actor sophistication and capabilities."""

    KNOWN_ACTORS: Dict[str, ActorCapabilitySpec] = {
        "APT28": ActorCapabilitySpec(SophisticationTier.TIER_1_NATION_STATE, 1.45, has_0day_exploit=True, has_edr_evasion=True),
        "APT29": ActorCapabilitySpec(SophisticationTier.TIER_1_NATION_STATE, 1.50, has_0day_exploit=True, has_edr_evasion=True),
        "SANDWORM": ActorCapabilitySpec(SophisticationTier.TIER_1_NATION_STATE, 1.55, has_wiper_capability=True, has_0day_exploit=True),
        "VOLT TYPHOON": ActorCapabilitySpec(SophisticationTier.TIER_1_NATION_STATE, 1.40, has_edr_evasion=True),
        "LAZARUS GROUP": ActorCapabilitySpec(SophisticationTier.TIER_2_ORGANIZED_SYNDICATE, 1.35, has_wiper_capability=True),
        "LOCKBIT": ActorCapabilitySpec(SophisticationTier.TIER_2_ORGANIZED_SYNDICATE, 1.30, has_wiper_capability=True, has_edr_evasion=True),
        "FIN7": ActorCapabilitySpec(SophisticationTier.TIER_2_ORGANIZED_SYNDICATE, 1.25),
    }

    def weight(
        self,
        base_score: float,
        actor_name: Optional[str] = None,
        attribution_confidence: float = 0.5,  # 0.0 to 1.0
        observed_0day: bool = False,
        observed_wiper: bool = False,
        observed_edr_tampering: bool = False,
    ) -> ActorWeightedSeverity:
        """Applies actor capabilities to elevate base severity."""
        norm_name = (actor_name or "UNKNOWN").upper().strip()
        spec = self.KNOWN_ACTORS.get(
            norm_name,
            ActorCapabilitySpec(SophisticationTier.TIER_4_COMMODITY, 1.0)
        )

        # Scale multiplier by attribution confidence
        effective_multiplier = 1.0 + ((spec.base_multiplier - 1.0) * attribution_confidence)

        # Capability bonus points
        bonus = 0.0
        details = []

        if observed_0day or spec.has_0day_exploit:
            bonus += 15.0
            details.append("Zero-day exploit weaponization (+15 pts)")

        if observed_wiper or spec.has_wiper_capability:
            bonus += 20.0
            details.append("Destructive wiper / encryption payload (+20 pts)")

        if observed_edr_tampering or spec.has_edr_evasion:
            bonus += 10.0
            details.append("Defense evasion / EDR neutralization (+10 pts)")

        raw_final = (base_score * effective_multiplier) + bonus
        clamped = min(100.0, max(0.0, raw_final))

        justification = (
            f"Attributed Actor '{norm_name}' [{spec.tier.value}]. "
            f"Multiplier: {round(effective_multiplier, 2)}x (Confidence: {round(attribution_confidence, 2)}). "
            f"Bonus points: +{bonus} ({', '.join(details) if details else 'None'})."
        )

        return ActorWeightedSeverity(
            base_score=base_score,
            final_score=clamped,
            actor_name=norm_name,
            tier=spec.tier,
            capability_multiplier=effective_multiplier,
            bonus_points=bonus,
            justification=justification,
        )
