"""
TTP-to-Threat-Actor Attribution Profiler for Investigation Agent.

Profiles observed MITRE ATT&CK techniques, tool signatures, and attack patterns
against known Advanced Persistent Threat (APT) groups and cybercrime syndicates.
Computes multi-dimensional similarity scores and attribution confidence levels.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set


class ActorMotivation(str, Enum):
    ESPIONAGE = "ESPIONAGE"
    FINANCIAL_GAIN = "FINANCIAL_GAIN"
    SABOTAGE_DESTRUCTION = "SABOTAGE_DESTRUCTION"
    EXTORTION_RANSOM = "EXTORTION_RANSOM"
    PERSISTENT_ACCESS = "PERSISTENT_ACCESS"


@dataclass
class ThreatActorProfile:
    name: str
    aliases: List[str]
    origin: str
    motivation: ActorMotivation
    primary_techniques: List[str]
    signature_tools: List[str]
    targeted_sectors: List[str]
    base_weight: float = 1.0

    def matches_identifier(self, identifier: str) -> bool:
        norm = identifier.lower().strip()
        if self.name.lower() == norm:
            return True
        return any(a.lower() == norm for a in self.aliases)


@dataclass
class AttributionMatch:
    actor_name: str
    aliases: List[str]
    motivation: str
    similarity_score: float  # 0.0 to 1.0
    confidence_level: str  # LOW, MEDIUM, HIGH, VERY_HIGH
    matched_techniques: List[str] = field(default_factory=list)
    matched_tools: List[str] = field(default_factory=list)
    assessment_summary: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "actor_name": self.actor_name,
            "aliases": self.aliases,
            "motivation": self.motivation,
            "similarity_score": round(self.similarity_score, 3),
            "confidence_level": self.confidence_level,
            "matched_techniques": self.matched_techniques,
            "matched_tools": self.matched_tools,
            "assessment_summary": self.assessment_summary,
        }


class AttributionProfiler:
    """Profiles and attributes observed TTPs against established APT groups."""

    def __init__(self) -> None:
        self._profiles = self._init_profiles()

    def _init_profiles(self) -> List[ThreatActorProfile]:
        return [
            ThreatActorProfile(
                name="APT28",
                aliases=["Fancy Bear", "STRONTIUM", "Sednit", "Sofacy", "Pawn Storm"],
                origin="Russian Federation (GRU)",
                motivation=ActorMotivation.ESPIONAGE,
                primary_techniques=["T1566.001", "T1059.001", "T1003", "T1071.001", "T1021.002", "T1070"],
                signature_tools=["Mimikatz", "X-Agent", "Chopstick", "Zebrocy", "Sofacy"],
                targeted_sectors=["Government", "Defense", "Energy", "Aerospace"],
                base_weight=1.1,
            ),
            ThreatActorProfile(
                name="APT29",
                aliases=["Cozy Bear", "NOBELIUM", "Midnight Blizzard", "The Dukes"],
                origin="Russian Federation (SVR)",
                motivation=ActorMotivation.ESPIONAGE,
                primary_techniques=["T1195.002", "T1078", "T1584", "T1071.001", "T1053", "T1027"],
                signature_tools=["Cobalt Strike", "WellMess", "Adversary Infrastructure", "GoldFinder"],
                targeted_sectors=["Government", "Technology", "Think Tanks", "Cloud Providers"],
                base_weight=1.1,
            ),
            ThreatActorProfile(
                name="Lazarus Group",
                aliases=["HIDDEN COBRA", "Zinc", "Labyrinth Chollima", "Guardians of Peace"],
                origin="Democratic People's Republic of Korea",
                motivation=ActorMotivation.FINANCIAL_GAIN,
                primary_techniques=["T1059.003", "T1486", "T1003", "T1021", "T1048", "T1566.002"],
                signature_tools=["Fallchill", "Brambul", "Destover", "Manuscrypt", "FASTCash"],
                targeted_sectors=["Finance", "Cryptocurrency", "Defense", "Media"],
                base_weight=1.05,
            ),
            ThreatActorProfile(
                name="FIN7",
                aliases=["Carbanak", "Sang炭ine Tempest", "ELBRUS"],
                origin="Eastern Europe / Cybercrime",
                motivation=ActorMotivation.FINANCIAL_GAIN,
                primary_techniques=["T1566.002", "T1059.005", "T1021.001", "T1055", "T1003", "T1041"],
                signature_tools=["Carbanak", "Griffon", "POWERPLANT", "Diceloader"],
                targeted_sectors=["Retail", "Hospitality", "Restaurant", "Banking"],
                base_weight=1.0,
            ),
            ThreatActorProfile(
                name="Sandworm",
                aliases=["Voodoo Bear", "BlackEnergy", "TeleBots", "Seashell Blizzard"],
                origin="Russian Federation (GRU Main Center)",
                motivation=ActorMotivation.SABOTAGE_DESTRUCTION,
                primary_techniques=["T1498", "T1485", "T1072", "T1562.001", "T1486", "T1021.002"],
                signature_tools=["BlackEnergy", "NotPetya", "Industroyer", "HermeticWiper", "CaddyWiper"],
                targeted_sectors=["Energy", "Critical Infrastructure", "Government", "Logistics"],
                base_weight=1.15,
            ),
            ThreatActorProfile(
                name="Volt Typhoon",
                aliases=["Bronze Silhouette", "Vanguard Panda", "Insidious Taurus"],
                origin="People's Republic of China",
                motivation=ActorMotivation.PERSISTENT_ACCESS,
                primary_techniques=["T1078", "T1021.002", "T1018", "T1033", "T1049", "T1562"],
                signature_tools=["wmic", "netsh", "ntdsutil", "powershell", "living-off-the-land"],
                targeted_sectors=["Critical Infrastructure", "Telecommunications", "Maritime", "Water"],
                base_weight=1.1,
            ),
            ThreatActorProfile(
                name="LockBit",
                aliases=["LockBit 3.0", "LockBit Black", "Bitwise Spider"],
                origin="Transnational Cybercrime Syndicate",
                motivation=ActorMotivation.EXTORTION_RANSOM,
                primary_techniques=["T1486", "T1490", "T1003", "T1021.001", "T1048", "T1562.001"],
                signature_tools=["StealBit", "LockBit Black Builder", "PsExec", "Mimikatz"],
                targeted_sectors=["Healthcare", "Manufacturing", "Legal", "Education", "Finance"],
                base_weight=1.0,
            ),
        ]

    def get_actor(self, identifier: str) -> Optional[ThreatActorProfile]:
        """Finds a threat actor profile by canonical name or alias."""
        for p in self._profiles:
            if p.matches_identifier(identifier):
                return p
        return None

    def profile(
        self,
        techniques: List[str],
        tools: Optional[List[str]] = None,
        alert_text: Optional[str] = None,
    ) -> List[AttributionMatch]:
        """Calculates attribution similarity across all known profiles."""
        if not techniques and not tools and not alert_text:
            return []

        tech_set = set(t.strip().upper() for t in techniques)
        tool_set = set(t.strip().lower() for t in (tools or []))
        text_lower = (alert_text or "").lower()

        matches: List[AttributionMatch] = []

        for p in self._profiles:
            # Technique matching (Jaccard + subtechnique prefix match)
            p_tech_set = set(t.upper() for t in p.primary_techniques)
            matched_techs = []
            for obs in tech_set:
                for target in p_tech_set:
                    if obs == target or obs.startswith(target) or target.startswith(obs):
                        matched_techs.append(target)
            matched_techs = list(dict.fromkeys(matched_techs))  # deduplicate preserving order

            # Tool matching
            matched_tools = []
            for tool in p.signature_tools:
                tool_low = tool.lower()
                if tool_low in tool_set or tool_low in text_lower:
                    matched_tools.append(tool)

            # Compute similarity score
            tech_score = (len(matched_techs) / max(len(p.primary_techniques), 1)) * 0.60
            tool_score = (len(matched_tools) / max(len(p.signature_tools), 1)) * 0.35
            overlap_bonus = 0.05 if (matched_techs and matched_tools) else 0.0

            raw_score = (tech_score + tool_score + overlap_bonus) * p.base_weight
            final_score = min(1.0, max(0.0, raw_score))

            if final_score < 0.15:
                continue

            if final_score >= 0.75:
                confidence = "VERY_HIGH"
            elif final_score >= 0.50:
                confidence = "HIGH"
            elif final_score >= 0.30:
                confidence = "MEDIUM"
            else:
                confidence = "LOW"

            summary = (
                f"Attribution score {round(final_score, 2)} ({confidence}) for {p.name} ({', '.join(p.aliases[:2])}). "
                f"Matched {len(matched_techs)} signature techniques and {len(matched_tools)} characteristic tools. "
                f"Origin: {p.origin}, Primary Motivation: {p.motivation.value}."
            )

            matches.append(
                AttributionMatch(
                    actor_name=p.name,
                    aliases=p.aliases,
                    motivation=p.motivation.value,
                    similarity_score=final_score,
                    confidence_level=confidence,
                    matched_techniques=matched_techs,
                    matched_tools=matched_tools,
                    assessment_summary=summary,
                )
            )

        matches.sort(key=lambda m: m.similarity_score, reverse=True)
        return matches
