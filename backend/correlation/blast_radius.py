"""
Entity Blast Radius & Crown-Jewel Risk Assessor.
Calculates enterprise operational impact, classifies assets by security tiers (Tier 0 to Tier 3),
and quantifies potential lateral spread and crown-jewel compromise risks.
"""
from typing import Dict, List, Set, Optional, Any
from enum import Enum
from backend.ingestion.models import Entity, EntityType

class AssetTier(str, Enum):
    TIER_0 = "Tier 0 (Identity & Root of Trust)"
    TIER_1 = "Tier 1 (Core Data & Production DB)"
    TIER_2 = "Tier 2 (Application & API Services)"
    TIER_3 = "Tier 3 (Endpoints & Dev/Staging)"

TIER_KEYWORDS: Dict[AssetTier, List[str]] = {
    AssetTier.TIER_0: ["dc", "domain", "ad-", "kdc", "vault", "iam", "root", "pki", "auth", "sso", "okta"],
    AssetTier.TIER_1: ["db", "database", "sql", "postgres", "mongo", "oracle", "pci", "payment", "ledger", "prod-master"],
    AssetTier.TIER_2: ["app", "api", "gateway", "service", "web", "ingress", "backend", "cluster", "worker"],
    AssetTier.TIER_3: ["dev", "test", "stage", "sandbox", "laptop", "desktop", "ws-", "jumpbox", "client"],
}

TIER_WEIGHTS: Dict[AssetTier, int] = {
    AssetTier.TIER_0: 40,
    AssetTier.TIER_1: 30,
    AssetTier.TIER_2: 15,
    AssetTier.TIER_3: 5,
}

class BlastRadiusAssessor:
    """Calculates blast radius score and identifies critical asset exposure."""

    @staticmethod
    def classify_asset(entity_value: str) -> AssetTier:
        """Classifies a hostname or asset name into a security architecture tier."""
        val = entity_value.lower().strip()
        for tier, keywords in TIER_KEYWORDS.items():
            if any(kw in val for kw in keywords):
                return tier
        return AssetTier.TIER_2  # Default to Tier 2 for unknown internal assets

    def assess_incident(self, entities: List[Entity]) -> Dict[str, Any]:
        """
        Assesses blast radius across all correlated entities.
        Returns score (0-100), highest impacted tier, count of distinct endpoints, and risk flags.
        """
        hosts: Set[str] = set()
        users: Set[str] = set()
        internal_ips: Set[str] = set()
        external_ips: Set[str] = set()

        for ent in entities:
            val = ent.value.strip()
            if ent.type == EntityType.HOST:
                hosts.add(val)
            elif ent.type == EntityType.USER:
                users.add(val)
            elif ent.type == EntityType.IP:
                # Classify as internal if RFC1918 or starts with 10./192.168./172.
                import ipaddress
                try:
                    ip_obj = ipaddress.ip_address(val)
                    if ip_obj.is_private:
                        internal_ips.add(val)
                    else:
                        external_ips.add(val)
                except Exception:
                    external_ips.add(val)

        # Evaluate highest tier among hosts
        highest_tier = AssetTier.TIER_3
        highest_weight = 0
        tiered_hosts: Dict[str, str] = {}

        for h in hosts:
            tier = self.classify_asset(h)
            tiered_hosts[h] = tier.value
            weight = TIER_WEIGHTS[tier]
            if weight > highest_weight:
                highest_weight = weight
                highest_tier = tier

        # Base score from highest asset tier
        blast_score = highest_weight

        # Scale by number of distinct internal hosts and IPs (lateral spread)
        lateral_entities = len(hosts) + len(internal_ips)
        if lateral_entities > 1:
            blast_score += min(35, (lateral_entities - 1) * 10)

        # Privileged accounts impact
        for u in users:
            if any(p in u.lower() for p in ["root", "admin", "administrator", "system", "service"]):
                blast_score += 15
                break

        blast_score = max(0, min(100, blast_score))

        is_crown_jewel = highest_tier in (AssetTier.TIER_0, AssetTier.TIER_1)
        is_wide_spread = len(hosts) >= 3 or len(internal_ips) >= 4

        return {
            "blast_radius_score": blast_score,
            "highest_impacted_tier": highest_tier.value,
            "is_crown_jewel_compromise": is_crown_jewel,
            "is_wide_spread": is_wide_spread,
            "impacted_hosts": list(hosts),
            "impacted_users": list(users),
            "internal_ip_count": len(internal_ips),
            "external_ip_count": len(external_ips),
            "tiered_assets": tiered_hosts,
        }
