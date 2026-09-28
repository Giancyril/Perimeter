"""
Asset Context & Criticality Resolver Tool.

Provides enterprise context for hosts, IP addresses, and user accounts.
Evaluates the business impact and asset tier (Domain Controller, Production DB,
Payment Gateway vs. standard workstation) which feeds directly into deterministic
severity floor calculation and escalation routing.
"""
from enum import Enum
from typing import Dict, Any, Optional
from pydantic import BaseModel, Field


class AssetCriticalityTier(str, Enum):
    TIER_0_CRITICAL = "critical"   # Domain Controllers, Root CAs, Key Vaults, Payment Processors
    TIER_1_HIGH = "high"           # Production databases, Kubernetes control plane, Core APIs
    TIER_2_MEDIUM = "medium"       # Internal web apps, jump hosts, developer staging
    TIER_3_LOW = "low"             # End-user workstations, test labs, ephemeral environments


class AssetContext(BaseModel):
    identifier: str
    asset_type: str = "host"  # "host", "user", "ip"
    criticality: AssetCriticalityTier = AssetCriticalityTier.TIER_2_MEDIUM
    criticality_score: float = 0.5  # 0.0 to 1.0 multiplier
    role_description: str = "Standard Internal System"
    environment: str = "production"
    owner: str = "IT Infrastructure"
    data_classification: str = "Confidential"
    is_internet_facing: bool = False
    details: Dict[str, Any] = Field(default_factory=dict)


class AssetContextResolver:
    """Resolves enterprise asset context based on inventory rules and hostname/IP heuristics."""

    def __init__(self):
        self._inventory: Dict[str, AssetContext] = {}
        self._register_default_eval_assets()

    def _register_default_eval_assets(self) -> None:
        """Seeds known evaluation assets and corporate infrastructure."""
        defaults = [
            AssetContext(
                identifier="dc-01.corp.internal",
                criticality=AssetCriticalityTier.TIER_0_CRITICAL,
                criticality_score=1.0,
                role_description="Primary Active Directory Domain Controller",
                environment="production",
                owner="Identity & Access Management",
                data_classification="Restricted",
            ),
            AssetContext(
                identifier="edge-gateway-nginx",
                criticality=AssetCriticalityTier.TIER_1_HIGH,
                criticality_score=0.85,
                role_description="Public Edge Ingress Reverse Proxy",
                environment="production",
                owner="Edge Network Team",
                is_internet_facing=True,
                data_classification="Confidential",
            ),
            AssetContext(
                identifier="prod-db-cluster",
                criticality=AssetCriticalityTier.TIER_0_CRITICAL,
                criticality_score=1.0,
                role_description="Customer Core PostgreSQL Database",
                environment="production",
                owner="Database Reliability Engineering",
                data_classification="Restricted",
            ),
            AssetContext(
                identifier="payment-vault-01",
                criticality=AssetCriticalityTier.TIER_0_CRITICAL,
                criticality_score=1.0,
                role_description="PCI-DSS Cardholder Data Environment Vault",
                environment="production",
                owner="Payment Security Team",
                data_classification="Restricted",
            ),
        ]
        for asset in defaults:
            self._inventory[asset.identifier.lower()] = asset

    def register_asset(self, asset: AssetContext) -> None:
        """Allows dynamic registration of enterprise inventory."""
        self._inventory[asset.identifier.lower()] = asset

    def resolve(self, identifier: Optional[str]) -> AssetContext:
        """
        Resolves asset context for a given host, IP, or username.
        If not in inventory, applies deterministic naming heuristics.
        """
        if not identifier:
            return AssetContext(
                identifier="unknown",
                criticality=AssetCriticalityTier.TIER_3_LOW,
                criticality_score=0.2,
                role_description="Unidentified Network Entity",
            )

        ident = str(identifier).strip().lower()
        if ident in self._inventory:
            return self._inventory[ident]

        # Heuristic classification based on hostname or role patterns
        if any(token in ident for token in ["dc", "domain-ctrl", "activedir", "ad-", "vault", "pci", "payment", "root-ca"]):
            return AssetContext(
                identifier=identifier,
                criticality=AssetCriticalityTier.TIER_0_CRITICAL,
                criticality_score=1.0,
                role_description="Critical Infrastructure System (Domain/Security Core)",
                environment="production",
                data_classification="Restricted",
            )
        elif any(token in ident for token in ["prod", "db-", "database", "postgres", "sql", "k8s-master", "control-plane"]):
            return AssetContext(
                identifier=identifier,
                criticality=AssetCriticalityTier.TIER_1_HIGH,
                criticality_score=0.85,
                role_description="Production Data or Cluster Control Host",
                environment="production",
                data_classification="Confidential",
            )
        elif any(token in ident for token in ["gateway", "edge", "proxy", "bastion", "jump", "ingress"]):
            return AssetContext(
                identifier=identifier,
                criticality=AssetCriticalityTier.TIER_1_HIGH,
                criticality_score=0.75,
                role_description="Perimeter Gateway or Administrative Jump Host",
                is_internet_facing=True,
            )
        elif any(token in ident for token in ["stage", "staging", "dev", "test", "qa", "lab"]):
            return AssetContext(
                identifier=identifier,
                criticality=AssetCriticalityTier.TIER_3_LOW,
                criticality_score=0.2,
                role_description="Non-Production / Development System",
                environment="development",
            )
        elif any(token in ident for token in ["ws-", "laptop", "desktop", "macbook", "workstation"]):
            return AssetContext(
                identifier=identifier,
                criticality=AssetCriticalityTier.TIER_2_MEDIUM,
                criticality_score=0.4,
                role_description="Corporate End-User Workstation",
                environment="corporate_workstations",
            )

        # Default fallback
        return AssetContext(
            identifier=identifier,
            criticality=AssetCriticalityTier.TIER_2_MEDIUM,
            criticality_score=0.5,
            role_description="Standard Corporate Server",
        )


# Global singleton
asset_context_resolver = AssetContextResolver()
