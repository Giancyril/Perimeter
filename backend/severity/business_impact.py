"""
Granular Business Impact & Critical Workflow Disruption Assessor for Severity Engine.

Maps affected infrastructure and credentials to business workflows (Payments, Identity, ERP),
calculates customer-facing service disruption risks, and computes regulatory SLA deadlines.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


class BusinessUnitType(str, Enum):
    PAYMENTS_CHECKOUT = "PAYMENTS_CHECKOUT"
    IDENTITY_AUTHENTICATION = "IDENTITY_AUTHENTICATION"
    CUSTOMER_PORTAL = "CUSTOMER_PORTAL"
    ERP_SUPPLY_CHAIN = "ERP_SUPPLY_CHAIN"
    INTERNAL_OFFICE_IT = "INTERNAL_OFFICE_IT"


class ServiceCriticality(str, Enum):
    TIER_0_MISSION_CRITICAL = "TIER_0_MISSION_CRITICAL"
    TIER_1_BUSINESS_CRITICAL = "TIER_1_BUSINESS_CRITICAL"
    TIER_2_OPERATIONAL = "TIER_2_OPERATIONAL"
    TIER_3_NON_CRITICAL = "TIER_3_NON_CRITICAL"


@dataclass
class SLATargets:
    ack_deadline_minutes: int
    remediation_deadline_hours: int


@dataclass
class BusinessImpactAssessment:
    highest_criticality: ServiceCriticality
    affected_units: List[BusinessUnitType]
    ack_deadline: datetime
    remediation_deadline: datetime
    sla_breached: bool
    business_impact_score: float  # 0.0 to 30.0 contribution to severity
    executive_summary: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "highest_criticality": self.highest_criticality.value,
            "affected_units": [u.value for u in self.affected_units],
            "ack_deadline": self.ack_deadline.isoformat(),
            "remediation_deadline": self.remediation_deadline.isoformat(),
            "sla_breached": self.sla_breached,
            "business_impact_score": round(self.business_impact_score, 2),
            "executive_summary": self.executive_summary,
        }


class BusinessImpactAssessor:
    """Evaluates business operational disruption and calculates SOC response deadlines."""

    CRITICALITY_SLAS = {
        ServiceCriticality.TIER_0_MISSION_CRITICAL: SLATargets(15, 1),
        ServiceCriticality.TIER_1_BUSINESS_CRITICAL: SLATargets(30, 4),
        ServiceCriticality.TIER_2_OPERATIONAL: SLATargets(120, 24),
        ServiceCriticality.TIER_3_NON_CRITICAL: SLATargets(480, 72),
    }

    UNIT_CRITICALITY_MAP = {
        BusinessUnitType.PAYMENTS_CHECKOUT: ServiceCriticality.TIER_0_MISSION_CRITICAL,
        BusinessUnitType.IDENTITY_AUTHENTICATION: ServiceCriticality.TIER_0_MISSION_CRITICAL,
        BusinessUnitType.CUSTOMER_PORTAL: ServiceCriticality.TIER_1_BUSINESS_CRITICAL,
        BusinessUnitType.ERP_SUPPLY_CHAIN: ServiceCriticality.TIER_1_BUSINESS_CRITICAL,
        BusinessUnitType.INTERNAL_OFFICE_IT: ServiceCriticality.TIER_2_OPERATIONAL,
    }

    def assess(
        self,
        affected_units: List[BusinessUnitType],
        incident_start: Optional[datetime] = None,
        customer_facing_outage: bool = False,
    ) -> BusinessImpactAssessment:
        """Determines highest criticality, calculates SLA timelines and score contribution."""
        start = incident_start or datetime.now(timezone.utc)
        units = affected_units or [BusinessUnitType.INTERNAL_OFFICE_IT]

        # Determine highest criticality
        highest_crit = ServiceCriticality.TIER_3_NON_CRITICAL
        rank_order = [
            ServiceCriticality.TIER_3_NON_CRITICAL,
            ServiceCriticality.TIER_2_OPERATIONAL,
            ServiceCriticality.TIER_1_BUSINESS_CRITICAL,
            ServiceCriticality.TIER_0_MISSION_CRITICAL,
        ]

        for u in units:
            crit = self.UNIT_CRITICALITY_MAP.get(u, ServiceCriticality.TIER_2_OPERATIONAL)
            if rank_order.index(crit) > rank_order.index(highest_crit):
                highest_crit = crit

        if customer_facing_outage and rank_order.index(highest_crit) < rank_order.index(ServiceCriticality.TIER_0_MISSION_CRITICAL):
            highest_crit = ServiceCriticality.TIER_0_MISSION_CRITICAL

        sla = self.CRITICALITY_SLAS[highest_crit]
        ack_dl = start + timedelta(minutes=sla.ack_deadline_minutes)
        rem_dl = start + timedelta(hours=sla.remediation_deadline_hours)

        now = datetime.now(timezone.utc)
        sla_breached = now > ack_dl

        # Score calculation (0 to 30 points)
        base_scores = {
            ServiceCriticality.TIER_0_MISSION_CRITICAL: 28.0,
            ServiceCriticality.TIER_1_BUSINESS_CRITICAL: 20.0,
            ServiceCriticality.TIER_2_OPERATIONAL: 12.0,
            ServiceCriticality.TIER_3_NON_CRITICAL: 5.0,
        }
        score = base_scores.get(highest_crit, 10.0)
        if len(units) > 1:
            score = min(30.0, score + (len(units) - 1) * 2.0)

        summary = (
            f"Business Impact [{highest_crit.value}]. Affected workflows: {[u.value for u in units]}. "
            f"Mandatory SOC Ack Deadline: {sla.ack_deadline_minutes}m, Remediation: {sla.remediation_deadline_hours}h. "
            f"Outage Flag: {customer_facing_outage}."
        )

        return BusinessImpactAssessment(
            highest_criticality=highest_crit,
            affected_units=units,
            ack_deadline=ack_dl,
            remediation_deadline=rem_dl,
            sla_breached=sla_breached,
            business_impact_score=score,
            executive_summary=summary,
        )
