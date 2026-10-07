"""
Dynamic Multi-Dimensional Risk Matrix for Severity Engine.

Evaluates security incidents across Likelihood and Impact dimensions (5x5 matrix),
calculates estimated financial exposure in USD (Ponemon data breach model),
and incorporates regulatory non-compliance penalties (GDPR, HIPAA, PCI-DSS).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from backend.ingestion.models import SeverityLevel


class LikelihoodLevel(int, Enum):
    RARE = 1
    UNLIKELY = 2
    POSSIBLE = 3
    LIKELY = 4
    ALMOST_CERTAIN = 5


class ImpactLevel(int, Enum):
    NEGLIGIBLE = 1
    MINOR = 2
    MODERATE = 3
    MAJOR = 4
    CATASTROPHIC = 5


class RegulatoryFramework(str, Enum):
    GDPR = "GDPR"
    HIPAA = "HIPAA"
    PCI_DSS = "PCI_DSS"
    SOX = "SOX"
    NIST_CSF = "NIST_CSF"


class RiskCategory(str, Enum):
    OPERATIONAL = "OPERATIONAL"
    FINANCIAL = "FINANCIAL"
    REPUTATIONAL = "REPUTATIONAL"
    REGULATORY_COMPLIANCE = "REGULATORY_COMPLIANCE"
    LEGAL = "LEGAL"


@dataclass
class RiskAssessment:
    likelihood: LikelihoodLevel
    impact: ImpactLevel
    matrix_score: int  # 1 to 25
    severity_level: SeverityLevel
    estimated_financial_exposure_usd: float
    regulatory_penalties: Dict[str, float] = field(default_factory=dict)
    primary_category: RiskCategory = RiskCategory.OPERATIONAL
    summary: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "likelihood": self.likelihood.name,
            "likelihood_val": self.likelihood.value,
            "impact": self.impact.name,
            "impact_val": self.impact.value,
            "matrix_score": self.matrix_score,
            "severity_level": self.severity_level.value,
            "estimated_financial_exposure_usd": round(self.estimated_financial_exposure_usd, 2),
            "regulatory_penalties": {k: round(v, 2) for k, v in self.regulatory_penalties.items()},
            "primary_category": self.primary_category.value,
            "summary": self.summary,
        }


class DynamicRiskMatrix:
    """Calculates multidimensional risk matrix score, financial risk and regulatory impact."""

    COST_PER_RECORD_USD = 165.0  # Industry benchmark (Ponemon Cost of Data Breach)
    CRITICAL_INFRA_OUTAGE_HOURLY_COST_USD = 50000.0  # Enterprise hourly downtime cost

    REGULATORY_BASE_FINES = {
        RegulatoryFramework.GDPR: 100000.0,
        RegulatoryFramework.HIPAA: 50000.0,
        RegulatoryFramework.PCI_DSS: 25000.0,
        RegulatoryFramework.SOX: 75000.0,
    }

    def _determine_severity(self, score: int) -> SeverityLevel:
        if score >= 20:
            return SeverityLevel.CRITICAL
        elif score >= 12:
            return SeverityLevel.HIGH
        elif score >= 6:
            return SeverityLevel.MEDIUM
        elif score >= 3:
            return SeverityLevel.LOW
        return SeverityLevel.INFORMATIONAL

    def evaluate(
        self,
        likelihood: LikelihoodLevel,
        impact: ImpactLevel,
        records_exposed: int = 0,
        estimated_downtime_hours: float = 0.0,
        crown_jewel_affected: bool = False,
        regulatory_frameworks: Optional[List[RegulatoryFramework]] = None,
        category: RiskCategory = RiskCategory.OPERATIONAL,
    ) -> RiskAssessment:
        """Evaluates composite risk score and financial exposure."""
        matrix_score = likelihood.value * impact.value
        sev = self._determine_severity(matrix_score)

        # Base financial loss calculation
        data_loss = records_exposed * self.COST_PER_RECORD_USD
        downtime_loss = estimated_downtime_hours * self.CRITICAL_INFRA_OUTAGE_HOURLY_COST_USD
        base_financial = data_loss + downtime_loss

        if crown_jewel_affected:
            base_financial += 250000.0

        # Regulatory penalties
        penalties: Dict[str, float] = {}
        if regulatory_frameworks:
            for framework in regulatory_frameworks:
                fine_multiplier = 1.0
                if records_exposed > 10000:
                    fine_multiplier = 3.5
                elif records_exposed > 1000:
                    fine_multiplier = 2.0
                base_fine = self.REGULATORY_BASE_FINES.get(framework, 20000.0)
                penalties[framework.value] = base_fine * fine_multiplier

        total_financial = base_financial + sum(penalties.values())

        # If catastrophic exposure exceeds $1M, elevate severity
        if total_financial >= 1000000.0 and sev != SeverityLevel.CRITICAL:
            sev = SeverityLevel.CRITICAL

        summary = (
            f"Risk Matrix: {likelihood.name} ({likelihood.value}) x {impact.name} ({impact.value}) = "
            f"Score {matrix_score} [{sev.value.upper()}]. "
            f"Est. Financial Exposure: ${total_financial:,.2f}. "
            f"Regulatory Frameworks: {[f.value for f in (regulatory_frameworks or [])]}."
        )

        return RiskAssessment(
            likelihood=likelihood,
            impact=impact,
            matrix_score=matrix_score,
            severity_level=sev,
            estimated_financial_exposure_usd=total_financial,
            regulatory_penalties=penalties,
            primary_category=category,
            summary=summary,
        )
