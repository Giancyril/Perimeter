"""
Composite Severity Orchestrator for Severity Engine (Day 4).

Integrates all Day 4 advanced modules into a single unified pipeline:
- RiskMatrix (financial/regulatory)
- FloorEnforcer (non-downgrade invariant)
- EnvironmentalDrift (temporal sensitivity)
- ThreatActorWeighting (actor capability)
- BusinessImpact (SLA / workflow)
- HistoricalCalibrator (analyst feedback)

Produces a fully-auditable, multi-factor SeverityResult.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from backend.ingestion.models import SeverityLevel
from backend.severity.risk_matrix import (
    DynamicRiskMatrix, LikelihoodLevel, ImpactLevel, RegulatoryFramework,
)
from backend.severity.floor_enforcer import (
    HardenedFloorEnforcer, FloorEnforcementRecord,
)
from backend.severity.environmental_drift import (
    EnvironmentalDriftCompensator, DriftAdjustmentResult,
)
from backend.severity.threat_actor_weighting import (
    ThreatActorWeightingEngine, ActorWeightedSeverity,
)
from backend.severity.business_impact import (
    BusinessImpactAssessor, BusinessUnitType, BusinessImpactAssessment,
)
from backend.severity.calibration import (
    HistoricalScoreCalibrator, AnalystVerdict,
)

SEVERITY_ORDER = [
    SeverityLevel.INFORMATIONAL,
    SeverityLevel.LOW,
    SeverityLevel.MEDIUM,
    SeverityLevel.HIGH,
    SeverityLevel.CRITICAL,
]


def _score_to_severity(score: float) -> SeverityLevel:
    if score >= 80.0:
        return SeverityLevel.CRITICAL
    elif score >= 60.0:
        return SeverityLevel.HIGH
    elif score >= 40.0:
        return SeverityLevel.MEDIUM
    elif score >= 20.0:
        return SeverityLevel.LOW
    return SeverityLevel.INFORMATIONAL


def _max_severity(a: SeverityLevel, b: SeverityLevel) -> SeverityLevel:
    return a if SEVERITY_ORDER.index(a) >= SEVERITY_ORDER.index(b) else b


@dataclass
class CompositeSeverityResult:
    result_id: str
    incident_id: str
    raw_base_score: float
    drift_adjusted_score: float
    actor_weighted_score: float
    calibrated_score: float
    final_score: float
    final_severity: SeverityLevel
    deterministic_floor: SeverityLevel
    enforcement_record: FloorEnforcementRecord
    business_impact: BusinessImpactAssessment
    pipeline_stages: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "result_id": self.result_id,
            "incident_id": self.incident_id,
            "raw_base_score": round(self.raw_base_score, 2),
            "drift_adjusted_score": round(self.drift_adjusted_score, 2),
            "actor_weighted_score": round(self.actor_weighted_score, 2),
            "calibrated_score": round(self.calibrated_score, 2),
            "final_score": round(self.final_score, 2),
            "final_severity": self.final_severity.value,
            "deterministic_floor": self.deterministic_floor.value,
            "enforcement_record": self.enforcement_record.to_dict(),
            "business_impact": self.business_impact.to_dict(),
            "pipeline_stages": self.pipeline_stages,
            "timestamp": self.timestamp.isoformat(),
        }


class CompositeSeverityOrchestrator:
    """Unified pipeline that applies all Day 4 severity modules in sequence."""

    def __init__(self) -> None:
        self._risk_matrix = DynamicRiskMatrix()
        self._floor_enforcer = HardenedFloorEnforcer()
        self._drift_compensator = EnvironmentalDriftCompensator()
        self._actor_engine = ThreatActorWeightingEngine()
        self._impact_assessor = BusinessImpactAssessor()
        self._calibrator = HistoricalScoreCalibrator()

    def score(
        self,
        incident_id: str,
        base_score: float,
        deterministic_floor: SeverityLevel,
        # Risk Matrix inputs
        likelihood: LikelihoodLevel = LikelihoodLevel.POSSIBLE,
        impact: ImpactLevel = ImpactLevel.MODERATE,
        records_exposed: int = 0,
        downtime_hours: float = 0.0,
        crown_jewel_affected: bool = False,
        regulatory_frameworks: Optional[List[RegulatoryFramework]] = None,
        # Temporal drift inputs
        timestamp: Optional[datetime] = None,
        in_maintenance: bool = False,
        change_freeze_active: bool = False,
        config_drift_score: float = 0.0,
        # Actor weighting inputs
        actor_name: Optional[str] = None,
        attribution_confidence: float = 0.5,
        observed_0day: bool = False,
        observed_wiper: bool = False,
        observed_edr_tampering: bool = False,
        # Business impact inputs
        affected_units: Optional[List[BusinessUnitType]] = None,
        customer_facing_outage: bool = False,
        # LLM proposed severity
        proposed_severity: Optional[SeverityLevel] = None,
        adversarial_injection_detected: bool = False,
    ) -> CompositeSeverityResult:
        """Runs full multi-factor severity scoring pipeline."""

        stages: Dict[str, Any] = {}

        # Stage 1: Risk Matrix financial weight
        risk = self._risk_matrix.evaluate(
            likelihood=likelihood,
            impact=impact,
            records_exposed=records_exposed,
            estimated_downtime_hours=downtime_hours,
            crown_jewel_affected=crown_jewel_affected,
            regulatory_frameworks=regulatory_frameworks,
        )
        stages["risk_matrix"] = risk.to_dict()

        # Stage 2: Environmental drift adjustment
        drift: DriftAdjustmentResult = self._drift_compensator.evaluate(
            base_score=base_score,
            timestamp=timestamp,
            in_maintenance=in_maintenance,
            change_freeze_active=change_freeze_active,
            config_drift_score=config_drift_score,
        )
        stages["environmental_drift"] = drift.to_dict()

        # Stage 3: Threat actor weighting
        actor: ActorWeightedSeverity = self._actor_engine.weight(
            base_score=drift.adjusted_score,
            actor_name=actor_name,
            attribution_confidence=attribution_confidence,
            observed_0day=observed_0day,
            observed_wiper=observed_wiper,
            observed_edr_tampering=observed_edr_tampering,
        )
        stages["actor_weighting"] = actor.to_dict()

        # Stage 4: Historical calibration
        calibrated_score = self._calibrator.calibrate(actor.final_score)
        stages["calibration"] = {"calibrated_score": round(calibrated_score, 2)}

        # Stage 5: Business impact
        impact_assessment: BusinessImpactAssessment = self._impact_assessor.assess(
            affected_units=affected_units or [],
            customer_facing_outage=customer_facing_outage,
        )
        final_score = min(100.0, calibrated_score + impact_assessment.business_impact_score * 0.2)
        stages["business_impact"] = impact_assessment.to_dict()

        # Stage 6: Determine candidate severity
        candidate = _score_to_severity(final_score)
        # Also respect the risk matrix elevated severity
        candidate = _max_severity(candidate, risk.severity_level)

        # Stage 7: Floor enforcement (never downgrade)
        proposed = proposed_severity or candidate
        enforcement = self._floor_enforcer.enforce(
            incident_id=incident_id,
            deterministic_floor=deterministic_floor,
            proposed_severity=proposed,
            adversarial_injection_detected=adversarial_injection_detected,
        )

        return CompositeSeverityResult(
            result_id=f"csr-{uuid.uuid4().hex[:8]}",
            incident_id=incident_id,
            raw_base_score=base_score,
            drift_adjusted_score=drift.adjusted_score,
            actor_weighted_score=actor.final_score,
            calibrated_score=calibrated_score,
            final_score=final_score,
            final_severity=enforcement.enforced_severity,
            deterministic_floor=deterministic_floor,
            enforcement_record=enforcement,
            business_impact=impact_assessment,
            pipeline_stages=stages,
        )

    def record_analyst_feedback(
        self,
        incident_id: str,
        model_score: float,
        model_severity: SeverityLevel,
        verdict: AnalystVerdict,
        analyst_id: str,
        adjusted_severity: Optional[SeverityLevel] = None,
        notes: Optional[str] = None,
    ) -> None:
        """Feeds analyst verdict back into the calibration engine."""
        self._calibrator.record_feedback(
            incident_id=incident_id,
            model_score=model_score,
            model_severity=model_severity,
            verdict=verdict,
            analyst_id=analyst_id,
            adjusted_severity=adjusted_severity,
            notes=notes,
        )
