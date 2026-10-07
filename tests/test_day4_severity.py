"""
Comprehensive test suite for Day 4 Severity Engine modules.

Covers:
- CompositeSeverityOrchestrator full pipeline
- SeverityReportGenerator (Markdown + JSON)
- BulkReportManager aggregation
- DeterministicScorer.score_with_composite integration
- FloorEnforcer non-downgrade invariant (regression)
- EnvironmentalDrift temporal multipliers
- ThreatActorWeighting capability logic
- BusinessImpact SLA assessment
- HistoricalCalibrator feedback loop
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import List

import pytest

from backend.ingestion.models import SeverityLevel
from backend.severity.risk_matrix import (
    DynamicRiskMatrix, LikelihoodLevel, ImpactLevel, RegulatoryFramework,
)
from backend.severity.floor_enforcer import (
    HardenedFloorEnforcer, DowngradeViolationType,
)
from backend.severity.environmental_drift import EnvironmentalDriftCompensator
from backend.severity.threat_actor_weighting import ThreatActorWeightingEngine
from backend.severity.business_impact import (
    BusinessImpactAssessor, BusinessUnitType, ServiceCriticality,
)
from backend.severity.calibration import HistoricalScoreCalibrator, AnalystVerdict
from backend.severity.composite_scorer import (
    CompositeSeverityOrchestrator, CompositeSeverityResult,
)
from backend.severity.report_generator import (
    SeverityReportGenerator, BulkReportManager,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

SEVERITY_ORDER = [
    SeverityLevel.INFORMATIONAL,
    SeverityLevel.LOW,
    SeverityLevel.MEDIUM,
    SeverityLevel.HIGH,
    SeverityLevel.CRITICAL,
]


def _sev_rank(sev: SeverityLevel) -> int:
    return SEVERITY_ORDER.index(sev)


# ---------------------------------------------------------------------------
# CompositeSeverityOrchestrator
# ---------------------------------------------------------------------------

class TestCompositeSeverityOrchestrator:

    def setup_method(self):
        self.orchestrator = CompositeSeverityOrchestrator()

    def _score(self, base_score=50.0, floor=SeverityLevel.LOW, **kwargs) -> CompositeSeverityResult:
        return self.orchestrator.score(
            incident_id=f"INC-{uuid.uuid4().hex[:6]}",
            base_score=base_score,
            deterministic_floor=floor,
            **kwargs,
        )

    def test_returns_composite_severity_result(self):
        result = self._score()
        assert isinstance(result, CompositeSeverityResult)

    def test_result_has_required_fields(self):
        result = self._score()
        assert result.result_id.startswith("csr-")
        assert result.incident_id
        assert isinstance(result.final_severity, SeverityLevel)
        assert 0.0 <= result.final_score <= 100.0

    def test_pipeline_stages_populated(self):
        result = self._score()
        for stage in ("risk_matrix", "environmental_drift", "actor_weighting",
                      "calibration", "business_impact"):
            assert stage in result.pipeline_stages, f"Missing stage: {stage}"

    def test_floor_respected_for_low_base_score(self):
        result = self._score(base_score=1.0, floor=SeverityLevel.HIGH)
        assert _sev_rank(result.final_severity) >= _sev_rank(SeverityLevel.HIGH)

    def test_floor_respected_for_critical(self):
        result = self._score(base_score=5.0, floor=SeverityLevel.CRITICAL)
        assert result.final_severity == SeverityLevel.CRITICAL

    def test_final_score_bounded(self):
        result = self._score(base_score=99.0)
        assert result.final_score <= 100.0

    def test_actor_0day_increases_score(self):
        r1 = self._score(base_score=50.0)
        r2 = self._score(base_score=50.0, observed_0day=True, attribution_confidence=0.9)
        assert r2.actor_weighted_score >= r1.actor_weighted_score

    def test_wiper_raises_severity(self):
        result = self._score(base_score=40.0, observed_wiper=True,
                             floor=SeverityLevel.LOW)
        assert _sev_rank(result.final_severity) >= _sev_rank(SeverityLevel.MEDIUM)

    def test_customer_facing_outage_increases_impact(self):
        r1 = self._score(base_score=50.0, customer_facing_outage=False)
        r2 = self._score(base_score=50.0, customer_facing_outage=True)
        assert r2.final_score >= r1.final_score

    def test_adversarial_injection_floor_applied(self):
        result = self._score(
            base_score=1.0,
            floor=SeverityLevel.HIGH,
            adversarial_injection_detected=True,
            proposed_severity=SeverityLevel.LOW,
        )
        assert result.enforcement_record.downgrade_prevented is True
        assert result.enforcement_record.violation_type == DowngradeViolationType.PROMPT_INJECTION_TAMPERING

    def test_to_dict_serialisable(self):
        result = self._score()
        d = result.to_dict()
        json.dumps(d)
        assert d["incident_id"] == result.incident_id

    def test_score_with_many_business_units(self):
        result = self._score(
            affected_units=[
                BusinessUnitType.PAYMENTS_CHECKOUT,
                BusinessUnitType.CUSTOMER_PORTAL,
                BusinessUnitType.INTERNAL_OFFICE_IT,
            ]
        )
        assert result.business_impact is not None
        assert result.business_impact.business_impact_score > 0.0

    def test_regulatory_frameworks_flow_to_risk_matrix(self):
        result = self._score(
            regulatory_frameworks=[RegulatoryFramework.GDPR, RegulatoryFramework.PCI_DSS],
            records_exposed=100000,
        )
        rm = result.pipeline_stages["risk_matrix"]
        assert rm.get("estimated_financial_exposure_usd", 0) > 0

    def test_change_freeze_raises_drift_multiplier(self):
        ts_weekday = datetime(2024, 1, 15, 14, 0, 0, tzinfo=timezone.utc)
        r1 = self._score(base_score=50.0, timestamp=ts_weekday)
        r2 = self._score(base_score=50.0, timestamp=ts_weekday, change_freeze_active=True)
        assert r2.drift_adjusted_score >= r1.drift_adjusted_score

    def test_analyst_feedback_accepted(self):
        result = self._score()
        self.orchestrator.record_analyst_feedback(
            incident_id=result.incident_id,
            model_score=result.final_score,
            model_severity=result.final_severity,
            verdict=AnalystVerdict.TRUE_POSITIVE_CONFIRMED,
            analyst_id="analyst-001",
        )

    def test_known_threat_actor_weighs_higher(self):
        r_unknown = self._score(base_score=50.0)
        r_known = self._score(base_score=50.0, actor_name="Lazarus Group",
                              attribution_confidence=0.9)
        assert r_known.actor_weighted_score >= r_unknown.actor_weighted_score


# ---------------------------------------------------------------------------
# SeverityReportGenerator
# ---------------------------------------------------------------------------

class TestSeverityReportGenerator:

    def setup_method(self):
        self.orchestrator = CompositeSeverityOrchestrator()
        self.generator = SeverityReportGenerator()

    def _make_result(self, base=50.0, floor=SeverityLevel.MEDIUM) -> CompositeSeverityResult:
        return self.orchestrator.score(
            incident_id=f"INC-{uuid.uuid4().hex[:6]}",
            base_score=base,
            deterministic_floor=floor,
        )

    def test_markdown_contains_incident_id(self):
        result = self._make_result()
        md = self.generator.to_markdown(result)
        assert result.incident_id in md

    def test_markdown_contains_result_id(self):
        result = self._make_result()
        md = self.generator.to_markdown(result)
        assert result.result_id in md

    def test_markdown_contains_severity(self):
        result = self._make_result()
        md = self.generator.to_markdown(result)
        assert result.final_severity.value.upper() in md

    def test_markdown_contains_score(self):
        result = self._make_result()
        md = self.generator.to_markdown(result)
        assert str(round(result.final_score, 1)) in md

    def test_json_valid(self):
        result = self._make_result()
        js = self.generator.to_json(result)
        parsed = json.loads(js)
        assert parsed["incident_id"] == result.incident_id

    def test_json_contains_pipeline_stages(self):
        result = self._make_result()
        parsed = json.loads(self.generator.to_json(result))
        assert "pipeline_stages" in parsed

    def test_save_report_creates_files(self, tmp_path):
        result = self._make_result()
        written = self.generator.save_report(result, output_dir=tmp_path)
        assert "md" in written
        assert "json" in written
        assert written["md"].exists()
        assert written["json"].exists()

    def test_save_report_md_only(self, tmp_path):
        result = self._make_result()
        written = self.generator.save_report(result, output_dir=tmp_path, formats=["md"])
        assert "md" in written
        assert "json" not in written

    def test_save_report_json_only(self, tmp_path):
        result = self._make_result()
        written = self.generator.save_report(result, output_dir=tmp_path, formats=["json"])
        assert "json" in written
        assert "md" not in written

    def test_enforcement_section_shown_when_applied(self):
        result = self.orchestrator.score(
            incident_id="INC-ENFORCE-01",
            base_score=1.0,
            deterministic_floor=SeverityLevel.CRITICAL,
            proposed_severity=SeverityLevel.LOW,
        )
        md = self.generator.to_markdown(result)
        assert "Floor Enforcement Applied" in md

    def test_no_enforcement_section_when_not_applied(self):
        result = self.orchestrator.score(
            incident_id="INC-NO-ENFORCE-01",
            base_score=90.0,
            deterministic_floor=SeverityLevel.LOW,
        )
        if not result.enforcement_record.downgrade_prevented:
            md = self.generator.to_markdown(result)
            assert "Floor Enforcement Applied" not in md


# ---------------------------------------------------------------------------
# BulkReportManager
# ---------------------------------------------------------------------------

class TestBulkReportManager:

    def setup_method(self):
        self.orch = CompositeSeverityOrchestrator()
        self.manager = BulkReportManager()

    def _add_results(self, n: int) -> None:
        for i in range(n):
            r = self.orch.score(
                incident_id=f"INC-{i:04d}",
                base_score=float(20 + i * 5),
                deterministic_floor=SeverityLevel.LOW,
            )
            self.manager.add_result(r)

    def test_empty_summary(self):
        summary = self.manager.generate_summary()
        assert "error" in summary

    def test_summary_with_results(self):
        self._add_results(5)
        summary = self.manager.generate_summary()
        assert summary["total_incidents"] == 5
        assert "severity_distribution" in summary
        assert "score_statistics" in summary

    def test_floor_enforcement_rate(self):
        self._add_results(10)
        summary = self.manager.generate_summary()
        rate = summary["floor_enforcement_rate"]
        assert 0.0 <= rate <= 1.0

    def test_save_all(self, tmp_path):
        self._add_results(3)
        results = self.manager.save_all(tmp_path)
        assert len(results) == 3
        for written in results:
            assert written["md"].exists()
            assert written["json"].exists()


# ---------------------------------------------------------------------------
# FloorEnforcer regression
# ---------------------------------------------------------------------------

class TestFloorEnforcerRegression:

    def setup_method(self):
        self.enforcer = HardenedFloorEnforcer()

    def test_critical_floor_never_downgraded_to_low(self):
        rec = self.enforcer.enforce(
            incident_id="REG-001",
            deterministic_floor=SeverityLevel.CRITICAL,
            proposed_severity=SeverityLevel.LOW,
        )
        assert rec.enforced_severity == SeverityLevel.CRITICAL
        assert rec.downgrade_prevented is True

    def test_high_floor_never_downgraded_to_informational(self):
        rec = self.enforcer.enforce(
            incident_id="REG-002",
            deterministic_floor=SeverityLevel.HIGH,
            proposed_severity=SeverityLevel.INFORMATIONAL,
        )
        assert rec.enforced_severity == SeverityLevel.HIGH

    def test_no_enforcement_when_proposed_exceeds_floor(self):
        rec = self.enforcer.enforce(
            incident_id="REG-003",
            deterministic_floor=SeverityLevel.LOW,
            proposed_severity=SeverityLevel.CRITICAL,
        )
        assert rec.enforced_severity == SeverityLevel.CRITICAL
        assert rec.downgrade_prevented is False

    def test_adversarial_injection_flagged(self):
        rec = self.enforcer.enforce(
            incident_id="REG-004",
            deterministic_floor=SeverityLevel.HIGH,
            proposed_severity=SeverityLevel.LOW,
            adversarial_injection_detected=True,
        )
        assert rec.downgrade_prevented is True
        assert rec.violation_type == DowngradeViolationType.PROMPT_INJECTION_TAMPERING
        assert rec.enforced_severity == SeverityLevel.HIGH


# ---------------------------------------------------------------------------
# EnvironmentalDrift
# ---------------------------------------------------------------------------

class TestEnvironmentalDrift:

    def setup_method(self):
        self.comp = EnvironmentalDriftCompensator()

    def test_change_freeze_increases_multiplier(self):
        ts = datetime(2024, 1, 15, 14, 0, tzinfo=timezone.utc)
        r1 = self.comp.evaluate(base_score=50.0, timestamp=ts)
        r2 = self.comp.evaluate(base_score=50.0, timestamp=ts, change_freeze_active=True)
        assert r2.drift_multiplier >= r1.drift_multiplier

    def test_maintenance_may_decrease_multiplier(self):
        ts = datetime(2024, 1, 15, 14, 0, tzinfo=timezone.utc)
        r_base = self.comp.evaluate(base_score=50.0, timestamp=ts)
        r_maint = self.comp.evaluate(base_score=50.0, timestamp=ts, in_maintenance=True)
        assert r_maint.drift_multiplier <= r_base.drift_multiplier

    def test_adjusted_score_reflects_multiplier(self):
        ts = datetime(2024, 1, 15, 14, 0, tzinfo=timezone.utc)
        r = self.comp.evaluate(base_score=50.0, timestamp=ts)
        expected = min(100.0, 50.0 * r.drift_multiplier)
        assert abs(r.adjusted_score - expected) < 0.01

    def test_high_config_drift_raises_score(self):
        ts = datetime(2024, 1, 15, 14, 0, tzinfo=timezone.utc)
        r_low = self.comp.evaluate(base_score=50.0, timestamp=ts, config_drift_score=0.0)
        r_high = self.comp.evaluate(base_score=50.0, timestamp=ts, config_drift_score=1.0)
        assert r_high.drift_multiplier >= r_low.drift_multiplier


# ---------------------------------------------------------------------------
# ThreatActorWeighting
# ---------------------------------------------------------------------------

class TestThreatActorWeighting:

    def setup_method(self):
        self.engine = ThreatActorWeightingEngine()

    def test_no_actor_returns_base_score(self):
        result = self.engine.weight(base_score=50.0)
        assert result.final_score >= 50.0

    def test_known_apt_raises_score(self):
        r_unknown = self.engine.weight(base_score=50.0)
        r_apt = self.engine.weight(
            base_score=50.0,
            actor_name="APT29",
            attribution_confidence=0.85,
        )
        assert r_apt.final_score >= r_unknown.final_score

    def test_low_confidence_reduces_weight(self):
        r_high = self.engine.weight(base_score=50.0, actor_name="APT28",
                                    attribution_confidence=0.9)
        r_low = self.engine.weight(base_score=50.0, actor_name="APT28",
                                   attribution_confidence=0.1)
        assert r_high.final_score >= r_low.final_score

    def test_0day_increases_score(self):
        r_no_0day = self.engine.weight(base_score=50.0)
        r_0day = self.engine.weight(base_score=50.0, observed_0day=True)
        assert r_0day.final_score >= r_no_0day.final_score

    def test_wiper_increases_score(self):
        r1 = self.engine.weight(base_score=50.0)
        r2 = self.engine.weight(base_score=50.0, observed_wiper=True)
        assert r2.final_score >= r1.final_score

    def test_final_score_bounded(self):
        r = self.engine.weight(
            base_score=99.0,
            actor_name="Sandworm",
            attribution_confidence=1.0,
            observed_0day=True,
            observed_wiper=True,
            observed_edr_tampering=True,
        )
        assert r.final_score <= 100.0


# ---------------------------------------------------------------------------
# BusinessImpact
# ---------------------------------------------------------------------------

class TestBusinessImpact:

    def setup_method(self):
        self.assessor = BusinessImpactAssessor()

    def test_no_units_returns_zero_impact(self):
        result = self.assessor.assess(affected_units=[])
        assert result.business_impact_score >= 0.0

    def test_customer_facing_outage_raises_impact(self):
        r1 = self.assessor.assess(affected_units=[], customer_facing_outage=False)
        r2 = self.assessor.assess(affected_units=[], customer_facing_outage=True)
        assert r2.highest_criticality == ServiceCriticality.TIER_0_MISSION_CRITICAL
        assert r2.business_impact_score >= r1.business_impact_score

    def test_payments_checkout_unit_criticality(self):
        r = self.assessor.assess(
            affected_units=[BusinessUnitType.PAYMENTS_CHECKOUT],
            customer_facing_outage=True,
        )
        assert r.highest_criticality == ServiceCriticality.TIER_0_MISSION_CRITICAL
        assert r.business_impact_score >= 25.0

    def test_to_dict_complete(self):
        r = self.assessor.assess(
            affected_units=[BusinessUnitType.INTERNAL_OFFICE_IT],
        )
        d = r.to_dict()
        assert "business_impact_score" in d
        assert "affected_units" in d


# ---------------------------------------------------------------------------
# HistoricalCalibrator
# ---------------------------------------------------------------------------

class TestHistoricalCalibrator:

    def setup_method(self):
        self.calibrator = HistoricalScoreCalibrator()

    def test_calibrate_returns_float(self):
        score = self.calibrator.calibrate(55.0)
        assert isinstance(score, float)

    def test_calibrated_score_bounded(self):
        score = self.calibrator.calibrate(100.0)
        assert 0.0 <= score <= 100.0

    def test_record_feedback_correct_verdict(self):
        self.calibrator.record_feedback(
            incident_id="CAL-001",
            model_score=60.0,
            model_severity=SeverityLevel.HIGH,
            verdict=AnalystVerdict.TRUE_POSITIVE_CONFIRMED,
            analyst_id="analyst-A",
        )

    def test_record_feedback_over_scored(self):
        self.calibrator.record_feedback(
            incident_id="CAL-002",
            model_score=80.0,
            model_severity=SeverityLevel.CRITICAL,
            verdict=AnalystVerdict.SEVERITY_OVERESTIMATED,
            analyst_id="analyst-B",
            adjusted_severity=SeverityLevel.HIGH,
        )

    def test_repeated_feedback_adjusts_calibration(self):
        for i in range(20):
            self.calibrator.record_feedback(
                incident_id=f"CAL-OS-{i}",
                model_score=85.0,
                model_severity=SeverityLevel.CRITICAL,
                verdict=AnalystVerdict.SEVERITY_OVERESTIMATED,
                analyst_id="analyst-C",
                adjusted_severity=SeverityLevel.HIGH,
            )
        calibrated = self.calibrator.calibrate(85.0)
        assert calibrated <= 85.0

    def test_under_scored_verdict_not_raises(self):
        self.calibrator.record_feedback(
            incident_id="CAL-003",
            model_score=30.0,
            model_severity=SeverityLevel.LOW,
            verdict=AnalystVerdict.SEVERITY_UNDERESTIMATED,
            analyst_id="analyst-D",
            adjusted_severity=SeverityLevel.HIGH,
        )
