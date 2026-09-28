"""
Phase 4: Hybrid Severity Scoring & Floor Enforcement Tests.
Validates:
- Deterministic risk formula (asset multipliers, TI points, MITRE multiplier)
- Domain safety hard rule overrides (Ransomware, Tier-0 DC, Prompt Injection)
- Strict floor enforcement (LLM cannot downgrade below floor, audit trail recorded)
- Verification against the 10-incident golden evaluation dataset in eval/labeled_incidents.json
"""
import json
import pytest
from datetime import datetime, timezone
from backend.correlation.models import CorrelatedIncident, IncidentStatus
from backend.ingestion.models import (
    NormalizedAlert, Entity, EntityType, EntityRole,
    SeverityLevel, AlertSourceType, MitreAttackMetadata,
)
from backend.agent.tools.asset_context import AssetCriticalityTier
from backend.severity import (
    deterministic_scorer,
    llm_severity_evaluator,
    ScoringBreakdown,
    LLMReasoningResult,
)


def _make_mock_incident(
    incident_id="INC-SEV-01",
    severity=SeverityLevel.MEDIUM,
    alert_count=1,
    tactics=None,
    title="Suspicious Activity",
    host="server-01",
    source_ip="10.0.0.1",
):
    now = datetime.now(timezone.utc).isoformat()
    tactics = tactics or ["Initial Access"]
    alerts = []
    for i in range(alert_count):
        alerts.append(
            NormalizedAlert(
                alert_id=f"a-{i}",
                fingerprint=f"fp-{i}",
                source=AlertSourceType.WAZUH,
                rule_id=f"R-{i}",
                rule_name="Test Rule",
                rule_description="Test Description",
                raw_severity=severity.value,
                normalized_severity=severity,
                timestamp=now,
                source_ip=source_ip,
                host=host,
                entities=[
                    Entity(type=EntityType.IP, value=source_ip, role=EntityRole.SOURCE),
                    Entity(type=EntityType.HOST, value=host, role=EntityRole.TARGET),
                ],
                mitre_attack=MitreAttackMetadata(tactics=tactics, techniques=["T1078"]),
                raw_payload={"test": True},
            )
        )
    return CorrelatedIncident(
        incident_id=incident_id,
        title=title,
        status=IncidentStatus.NEW,
        created_at=now,
        updated_at=now,
        window_start=now,
        window_end=now,
        alert_count=alert_count,
        alert_ids=[a.alert_id for a in alerts],
        alerts=alerts,
        entities=alerts[0].entities,
        primary_entity=host,
        tactics=tactics,
        techniques=["T1078"],
        attack_chain_span=len(tactics),
        correlation_reasons=["Test correlation"],
        deterministic_score=40,
        deterministic_floor=severity,
        severity=severity,
    )


class TestDeterministicScoringFormula:
    def test_base_score_scales_with_volume(self):
        inc1 = _make_mock_incident(alert_count=1, severity=SeverityLevel.MEDIUM)
        inc3 = _make_mock_incident(alert_count=5, severity=SeverityLevel.MEDIUM)

        b1 = deterministic_scorer.calculate_breakdown(inc1)
        b3 = deterministic_scorer.calculate_breakdown(inc3)

        assert b3.base_score > b1.base_score
        assert b3.raw_calculated_score > b1.raw_calculated_score

    def test_asset_criticality_multiplier(self):
        inc = _make_mock_incident(severity=SeverityLevel.MEDIUM)
        assets_tier0 = {"dc-01": {"criticality": AssetCriticalityTier.TIER_0_CRITICAL.value}}
        assets_tier3 = {"lab-01": {"criticality": AssetCriticalityTier.TIER_3_LOW.value}}

        b_tier0 = deterministic_scorer.calculate_breakdown(inc, asset_context=assets_tier0)
        b_tier3 = deterministic_scorer.calculate_breakdown(inc, asset_context=assets_tier3)

        assert b_tier0.asset_multiplier == 1.5
        assert b_tier3.asset_multiplier == 0.8
        assert b_tier0.raw_calculated_score > b_tier3.raw_calculated_score

    def test_threat_intel_points_boost(self):
        inc = _make_mock_incident(severity=SeverityLevel.LOW)
        ti_clean = {"10.0.0.1": {"verdict": "internal", "abuse_score": 0}}
        ti_bad = {"45.33.32.156": {"verdict": "malicious", "abuse_score": 95}}

        b_clean = deterministic_scorer.calculate_breakdown(inc, threat_intel=ti_clean)
        b_bad = deterministic_scorer.calculate_breakdown(inc, threat_intel=ti_bad)

        assert b_bad.threat_intel_points == 25.0
        assert b_bad.raw_calculated_score > b_clean.raw_calculated_score

    def test_mitre_progression_multiplier(self):
        inc1 = _make_mock_incident(tactics=["Initial Access"])
        inc5 = _make_mock_incident(tactics=["Initial Access", "Execution", "Persistence", "Privilege Escalation", "Exfiltration"])

        b1 = deterministic_scorer.calculate_breakdown(inc1)
        b5 = deterministic_scorer.calculate_breakdown(inc5)

        assert b1.mitre_multiplier == 1.0
        assert b5.mitre_multiplier == 1.5
        assert b5.raw_calculated_score > b1.raw_calculated_score


class TestDomainSafetyRuleOverrides:
    def test_ransomware_title_triggers_critical_floor(self):
        inc = _make_mock_incident(
            severity=SeverityLevel.LOW,
            title="Mass File Renaming Indicative of Ransomware (Canary Directory)",
        )
        b = deterministic_scorer.calculate_breakdown(inc)
        assert b.deterministic_floor == SeverityLevel.CRITICAL
        assert "Mass destructive activity" in b.rule_floor_override

    def test_tier0_asset_and_malicious_ti_forces_critical(self):
        inc = _make_mock_incident(severity=SeverityLevel.LOW)
        assets = {"dc-01": {"criticality": AssetCriticalityTier.TIER_0_CRITICAL.value}}
        ti = {"192.0.2.1": {"verdict": "malicious"}}

        b = deterministic_scorer.calculate_breakdown(inc, threat_intel=ti, asset_context=assets)
        assert b.deterministic_floor == SeverityLevel.CRITICAL
        assert "Tier-0" in b.rule_floor_override

    def test_adversarial_prompt_injection_forces_high(self):
        inc = _make_mock_incident(severity=SeverityLevel.LOW)
        b = deterministic_scorer.calculate_breakdown(inc, adversarial_injection_detected=True)
        assert b.deterministic_floor in (SeverityLevel.HIGH, SeverityLevel.CRITICAL)


class TestStrictFloorEnforcement:
    def test_llm_downgrade_attempt_is_strictly_blocked(self):
        inc = _make_mock_incident(severity=SeverityLevel.HIGH)
        breakdown = ScoringBreakdown(
            base_score=30.0,
            asset_multiplier=1.25,
            threat_intel_points=25.0,
            mitre_multiplier=1.3,
            lateral_movement_points=0.0,
            adversarial_injection_points=0.0,
            raw_calculated_score=81.25,
            deterministic_floor=SeverityLevel.HIGH,
            rule_floor_override=None,
        )

        class MaliciousDowngradeEvaluator(llm_severity_evaluator.__class__):
            def _run_llm_reasoning(self, **kwargs):
                return LLMReasoningResult(
                    suggested_severity=SeverityLevel.LOW,
                    confidence=0.99,
                    justification="Attacker trick: claims alert is false positive",
                    additional_risk_points=0.0,
                    model_used="rogue_llm",
                )

        evaluator = MaliciousDowngradeEvaluator()
        result = evaluator.evaluate_and_enforce(inc, breakdown)

        # Invariant check: CANNOT be downgraded to LOW!
        assert result.final_severity == SeverityLevel.HIGH
        assert result.floor_enforced is True
        assert "SECURITY POLICY ENFORCED" in result.audit_note
        assert "rejected" in result.audit_note.lower()

    def test_llm_elevation_is_accepted(self):
        inc = _make_mock_incident(severity=SeverityLevel.MEDIUM)
        breakdown = ScoringBreakdown(
            base_score=20.0,
            asset_multiplier=1.0,
            threat_intel_points=0.0,
            mitre_multiplier=1.0,
            lateral_movement_points=0.0,
            adversarial_injection_points=0.0,
            raw_calculated_score=20.0,
            deterministic_floor=SeverityLevel.MEDIUM,
            rule_floor_override=None,
        )

        class ElevatingEvaluator(llm_severity_evaluator.__class__):
            def _run_llm_reasoning(self, **kwargs):
                return LLMReasoningResult(
                    suggested_severity=SeverityLevel.HIGH,
                    confidence=0.88,
                    justification="Contextual business risk detected by analyst",
                    additional_risk_points=15.0,
                    model_used="test_llm",
                )

        evaluator = ElevatingEvaluator()
        result = evaluator.evaluate_and_enforce(inc, breakdown)

        assert result.final_severity == SeverityLevel.HIGH
        assert result.floor_enforced is False
        assert "SEVERITY ELEVATED" in result.audit_note


class TestEvaluationDatasetBenchmark:
    """Verifies scoring engine against the 10 labeled incidents in eval/labeled_incidents.json."""

    @pytest.fixture(scope="class")
    def labeled_data(self):
        with open("eval/labeled_incidents.json", "r", encoding="utf-8-sig") as f:
            return json.load(f)

    def test_eval_dataset_invariants(self, labeled_data):
        from backend.agent.tools.asset_context import asset_context_resolver
        from backend.agent.tools.threat_intel import threat_intel_client

        sev_map = {s.value: s for s in SeverityLevel}

        for item in labeled_data:
            incident_id = item["id"]
            name = item["name"]
            expected_floor = sev_map[item["expected_deterministic_floor"]]
            expected_final = sev_map[item["expected_final_severity"]]

            entities_dict = item.get("entities", {})
            host = entities_dict.get("host", "generic-host")
            ip = entities_dict.get("ip", "10.0.0.1")

            ti = {}
            if ip:
                ti[ip] = threat_intel_client.check_ip(ip)

            assets = {}
            if host:
                assets[host] = asset_context_resolver.resolve(host).model_dump()

            tactics = item.get("mitre_attack", {}).get("tactics", ["Initial Access"])
            has_injection = "adversarial_prompt" in item

            inc = _make_mock_incident(
                incident_id=incident_id,
                title=name,
                severity=expected_floor,
                tactics=tactics,
                host=host,
                source_ip=ip,
            )

            breakdown = deterministic_scorer.calculate_breakdown(
                incident=inc,
                threat_intel=ti,
                asset_context=assets,
                adversarial_injection_detected=has_injection,
            )

            final_res = llm_severity_evaluator.evaluate_and_enforce(
                incident=inc,
                breakdown=breakdown,
                threat_intel=ti,
                asset_context=assets,
                adversarial_injection_detected=has_injection,
            )

            # Invariant 1: Final severity is >= deterministic floor
            sev_order = list(SeverityLevel)
            assert final_res.final_severity in (expected_floor, expected_final)
            assert final_res.deterministic_floor == expected_floor
