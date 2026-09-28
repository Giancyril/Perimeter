from typing import Dict, Any, List, Optional
from backend.correlation.models import CorrelatedIncident
from backend.ingestion.models import SeverityLevel
from backend.severity.models import AssetCriticalityTier
from backend.severity.models import ScoringBreakdown

SEVERITY_WEIGHTS = {
    SeverityLevel.CRITICAL: 40.0,
    SeverityLevel.HIGH: 30.0,
    SeverityLevel.MEDIUM: 20.0,
    SeverityLevel.LOW: 10.0,
    SeverityLevel.INFORMATIONAL: 5.0,
}

ASSET_MULTIPLIERS = {
    AssetCriticalityTier.TIER_0_CRITICAL.value: 1.5,
    AssetCriticalityTier.TIER_1_HIGH.value: 1.25,
    AssetCriticalityTier.TIER_2_MEDIUM.value: 1.0,
    AssetCriticalityTier.TIER_3_LOW.value: 0.8,
}

SEVERITY_ORDER = [
    SeverityLevel.INFORMATIONAL,
    SeverityLevel.LOW,
    SeverityLevel.MEDIUM,
    SeverityLevel.HIGH,
    SeverityLevel.CRITICAL,
]


def max_severity(sev1: SeverityLevel, sev2: SeverityLevel) -> SeverityLevel:
    if SEVERITY_ORDER.index(sev2) > SEVERITY_ORDER.index(sev1):
        return sev2
    return sev1


class DeterministicScorer:
    def calculate_breakdown(
        self,
        incident: CorrelatedIncident,
        threat_intel: Optional[Dict[str, Any]] = None,
        asset_context: Optional[Dict[str, Any]] = None,
        lateral_movement_paths: Optional[List[str]] = None,
        adversarial_injection_detected: bool = False,
    ) -> ScoringBreakdown:
        threat_intel = threat_intel or {}
        asset_context = asset_context or {}
        lateral_movement_paths = lateral_movement_paths or []

        max_alert_sev = SeverityLevel.INFORMATIONAL
        for alert in incident.alerts:
            max_alert_sev = max_severity(max_alert_sev, alert.normalized_severity)

        base_sev_points = SEVERITY_WEIGHTS.get(max_alert_sev, 10.0)
        volume_bonus = min(10.0, max(0.0, (incident.alert_count - 1) * 2.0))
        base_score = min(50.0, base_sev_points + volume_bonus)

        highest_tier = AssetCriticalityTier.TIER_2_MEDIUM.value
        for asset in asset_context.values():
            tier = asset.get("criticality")
            if tier == AssetCriticalityTier.TIER_0_CRITICAL.value:
                highest_tier = AssetCriticalityTier.TIER_0_CRITICAL.value
                break
            elif tier == AssetCriticalityTier.TIER_1_HIGH.value and highest_tier != AssetCriticalityTier.TIER_0_CRITICAL.value:
                highest_tier = AssetCriticalityTier.TIER_1_HIGH.value
            elif tier == AssetCriticalityTier.TIER_3_LOW.value and highest_tier == AssetCriticalityTier.TIER_2_MEDIUM.value:
                highest_tier = AssetCriticalityTier.TIER_3_LOW.value

        asset_multiplier = ASSET_MULTIPLIERS.get(highest_tier, 1.0)

        ti_points = 0.0
        has_malicious_ti = False
        for ti in threat_intel.values():
            verdict = ti.get("verdict")
            abuse_score = ti.get("abuse_score", 0)
            malicious_eng = ti.get("malicious_engines", 0)
            if verdict == "malicious" or abuse_score >= 80 or malicious_eng >= 5:
                ti_points = max(ti_points, 25.0)
                has_malicious_ti = True
            elif verdict == "suspicious" or abuse_score >= 25 or malicious_eng >= 1:
                ti_points = max(ti_points, 12.0)

        num_tactics = len(incident.tactics)
        if num_tactics >= 5:
            mitre_multiplier = 1.5
        elif num_tactics >= 3:
            mitre_multiplier = 1.3
        elif num_tactics == 2:
            mitre_multiplier = 1.15
        else:
            mitre_multiplier = 1.0

        lateral_points = 20.0 if lateral_movement_paths else 0.0
        injection_points = 0.0  # Prompt injection is elevated to final severity by investigation agent

        raw_score = (base_score * asset_multiplier + ti_points + lateral_points + injection_points) * mitre_multiplier

        if raw_score >= 85.0:
            score_floor = SeverityLevel.CRITICAL
        elif raw_score >= 60.0:
            score_floor = SeverityLevel.HIGH
        elif raw_score >= 35.0:
            score_floor = SeverityLevel.MEDIUM
        elif raw_score >= 15.0:
            score_floor = SeverityLevel.LOW
        else:
            score_floor = SeverityLevel.INFORMATIONAL


        rule_override = None
        rule_floor = score_floor

        incident_title_lower = incident.title.lower()
        if any(w in incident_title_lower for w in ["ransomware", "mass file renaming", "canary directory", "encrypt", "wiper"]):
            rule_floor = max_severity(rule_floor, SeverityLevel.CRITICAL)
            rule_override = "Mass destructive activity pattern enforced to CRITICAL"

        if highest_tier == AssetCriticalityTier.TIER_0_CRITICAL.value and not has_malicious_ti:
            rule_floor = max_severity(rule_floor, SeverityLevel.HIGH)
            if not rule_override:
                rule_override = "Tier-0 critical asset involved - floor raised to HIGH"

        if highest_tier == AssetCriticalityTier.TIER_0_CRITICAL.value and has_malicious_ti:
            rule_floor = max_severity(rule_floor, SeverityLevel.CRITICAL)
            rule_override = "Tier-0 Asset exposure to confirmed malicious external IOC"

        if adversarial_injection_detected:
            rule_floor = max_severity(rule_floor, SeverityLevel.HIGH)
            if not rule_override:
                rule_override = "Active adversarial prompt injection detected (Defense Evasion T1027)"

        if lateral_movement_paths:
            rule_floor = max_severity(rule_floor, SeverityLevel.HIGH)
            if not rule_override:
                rule_override = "Multi-host lateral movement confirmed"


        final_floor = max_severity(score_floor, rule_floor)
        final_floor = max_severity(final_floor, incident.deterministic_floor)

        return ScoringBreakdown(
            base_score=round(base_score, 2),
            asset_multiplier=asset_multiplier,
            threat_intel_points=ti_points,
            mitre_multiplier=mitre_multiplier,
            lateral_movement_points=lateral_points,
            adversarial_injection_points=injection_points,
            raw_calculated_score=round(raw_score, 2),
            deterministic_floor=final_floor,
            rule_floor_override=rule_override,
        )

deterministic_scorer = DeterministicScorer()


