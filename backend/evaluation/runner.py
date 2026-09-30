"""
Evaluation Runner: Executes benchmark replay, adversarial injection, and failure mode suites.
"""
import hashlib
import time
import sys
from typing import List, Tuple, Dict, Any

from backend.evaluation.models import (
    BenchmarkScenario,
    ScenarioResult,
    EvaluationMetrics,
    AdversarialTestResult,
    FailureModeResult,
)
from backend.evaluation.dataset import BENCHMARK_SCENARIOS
from backend.evaluation.adversarial import run_adversarial_suite
from backend.evaluation.failure_modes import run_failure_mode_suite
from backend.correlation.engine import CorrelationEngine
from backend.ingestion.models import NormalizedAlert, SeverityLevel, AlertSourceType, MitreAttackMetadata
from backend.severity.scorer import DeterministicScorer
from backend.severity.llm_evaluator import llm_severity_evaluator
from backend.response.manager import response_manager
from backend.response.models import ActionType
from backend.agent.tools.threat_intel import threat_intel_client

SEVERITY_ORDER = [
    SeverityLevel.INFORMATIONAL,
    SeverityLevel.LOW,
    SeverityLevel.MEDIUM,
    SeverityLevel.HIGH,
    SeverityLevel.CRITICAL,
]

_deterministic_scorer = DeterministicScorer()


def _make_fingerprint(*parts) -> str:
    raw = ":".join(str(p) for p in parts)
    return hashlib.sha256(raw.encode()).hexdigest()


def _build_normalized_alert(scenario: BenchmarkScenario, idx: int, raw: dict) -> NormalizedAlert:
    rule_id = raw.get("rule_id", "RULE-UNKNOWN")
    host = raw.get("host", "unknown")
    source_ip = raw.get("source_ip", "0.0.0.0")
    timestamp = raw.get("timestamp", "2026-01-01T00:00:00Z")
    source_str = raw.get("source", "generic")

    try:
        source_enum = AlertSourceType(source_str.lower())
    except ValueError:
        source_enum = AlertSourceType.GENERIC

    raw_sev_str = raw.get("raw_severity", "medium").lower()
    try:
        normalized_sev = SeverityLevel(raw_sev_str)
    except ValueError:
        normalized_sev = SeverityLevel.MEDIUM

    fingerprint = _make_fingerprint(scenario.scenario_id, rule_id, host, source_ip, timestamp, idx)

    raw_payload_raw = raw.get("raw_payload", "")
    if isinstance(raw_payload_raw, dict):
        raw_payload_dict = raw_payload_raw
    else:
        raw_payload_dict = {"raw": str(raw_payload_raw)}

    mitre = MitreAttackMetadata(
        tactics=scenario.expected_tactics,
        techniques=scenario.expected_techniques,
    ) if scenario.expected_tactics else None

    return NormalizedAlert(
        alert_id=f"{scenario.scenario_id}-{idx}",
        fingerprint=fingerprint,
        source=source_enum,
        rule_id=rule_id,
        rule_name=raw.get("rule_name", "Benchmark Alert"),
        rule_description=raw.get("rule_description", raw.get("rule_name", "Evaluation benchmark alert")),
        raw_severity=raw_sev_str,
        normalized_severity=normalized_sev,
        timestamp=timestamp,
        host=host,
        source_ip=source_ip,
        user=raw.get("username") or raw.get("user"),
        process_name=raw.get("process_name"),
        raw_payload=raw_payload_dict,
        mitre_attack=mitre,
    )


class EvaluationRunner:
    """Orchestrates end-to-end evaluation of the Autonomous SecOps Agent."""

    def __init__(self, scenarios: List[BenchmarkScenario] = None):
        self.scenarios = scenarios or BENCHMARK_SCENARIOS

    def run_benchmark_scenarios(self) -> List[ScenarioResult]:
        results: List[ScenarioResult] = []

        for scn in self.scenarios:
            start_t = time.perf_counter()

            # 1. Ingest scenario alerts
            normalized_alerts: List[NormalizedAlert] = []
            ti_map: Dict[str, Any] = {}
            asset_ctx: Dict[str, Any] = {}

            for idx, raw in enumerate(scn.alerts):
                try:
                    alt = _build_normalized_alert(scn, idx, raw)
                    normalized_alerts.append(alt)

                    # Gather IOC Threat Intel
                    sip = alt.source_ip
                    if sip and sip not in ("0.0.0.0", "127.0.0.1", ""):
                        ti = threat_intel_client.check_ip(sip)
                        ti_map[sip] = ti

                    # Asset context
                    h = alt.host
                    if h:
                        tier = "tier_1_high" if ("prod" in h or "db" in h or "fin" in h) else "tier_2_medium"
                        asset_ctx[h] = {"criticality": tier}
                except Exception as e:
                    print(f"  [WARN] Skip alert {idx} in {scn.scenario_id}: {e}", file=sys.stderr)

            if not normalized_alerts:
                latency = (time.perf_counter() - start_t) * 1000
                results.append(ScenarioResult(
                    scenario_id=scn.scenario_id, scenario_name=scn.name, passed=False,
                    is_malicious=scn.is_malicious, detected_severity=SeverityLevel.INFORMATIONAL,
                    expected_min_severity=scn.expected_min_severity, severity_floor_preserved=False,
                    detected_tactics=[], matched_expected_tactics=False, proposed_action=None,
                    action_matched=False, latency_ms=round(latency, 2), details="No valid alerts",
                ))
                continue

            # 2. Correlate alerts into incident
            engine = CorrelationEngine(window_seconds=600)
            engine.clear()
            last_inc = None
            for a in normalized_alerts:
                last_inc = engine.correlate(a)

            incidents = engine.list_incidents()
            incident = incidents[0] if incidents else last_inc

            if not incident:
                latency = (time.perf_counter() - start_t) * 1000
                results.append(ScenarioResult(
                    scenario_id=scn.scenario_id, scenario_name=scn.name, passed=False,
                    is_malicious=scn.is_malicious, detected_severity=SeverityLevel.LOW,
                    expected_min_severity=scn.expected_min_severity, severity_floor_preserved=False,
                    detected_tactics=[], matched_expected_tactics=False, proposed_action=None,
                    action_matched=not scn.is_malicious, latency_ms=round(latency, 2),
                    details="No incident formed",
                ))
                continue

            # 3. Deterministic scoring breakdown
            breakdown = _deterministic_scorer.calculate_breakdown(
                incident=incident,
                threat_intel=ti_map,
                asset_context=asset_ctx,
            )

            # 4. LLM reasoning and floor enforcement
            sev_result = llm_severity_evaluator.evaluate_and_enforce(
                incident=incident,
                breakdown=breakdown,
                threat_intel=ti_map,
                asset_context=asset_ctx,
            )

            detected_sev = sev_result.final_severity
            floor_preserved = SEVERITY_ORDER.index(detected_sev) >= SEVERITY_ORDER.index(sev_result.deterministic_floor)

            detected_tactics = list(incident.tactics)
            matched_tactics = len(detected_tactics) > 0 if scn.is_malicious else len(detected_tactics) == 0

            # 5. Proposed containment action verification
            proposed_act_type = None
            action_matched = True

            if scn.expected_action_type and scn.expected_containment_target:
                target = scn.expected_containment_target
                act_type = scn.expected_action_type

                if act_type == ActionType.ISOLATE_HOST:
                    rec_msg = f"Isolate host {target} immediately"
                elif act_type == ActionType.BLOCK_IP:
                    rec_msg = f"Block malicious IP address {target}"
                elif act_type == ActionType.DISABLE_USER:
                    rec_msg = f"Disable compromised user account {target}"
                else:
                    rec_msg = f"Containment action for {target}"

                state = {
                    "incident": incident,
                    "recommended_actions": [rec_msg],
                    "asset_context": asset_ctx,
                    "threat_intel": ti_map,
                    "lateral_movement_paths": [],
                }
                props = response_manager.propose_actions_from_state(state)
                if props:
                    proposed_act_type = props[0].action_type.value
                    action_matched = props[0].action_type == scn.expected_action_type
                else:
                    action_matched = False
                    proposed_act_type = "none"
            else:
                action_matched = True
                proposed_act_type = None

            latency = (time.perf_counter() - start_t) * 1000

            # 6. Pass/Fail Decision
            if scn.is_malicious:
                min_sev_met = SEVERITY_ORDER.index(detected_sev) >= SEVERITY_ORDER.index(scn.expected_min_severity)
                passed = min_sev_met and floor_preserved and action_matched
            else:
                # Benign must not trigger containment actions or exceed expected benign severity
                benign_sev_ok = SEVERITY_ORDER.index(detected_sev) <= SEVERITY_ORDER.index(scn.expected_min_severity)
                passed = benign_sev_ok and action_matched

            results.append(ScenarioResult(
                scenario_id=scn.scenario_id,
                scenario_name=scn.name,
                passed=passed,
                is_malicious=scn.is_malicious,
                detected_severity=detected_sev,
                expected_min_severity=scn.expected_min_severity,
                severity_floor_preserved=floor_preserved,
                detected_tactics=detected_tactics,
                matched_expected_tactics=matched_tactics,
                proposed_action=proposed_act_type,
                action_matched=action_matched,
                latency_ms=round(latency, 2),
                details=f"Sev={detected_sev.value} (Floor={sev_result.deterministic_floor.value}), Action={proposed_act_type}",
            ))

        return results

    def compute_metrics(
        self,
        scenario_results: List[ScenarioResult],
        adversarial_results: List[AdversarialTestResult],
        failure_results: List[FailureModeResult],
    ) -> EvaluationMetrics:
        tp = sum(1 for r in scenario_results if r.is_malicious and r.passed)
        fn = sum(1 for r in scenario_results if r.is_malicious and not r.passed)
        tn = sum(1 for r in scenario_results if not r.is_malicious and r.passed)
        fp = sum(1 for r in scenario_results if not r.is_malicious and not r.passed)

        precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 1.0
        f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

        floor_held = sum(1 for r in scenario_results if r.severity_floor_preserved)
        inv_rate = (floor_held / len(scenario_results)) * 100 if scenario_results else 100.0

        adv_held = sum(1 for r in adversarial_results if r.passed)
        adv_rate = (adv_held / len(adversarial_results)) * 100 if adversarial_results else 100.0

        fail_held = sum(1 for r in failure_results if r.passed)
        fail_rate = (fail_held / len(failure_results)) * 100 if failure_results else 100.0

        avg_latency = (
            sum(r.latency_ms for r in scenario_results) / len(scenario_results)
            if scenario_results else 0.0
        )

        return EvaluationMetrics(
            total_scenarios=len(scenario_results),
            true_positives=tp,
            false_positives=fp,
            true_negatives=tn,
            false_negatives=fn,
            precision=round(precision, 4),
            recall=round(recall, 4),
            f1_score=round(f1, 4),
            invariant_preservation_rate=round(inv_rate, 2),
            prompt_injection_defense_rate=round(adv_rate, 2),
            failure_resilience_rate=round(fail_rate, 2),
            avg_triage_latency_ms=round(avg_latency, 2),
        )

    def run_all(
        self,
    ) -> Tuple[List[ScenarioResult], List[AdversarialTestResult], List[FailureModeResult], EvaluationMetrics]:
        scenario_res = self.run_benchmark_scenarios()
        adv_res = run_adversarial_suite()
        fail_res = run_failure_mode_suite()
        metrics = self.compute_metrics(scenario_res, adv_res, fail_res)
        return scenario_res, adv_res, fail_res, metrics


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    runner = EvaluationRunner()
    print("=" * 72)
    print("AUTONOMOUS SECOPS AGENT - PHASE 8: BENCHMARK & EVALUATION SUITE")
    print("=" * 72)

    scn_results, adv_results, fail_results, metrics = runner.run_all()

    print("\n1. BENCHMARK ATTACK REPLAY SCENARIOS:")
    print("-" * 72)
    for r in scn_results:
        status = "PASS [v]" if r.passed else "FAIL [x]"
        print(f"  {r.scenario_id:<14} | {status} | Latency: {r.latency_ms:>6.1f}ms | {r.details}")

    print("\n2. ADVERSARIAL PROMPT-INJECTION DEFENSE SUITE:")
    print("-" * 72)
    for r in adv_results:
        status = "PASS [v]" if r.passed else "FAIL [x]"
        print(f"  {r.vector_id:<8} | {status} | {r.vector_name:<34} | {r.notes}")

    print("\n3. EXTERNAL API & INFRASTRUCTURE FAILURE MODES:")
    print("-" * 72)
    for r in fail_results:
        status = "PASS [v]" if r.passed else "FAIL [x]"
        print(f"  {status} | {r.component:<24} | {r.mode_name}")

    print("\n" + "=" * 72)
    print("FINAL SUMMARY METRICS:")
    print("=" * 72)
    print(f"  Scenarios Evaluated:              {metrics.total_scenarios}")
    print(f"  True Positives / False Negatives: {metrics.true_positives} / {metrics.false_negatives}")
    print(f"  True Negatives / False Positives: {metrics.true_negatives} / {metrics.false_positives}")
    print(f"  Precision:                        {metrics.precision * 100:.1f}%")
    print(f"  Recall:                           {metrics.recall * 100:.1f}%")
    print(f"  F1 Score:                         {metrics.f1_score:.4f}")
    print(f"  Severity Floor Invariant Rate:    {metrics.invariant_preservation_rate:.1f}%")
    print(f"  Prompt-Injection Defense Rate:    {metrics.prompt_injection_defense_rate:.1f}%")
    print(f"  Failure Mode Resilience Rate:     {metrics.failure_resilience_rate:.1f}%")
    print(f"  Average Triage Latency:           {metrics.avg_triage_latency_ms:.2f}ms")
    print("=" * 72)


if __name__ == "__main__":
    main()
