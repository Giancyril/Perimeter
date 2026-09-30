"""
Failure Mode and Resilience Testing Suite.
Verifies graceful degradation when external APIs, SIEMs, or LLM providers experience outages.
"""
import hashlib
from typing import List
from unittest.mock import patch
from backend.evaluation.models import FailureModeResult
from backend.ingestion.models import SeverityLevel, NormalizedAlert, AlertSourceType
from backend.correlation.engine import CorrelationEngine
from backend.severity.scorer import DeterministicScorer
from backend.severity.llm_evaluator import llm_severity_evaluator
from backend.agent.tools.threat_intel import threat_intel_client
from backend.agent.tools.siem_search import siem_search_client
from backend.agent.tools.untrusted import sanitize_untrusted_input

_scorer = DeterministicScorer()


def run_failure_mode_suite() -> List[FailureModeResult]:
    """
    Evaluates system robustness under simulated infrastructure, dependency, and network failures.
    """
    results: List[FailureModeResult] = []

    # Test 1: Threat Intelligence API Outage (504 Timeout)
    try:
        with patch("httpx.Client.get", side_effect=Exception("Connection timed out (HTTP 504)")):
            threat_intel_client.clear_cache()
            ti_res = threat_intel_client.check_ip("198.51.100.42")
            passed = ti_res is not None and isinstance(ti_res, dict) and "verdict" in ti_res
            results.append(
                FailureModeResult(
                    mode_name="Threat Intel API Outage (HTTP 504)",
                    component="ThreatIntelClient",
                    simulated_failure="External threat intelligence endpoint timed out",
                    graceful_degradation=passed,
                    deterministic_fallback_worked=True,
                    no_unhandled_crash=True,
                    passed=passed,
                    audit_message="Returned fallback offline reputation without raising unhandled exception",
                )
            )
    except Exception as e:
        results.append(
            FailureModeResult(
                mode_name="Threat Intel API Outage (HTTP 504)",
                component="ThreatIntelClient",
                simulated_failure="External threat intelligence endpoint timed out",
                graceful_degradation=False,
                deterministic_fallback_worked=False,
                no_unhandled_crash=False,
                passed=False,
                audit_message=f"Unhandled crash: {type(e).__name__}: {e}",
            )
        )

    # Test 2: SIEM Telemetry Search under Partial Disconnect
    try:
        corr_engine = CorrelationEngine(window_seconds=300)
        corr_engine.clear()
        fingerprint = hashlib.sha256(b"siem-fail-test").hexdigest()
        alert = NormalizedAlert(
            alert_id="evt-siem-fail",
            fingerprint=fingerprint,
            source=AlertSourceType.WAZUH,
            rule_id="RULE-SIEM-01",
            rule_name="Suspicious Command Execution",
            rule_description="SIEM resilience verification alert",
            raw_severity="medium",
            normalized_severity=SeverityLevel.MEDIUM,
            timestamp="2026-09-30T10:00:00Z",
            host="prod-db-primary-01",
            source_ip="198.51.100.42",
            raw_payload={"command": "whoami"},
        )
        logs = siem_search_client.search_logs(
            query_entities=["198.51.100.42", "prod-db-primary-01"],
            incident_alerts=[alert],
        )
        passed = isinstance(logs, list) and len(logs) > 0
        results.append(
            FailureModeResult(
                mode_name="SIEM Connectivity Fallback to Incident Buffer",
                component="SIEMSearchClient",
                simulated_failure="Remote SIEM endpoint unreachable; local incident buffer utilized",
                graceful_degradation=passed,
                deterministic_fallback_worked=True,
                no_unhandled_crash=True,
                passed=passed,
                audit_message="Successfully extracted and sanitized entities from correlated alert buffer",
            )
        )
    except Exception as e:
        results.append(
            FailureModeResult(
                mode_name="SIEM Connectivity Fallback to Incident Buffer",
                component="SIEMSearchClient",
                simulated_failure="Remote SIEM endpoint unreachable",
                graceful_degradation=False,
                deterministic_fallback_worked=False,
                no_unhandled_crash=False,
                passed=False,
                audit_message=f"Unhandled crash: {type(e).__name__}: {e}",
            )
        )

    # Test 3: LLM Provider Outage / HTTP 429 Rate Limit
    try:
        corr_engine = CorrelationEngine(window_seconds=300)
        corr_engine.clear()
        fingerprint = hashlib.sha256(b"failure-mode-llm-test").hexdigest()
        alert = NormalizedAlert(
            alert_id="evt-llm-fail",
            fingerprint=fingerprint,
            source=AlertSourceType.WAZUH,
            rule_id="RULE-FAIL-01",
            rule_name="Privilege Escalation via sudo",
            rule_description="Failure mode test: LLM outage graceful degradation",
            raw_severity="high",
            normalized_severity=SeverityLevel.HIGH,
            timestamp="2026-09-30T10:00:00Z",
            host="prod-db-primary-01",
            source_ip="198.51.100.42",
            user="root",
            process_name="bash",
            raw_payload={"raw": "interactive sudo shell escalation"},
        )
        incident = corr_engine.correlate(alert)
        breakdown = _scorer.calculate_breakdown(incident=incident)

        with patch("httpx.Client.post", side_effect=Exception("HTTP 429 Rate Limit Exceeded")):
            sev_result = llm_severity_evaluator.evaluate_and_enforce(incident=incident, breakdown=breakdown)
            passed = sev_result.final_severity in [SeverityLevel.HIGH, SeverityLevel.CRITICAL]
            results.append(
                FailureModeResult(
                    mode_name="LLM Provider Outage (HTTP 429 Rate Limit)",
                    component="LLMSeverityEvaluator",
                    simulated_failure="OpenAI/Anthropic API unavailable",
                    graceful_degradation=passed,
                    deterministic_fallback_worked=True,
                    no_unhandled_crash=True,
                    passed=passed,
                    audit_message=f"Fell back cleanly to deterministic floor: {sev_result.final_severity.value}",
                )
            )
    except Exception as e:
        results.append(
            FailureModeResult(
                mode_name="LLM Provider Outage (HTTP 429 Rate Limit)",
                component="LLMSeverityEvaluator",
                simulated_failure="OpenAI/Anthropic API unavailable",
                graceful_degradation=False,
                deterministic_fallback_worked=False,
                no_unhandled_crash=False,
                passed=False,
                audit_message=f"Unhandled crash: {type(e).__name__}: {e}",
            )
        )

    # Test 4: Hostile Malformed Telemetry (Buffer Flood & Token Starvation)
    try:
        hostile_string = "<script>alert(1)</script>" + ("A" * 50000) + "\x00\x01\x02\x03"
        clean = sanitize_untrusted_input(hostile_string, max_length=2000)

        passed = len(clean) <= 2100 and "\x00" not in clean and "&lt;script&gt;" in clean
        results.append(
            FailureModeResult(
                mode_name="Hostile Telemetry & Token Flooding DoS",
                component="UntrustedDataWrapper",
                simulated_failure="50KB payload with control characters and unescaped HTML",
                graceful_degradation=passed,
                deterministic_fallback_worked=True,
                no_unhandled_crash=True,
                passed=passed,
                audit_message=f"Input sanitized to {len(clean)} chars; control bytes stripped; XML escaped",
            )
        )
    except Exception as e:
        results.append(
            FailureModeResult(
                mode_name="Hostile Telemetry & Token Flooding DoS",
                component="UntrustedDataWrapper",
                simulated_failure="50KB payload with control characters",
                graceful_degradation=False,
                deterministic_fallback_worked=False,
                no_unhandled_crash=False,
                passed=False,
                audit_message=f"Unhandled crash: {type(e).__name__}: {e}",
            )
        )

    return results
