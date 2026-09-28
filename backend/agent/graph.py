"""
Phase 3, Phase 4 & Phase 5: LangGraph Investigation Agent with Hybrid Severity Scoring and Evidence-Linked Report Generation.

Implements a LangGraph StateGraph that investigates a correlated incident by
running a suite of deterministic tool-nodes (Threat Intel, Asset Context, SIEM Log Search,
Lateral Movement Analyzer, Untrusted Data Boundary Wrapper), computes hybrid risk scores
via DeterministicScorer and LLMSeverityEvaluator, and strictly enforces the non-downgradable
severity floor invariant before synthesizing an auditable incident report.

Safety invariants enforced in code:
  - Severity is strictly clamped to >= deterministic_floor (CANNOT be downgraded)
  - All log content is sanitized and wrapped as passive data (prevents prompt injection)
  - Adversarial prompt injection attempts are detected and flagged as malicious indicators
  - Step limiters prevent infinite graph execution loops
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, TypedDict
from enum import Enum

try:
    from langgraph.graph import StateGraph, END  # type: ignore
    _LANGGRAPH_AVAILABLE = True
except ImportError:
    _LANGGRAPH_AVAILABLE = False

from backend.correlation.models import CorrelatedIncident, IncidentStatus
from backend.ingestion.models import SeverityLevel, utc_now
from backend.agent.tools.threat_intel import threat_intel_client
from backend.agent.tools.asset_context import asset_context_resolver, AssetCriticalityTier
from backend.agent.tools.siem_search import siem_search_client
from backend.agent.tools.untrusted import (
    sanitize_untrusted_input,
    wrap_untrusted_data,
    detect_prompt_injection,
)
from backend.severity import (
    deterministic_scorer,
    llm_severity_evaluator,
    max_severity,
)
from backend.reporting import build_report, render_markdown, IncidentReport


# ---------------------------------------------------------------------------
# Agent State Schema
# ---------------------------------------------------------------------------

class InvestigationState(TypedDict, total=False):
    """Typed state threaded through every node in the investigation graph."""
    incident_id: str
    incident: Optional[CorrelatedIncident]

    # Tool outputs (deterministic, structured data)
    threat_intel: Dict[str, Any]
    asset_context: Dict[str, Any]
    log_evidence: List[Dict[str, Any]]
    lateral_movement_paths: List[str]

    # Security & Prompt Injection Defense
    adversarial_injection_detected: bool
    adversarial_injection_reason: Optional[str]

    # Phase 4: Scoring & Floor Enforcement
    scoring_breakdown: Optional[Dict[str, Any]]
    floor_enforced: bool
    audit_note: Optional[str]
    risk_score_override: Optional[int]
    severity_recommendation: Optional[SeverityLevel]

    # Phase 5: Structured Evidence-Linked Report
    incident_report: Optional[IncidentReport]
    report_markdown: Optional[str]

    # Report & Containment Actions
    narrative: str
    recommended_actions: List[str]

    # Execution controls
    step_count: int
    max_steps: int
    investigation_complete: bool
    error: Optional[str]


# ---------------------------------------------------------------------------
# Node implementations
# ---------------------------------------------------------------------------

def node_fetch_context(state: InvestigationState) -> InvestigationState:
    """Loads the full CorrelatedIncident from the correlation store."""
    from backend.correlation.engine import correlation_engine

    incident_id = state.get("incident_id", "")
    incident = correlation_engine.get_incident(incident_id)

    if not incident:
        return {
            **state,
            "error": f"Incident '{incident_id}' not found in correlation store",
            "investigation_complete": True,
            "step_count": state.get("step_count", 0) + 1,
        }

    return {
        **state,
        "incident": incident,
        "threat_intel": {},
        "asset_context": {},
        "log_evidence": [],
        "lateral_movement_paths": [],
        "adversarial_injection_detected": False,
        "adversarial_injection_reason": None,
        "scoring_breakdown": None,
        "floor_enforced": False,
        "audit_note": None,
        "risk_score_override": None,
        "severity_recommendation": incident.severity,
        "incident_report": None,
        "report_markdown": None,
        "narrative": "",
        "recommended_actions": [],
        "step_count": state.get("step_count", 0) + 1,
        "max_steps": state.get("max_steps", 20),
        "investigation_complete": False,
        "error": None,
    }


def node_query_threat_intel(state: InvestigationState) -> InvestigationState:
    """Enriches IP and hash entities with threat-intelligence verdicts."""
    incident = state.get("incident")
    if not incident:
        return state

    threat_intel: Dict[str, Any] = {}
    for entity in incident.entities:
        val = entity.value
        if entity.type.value == "ip":
            threat_intel[val] = threat_intel_client.check_ip(val)
        elif entity.type.value in ("hash", "file_hash"):
            threat_intel[val] = threat_intel_client.check_hash(val)

    return {
        **state,
        "threat_intel": threat_intel,
        "step_count": state.get("step_count", 0) + 1,
    }


def node_query_asset_context(state: InvestigationState) -> InvestigationState:
    """Resolves asset criticality and business role for involved hosts and primary entities."""
    incident = state.get("incident")
    if not incident:
        return state

    asset_map: Dict[str, Any] = {}
    targets = set()
    if incident.primary_entity:
        targets.add(incident.primary_entity)

    for entity in incident.entities:
        if entity.type.value in ("host", "hostname", "server"):
            targets.add(entity.value)

    for target in targets:
        ctx = asset_context_resolver.resolve(target)
        asset_map[target] = ctx.model_dump()

    return {
        **state,
        "asset_context": asset_map,
        "step_count": state.get("step_count", 0) + 1,
    }


def node_query_logs(state: InvestigationState) -> InvestigationState:
    """
    Retrieves and sanitizes SIEM logs across the incident's time window.
    Applies adversarial prompt-injection detection to all incoming log content.
    """
    incident = state.get("incident")
    if not incident:
        return state

    entities = [e.value for e in incident.entities]
    logs = siem_search_client.search_logs(
        query_entities=entities,
        window_start=incident.window_start,
        window_end=incident.window_end,
        limit=50,
        incident_alerts=incident.alerts,
    )

    injection_found = False
    injection_reason = None
    for entry in logs:
        if entry.get("adversarial_injection_detected"):
            injection_found = True
            injection_reason = entry.get("adversarial_injection_reason")
            break

    if not injection_found:
        has_inj, rsn = detect_prompt_injection(incident.title)
        if has_inj:
            injection_found, injection_reason = True, rsn
        else:
            for alert in incident.alerts:
                has_inj, rsn = detect_prompt_injection(str(alert.raw_payload))
                if has_inj:
                    injection_found, injection_reason = True, rsn
                    break

    return {
        **state,
        "log_evidence": logs,
        "adversarial_injection_detected": injection_found,
        "adversarial_injection_reason": injection_reason,
        "step_count": state.get("step_count", 0) + 1,
    }


def node_analyze_lateral_movement(state: InvestigationState) -> InvestigationState:
    """Detects lateral movement patterns (e.g. single source IP hitting multiple hosts)."""
    incident = state.get("incident")
    log_evidence = state.get("log_evidence", [])
    paths: List[str] = []

    src_to_hosts: Dict[str, set] = {}
    for entry in log_evidence:
        src = entry.get("source_ip")
        host = entry.get("host")
        if src and host:
            src_to_hosts.setdefault(src, set()).add(host)

    for src, hosts in src_to_hosts.items():
        if len(hosts) > 1:
            paths.append(f"{src} -> {', '.join(sorted(hosts))} ({len(hosts)} hosts)")

    return {
        **state,
        "lateral_movement_paths": paths,
        "step_count": state.get("step_count", 0) + 1,
    }


def node_compute_risk_score(state: InvestigationState) -> InvestigationState:
    """
    Deterministically computes final severity score using Phase 4 hybrid scoring.
    CRITICAL INVARIANT: The severity can NEVER be downgraded below incident.deterministic_floor.
    """
    incident = state.get("incident")
    if not incident:
        return state

    threat_intel = state.get("threat_intel", {})
    lateral_paths = state.get("lateral_movement_paths", [])
    assets = state.get("asset_context", {})
    injection_detected = state.get("adversarial_injection_detected", False)

    # 1. Deterministic formula breakdown
    breakdown = deterministic_scorer.calculate_breakdown(
        incident=incident,
        threat_intel=threat_intel,
        asset_context=assets,
        lateral_movement_paths=lateral_paths,
        adversarial_injection_detected=injection_detected,
    )

    # 2. LLM reasoning + Strict Floor Enforcement
    final_res = llm_severity_evaluator.evaluate_and_enforce(
        incident=incident,
        breakdown=breakdown,
        threat_intel=threat_intel,
        asset_context=assets,
        adversarial_injection_detected=injection_detected,
    )

    incident.updated_at = utc_now()

    return {
        **state,
        "scoring_breakdown": breakdown.model_dump(),
        "floor_enforced": final_res.floor_enforced,
        "audit_note": final_res.audit_note,
        "severity_recommendation": final_res.final_severity,
        "step_count": state.get("step_count", 0) + 1,
    }


def node_generate_report(state: InvestigationState) -> InvestigationState:
    """Synthesizes structured investigation narrative, containment actions, and audit trail."""
    incident = state.get("incident")
    if not incident:
        return {**state, "investigation_complete": True}

    threat_intel = state.get("threat_intel", {})
    assets = state.get("asset_context", {})
    lateral_paths = state.get("lateral_movement_paths", [])
    log_evidence = state.get("log_evidence", [])
    injection_detected = state.get("adversarial_injection_detected", False)
    injection_reason = state.get("adversarial_injection_reason")
    breakdown = state.get("scoring_breakdown", {})
    floor_enforced = state.get("floor_enforced", False)
    audit_note = state.get("audit_note")

    malicious_entities = [k for k, v in threat_intel.items() if v.get("verdict") == "malicious"]
    critical_assets = [k for k, v in assets.items() if v.get("criticality") == AssetCriticalityTier.TIER_0_CRITICAL.value]

    lines = [
        "# Security Incident Investigation Report",
        "",
        f"**Incident ID**: {incident.incident_id}",
        f"**Title**: {incident.title}",
        f"**Final Severity**: {incident.severity.value.upper()} (Enforced Floor: {incident.deterministic_floor.value.upper()})",
        f"**Status**: {IncidentStatus.INVESTIGATING.value}",
        f"**Time Window**: {incident.window_start} -> {incident.window_end}",
        "",
        "## Severity Scoring & Invariants",
        f"- Enforced Floor: {incident.deterministic_floor.value.upper()}",
        f"- Floor Enforcement Active: {'YES (Downgrade Blocked)' if floor_enforced else 'No (Baseline Maintained)'}",
    ]
    if audit_note:
        lines.append(f"- Audit Note: {audit_note}")
    if breakdown:
        lines += [
            f"- Base Score: {breakdown.get('base_score')}",
            f"- Asset Multiplier: {breakdown.get('asset_multiplier')}x",
            f"- Threat Intel Points: +{breakdown.get('threat_intel_points')}",
            f"- MITRE Multiplier: {breakdown.get('mitre_multiplier')}x",
            f"- Lateral Movement Points: +{breakdown.get('lateral_movement_points')}",
            f"- Composite Raw Score: {breakdown.get('raw_calculated_score')}",
        ]

    lines += [
        "",
        "## Adversarial Prompt Injection Defense",
        f"- Injection Attempt Detected: {'YES (BLOCKED)' if injection_detected else 'No'}",
    ]
    if injection_detected:
        lines.append(f"  - Details: {injection_reason}")
        lines.append("  - Action Taken: Attacker prompt neutralized via untrusted boundary wrapper; severity elevated.")

    lines += [
        "",
        "## Kill-Chain & ATT&CK Mapping",
        f"- Tactics ({len(incident.tactics)}): {', '.join(incident.tactics) or 'None'}",
        f"- Techniques: {', '.join(incident.techniques) or 'None'}",
        f"- Attack chain span: {incident.attack_chain_span} stage(s)",
        "",
        "## Threat Intelligence & Entity Enrichment",
        f"- Entities Analyzed: {len(incident.entities)}",
        f"- Malicious IOCs Detected: {len(malicious_entities)}",
    ]
    for e in malicious_entities:
        ti = threat_intel[e]
        lines.append(f"  - [MALICIOUS] {e} (source: {ti.get('source')}, abuse score: {ti.get('abuse_score')})")

    if critical_assets:
        lines += [
            "",
            "## Critical Assets Involved (Tier-0)",
        ]
        for ca in critical_assets:
            a_ctx = assets[ca]
            lines.append(f"  - {ca}: {a_ctx.get('role_description')} (Owner: {a_ctx.get('owner')})")

    if lateral_paths:
        lines += [
            "",
            "## Lateral Movement Analysis",
            "Potential lateral movement hops detected:",
        ]
        for p in lateral_paths:
            lines.append(f"  - {p}")

    lines += [
        "",
        "## Evidence & Audit Summary",
        f"- Correlated Alerts: {incident.alert_count}",
        f"- Log Evidence Records: {len(log_evidence)}",
    ]

    narrative = "\n".join(lines)

    actions: List[str] = []
    sev = incident.severity
    if sev == SeverityLevel.CRITICAL:
        actions.append("IMMEDIATE: Isolate compromised host(s) from corporate network")
        actions.append("IMMEDIATE: Escalate to On-Call Incident Commander and CISO")
    if sev in [SeverityLevel.CRITICAL, SeverityLevel.HIGH]:
        if malicious_entities:
            actions.append(f"Block malicious IOCs at perimeter firewall: {', '.join(malicious_entities)}")
        actions.append("Preserve forensic memory and disk images of affected systems")
        actions.append("Revoke active user sessions and force credential rotation")
    if lateral_paths:
        actions.append("Enact internal micro-segmentation rules to halt east-west propagation")
    if injection_detected:
        actions.append("Log adversarial prompt injection signature to WAF and SIEM correlation rules")
    actions.append("Close loop: verify eradication and update detection signatures")

    incident.status = IncidentStatus.INVESTIGATING
    incident.updated_at = utc_now()

    # ---- Phase 5: Build structured evidence-linked report ----
    new_state = {
        **state,
        "narrative": narrative,
        "recommended_actions": actions,
        "investigation_complete": True,
        "step_count": state.get("step_count", 0) + 1,
    }
    try:
        report_obj = build_report(new_state)
        md_report = render_markdown(report_obj)
        new_state["incident_report"] = report_obj
        new_state["report_markdown"] = md_report
    except Exception as exc:
        # Report generation failure must NEVER halt the investigation
        new_state["audit_note"] = (
            (new_state.get("audit_note") or "") +
            f" [ReportBuildError: {exc}]"
        )
    return new_state


def _route_after_fetch(state: InvestigationState) -> str:
    """Route to END if fetch_context encountered an error or max steps exceeded."""
    if state.get("error") or state.get("step_count", 0) >= state.get("max_steps", 20):
        return END
    return "query_threat_intel"


def build_investigation_graph():
    """Constructs and compiles the LangGraph StateGraph for incident investigation."""
    if not _LANGGRAPH_AVAILABLE:
        return None

    graph = StateGraph(InvestigationState)

    graph.add_node("fetch_context", node_fetch_context)
    graph.add_node("query_threat_intel", node_query_threat_intel)
    graph.add_node("query_asset_context", node_query_asset_context)
    graph.add_node("query_logs", node_query_logs)
    graph.add_node("analyze_lateral_movement", node_analyze_lateral_movement)
    graph.add_node("compute_risk_score", node_compute_risk_score)
    graph.add_node("generate_report", node_generate_report)

    graph.set_entry_point("fetch_context")

    graph.add_conditional_edges("fetch_context", _route_after_fetch)
    graph.add_edge("query_threat_intel", "query_asset_context")
    graph.add_edge("query_asset_context", "query_logs")
    graph.add_edge("query_logs", "analyze_lateral_movement")
    graph.add_edge("analyze_lateral_movement", "compute_risk_score")
    graph.add_edge("compute_risk_score", "generate_report")
    graph.add_edge("generate_report", END)

    return graph.compile()


def investigate_incident(incident_id: str, max_steps: int = 20) -> InvestigationState:
    """
    Public entry point: runs the full investigation pipeline for an incident.
    Uses compiled LangGraph StateGraph if available, or sequential step-limited fallback.
    """
    graph = build_investigation_graph()
    initial_state: InvestigationState = {
        "incident_id": incident_id,
        "step_count": 0,
        "max_steps": max_steps,
    }

    if graph:
        return graph.invoke(initial_state)

    state = initial_state
    pipeline = [
        node_fetch_context,
        node_query_threat_intel,
        node_query_asset_context,
        node_query_logs,
        node_analyze_lateral_movement,
        node_compute_risk_score,
        node_generate_report,
    ]

    for node_fn in pipeline:
        state = node_fn(state)
        if state.get("investigation_complete") or state.get("error"):
            break
        if state.get("step_count", 0) >= state.get("max_steps", 20):
            state["investigation_complete"] = True
            state["error"] = "Investigation halted: maximum execution steps reached."
            break

    return state


investigation_graph = build_investigation_graph()
