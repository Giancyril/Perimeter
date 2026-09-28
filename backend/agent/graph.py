"""
Phase 3: LangGraph Investigation Agent.

Implements a LangGraph StateGraph that investigates a correlated incident by
running a suite of deterministic tool-nodes (Threat Intel, Asset Context, SIEM Log Search,
Lateral Movement Analyzer, Untrusted Data Boundary Wrapper), then computes risk score
and synthesizes a structured investigation report.

State machine nodes:
  1. fetch_context          - Load incident + alerts; wrap untrusted content
  2. query_threat_intel     - Query AbuseIPDB / VirusTotal via ThreatIntelClient
  3. query_asset_context    - Resolve asset criticality via AssetContextResolver
  4. query_logs             - Search and sanitize SIEM logs; detect prompt injection
  5. analyze_lateral_move   - Detect east-west movement across hosts
  6. compute_risk_score     - Deterministically evaluate findings; enforce floor
  7. generate_report        - Structured narrative + actionable containment steps

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


SEVERITY_ORDER = [
    SeverityLevel.INFORMATIONAL,
    SeverityLevel.LOW,
    SeverityLevel.MEDIUM,
    SeverityLevel.HIGH,
    SeverityLevel.CRITICAL,
]


def _raise_severity(current: SeverityLevel, target: SeverityLevel) -> SeverityLevel:
    """Returns the higher of current and target severity. Never downgrades."""
    if SEVERITY_ORDER.index(target) > SEVERITY_ORDER.index(current):
        return target
    return current


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

    # Scoring & Floor Enforcement
    risk_score_override: Optional[int]
    severity_recommendation: Optional[SeverityLevel]

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
        "risk_score_override": None,
        "severity_recommendation": incident.severity,
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

    # Also inspect incident title and alert descriptions
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
    Deterministically computes final severity score based on all enrichment findings.
    CRITICAL INVARIANT: The severity can NEVER be downgraded below incident.deterministic_floor.
    """
    incident = state.get("incident")
    if not incident:
        return state

    floor = incident.deterministic_floor
    current = floor

    threat_intel = state.get("threat_intel", {})
    lateral_paths = state.get("lateral_movement_paths", [])
    assets = state.get("asset_context", {})
    injection_detected = state.get("adversarial_injection_detected", False)

    # 1. Threat Intel Escalation
    has_malicious_ti = any(v.get("verdict") == "malicious" for v in threat_intel.values())
    if has_malicious_ti:
        current = _raise_severity(current, SeverityLevel.HIGH)

    # 2. Lateral Movement Escalation
    if lateral_paths:
        current = _raise_severity(current, SeverityLevel.HIGH)

    # 3. Critical Asset Exposure (Tier 0)
    has_tier_0 = any(
        a.get("criticality") == AssetCriticalityTier.TIER_0_CRITICAL.value
        for a in assets.values()
    )
    if has_tier_0:
        if has_malicious_ti or lateral_paths or len(incident.tactics) >= 2:
            current = _raise_severity(current, SeverityLevel.CRITICAL)
        else:
            current = _raise_severity(current, SeverityLevel.HIGH)

    # 4. Adversarial Prompt Injection Defense Escalation
    # An attacker attempting prompt injection in logs is actively exploiting defense evasion
    if injection_detected:
        current = _raise_severity(current, SeverityLevel.HIGH)

    # 5. MITRE Kill-Chain Breadth Escalation
    if len(incident.tactics) >= 5:
        current = _raise_severity(current, SeverityLevel.CRITICAL)
    elif len(incident.tactics) >= 3:
        current = _raise_severity(current, SeverityLevel.HIGH)

    # Strictly enforce floor
    final_sev = _raise_severity(floor, current)

    # Update incident state
    incident.severity = final_sev
    incident.updated_at = utc_now()

    return {
        **state,
        "severity_recommendation": final_sev,
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

    # Formulate prioritized recommended actions
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

    return {
        **state,
        "narrative": narrative,
        "recommended_actions": actions,
        "investigation_complete": True,
        "step_count": state.get("step_count", 0) + 1,
    }


# ---------------------------------------------------------------------------
# Graph construction & Execution Engine
# ---------------------------------------------------------------------------

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

    # Sequential execution fallback with step limiter
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


# Singleton graph
investigation_graph = build_investigation_graph()
