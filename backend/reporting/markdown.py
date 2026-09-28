"""
Phase 5: Markdown Report Renderer.

Converts a structured IncidentReport into a polished, SOC-grade Markdown document
suitable for Jira tickets, Confluence pages, or email escalation chains.
"""
from __future__ import annotations

from backend.reporting.models import IncidentReport, SeverityLevel


_SEVERITY_EMOJI = {
    "critical": "[CRITICAL]",
    "high": "[HIGH]",
    "medium": "[MEDIUM]",
    "low": "[LOW]",
    "informational": "[INFO]",
}

_VERDICT_EMOJI = {
    "malicious": "[MALICIOUS]",
    "suspicious": "[SUSPICIOUS]",
    "clean": "[CLEAN]",
    "unknown": "[UNKNOWN]",
}


def render_markdown(report: IncidentReport) -> str:
    """
    Render a complete Markdown investigation report from a structured IncidentReport.

    Returns:
        A multi-line Markdown string ready for writing to .md file or API response.
    """
    sev = report.final_severity.value
    floor = report.deterministic_floor.value
    sev_tag = _SEVERITY_EMOJI.get(sev, "[INFO]")
    lines = [
        f"# {sev_tag} Security Incident Report - {report.incident_id}",
        "",
        f"> **Report ID**: `{report.report_id}`  ",
        f"> **Generated**: {report.generated_at.strftime('%Y-%m-%d %H:%M:%S UTC')}  ",
        f"> **Status**: {report.status.upper()}",
        "",
        "---",
        "",
        "## Executive Summary",
        "",
    ]

    # Executive summary
    if report.executive_summary:
        summary_lines = [l for l in report.executive_summary.splitlines() if l.strip()][:6]
        lines += summary_lines
    else:
        lines.append(
            f"Investigation of **{report.incident_title}** completed. "
            f"Final severity determined as **{sev.upper()}** with deterministic floor **{floor.upper()}**."
        )

    lines += [
        "",
        "---",
        "",
        "## Severity Determination",
        "",
        f"| Metric | Value |",
        f"|--------|-------|",
        f"| **Final Severity** | {sev_tag} **{sev.upper()}** |",
        f"| **Deterministic Floor** | {_SEVERITY_EMOJI.get(floor, '[INFO]')} {floor.upper()} |",
        f"| **Floor Enforced** | {'YES - LLM downgrade blocked' if report.severity_audit.floor_enforced else 'No'} |",
        f"| **Base Score** | {report.severity_audit.base_score} |",
        f"| **Asset Multiplier** | {report.severity_audit.asset_multiplier}x |",
        f"| **Threat Intel Points** | +{report.severity_audit.threat_intel_points} |",
        f"| **MITRE Multiplier** | {report.severity_audit.mitre_multiplier}x |",
        f"| **Lateral Movement Points** | +{report.severity_audit.lateral_movement_points} |",
        f"| **Composite Raw Score** | {report.severity_audit.raw_calculated_score} |",
    ]
    if report.severity_audit.rule_override_reason:
        lines.append(f"| **Rule Override** | {report.severity_audit.rule_override_reason} |")
    if report.severity_audit.llm_reasoning:
        lines += ["", f"> **LLM Audit Note**: {report.severity_audit.llm_reasoning}"]

    # ATT&CK mapping
    lines += [
        "",
        "---",
        "",
        "## MITRE ATT&CK Mapping",
        "",
        f"- **Tactics** ({len(report.mitre_tactics)}): {', '.join(report.mitre_tactics) or 'None identified'}",
        f"- **Techniques**: {', '.join(report.mitre_techniques) or 'None identified'}",
        f"- **Attack Chain Span**: {report.attack_chain_span} stage(s)",
    ]

    # Adversarial injection
    lines += [
        "",
        "---",
        "",
        "## Adversarial Prompt Injection Defense",
        "",
        f"- **Injection Detected**: {'YES - BLOCKED' if report.adversarial_injection_detected else 'No attempt detected'}",
    ]
    if report.adversarial_injection_detected and report.adversarial_injection_reason:
        lines.append(f"- **Details**: `{report.adversarial_injection_reason}`")
        lines.append("- **Mitigation**: Attacker payload neutralised via untrusted-data boundary wrapper.")

    # Entity traceability
    lines += [
        "",
        "---",
        "",
        "## Affected Entities & Evidence Traceability",
        "",
        "| Entity | Type | Criticality | TI Verdict | Abuse Score | Evidence Events |",
        "|--------|------|-------------|------------|-------------|-----------------|",
    ]
    for ent in report.entities:
        verdict_tag = _VERDICT_EMOJI.get(ent.threat_verdict or "unknown", "[UNKNOWN]")
        lines.append(
            f"| `{ent.entity_value}` "
            f"| {ent.entity_type} "
            f"| {ent.criticality or 'N/A'} "
            f"| {verdict_tag} {ent.threat_verdict or 'unknown'} "
            f"| {ent.abuse_score if ent.abuse_score is not None else 'N/A'} "
            f"| {len(ent.timeline_event_indices)} event(s) |"
        )

    # Timeline
    lines += [
        "",
        "---",
        "",
        f"## Evidence Timeline ({len(report.timeline)} events)",
        "",
    ]
    for i, ev in enumerate(report.timeline, 1):
        ts = ev.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")
        entities_str = ", ".join(f"`{e}`" for e in ev.related_entities) if ev.related_entities else "None"
        lines += [
            f"### [{i}] {ev.title}",
            f"- **Time**: {ts}",
            f"- **Type**: `{ev.event_type}` | **Source**: `{ev.source}`",
            f"- **Entities**: {entities_str}",
            f"- **Description**: {ev.description}",
        ]
        if ev.severity_impact:
            lines.append(f"- **Severity Impact**: _{ev.severity_impact}_")
        if ev.raw_evidence_id:
            lines.append(f"- **Evidence ID**: `{ev.raw_evidence_id}`")
        lines.append("")

    # Lateral movement
    if report.lateral_movement_paths:
        lines += [
            "---",
            "",
            "## Lateral Movement Analysis",
            "",
            "Confirmed multi-host lateral movement paths:",
            "",
        ]
        for path in report.lateral_movement_paths:
            lines.append(f"- `{path}`")
        lines.append("")

    # Recommended actions
    lines += [
        "---",
        "",
        "## Recommended Containment Actions",
        "",
    ]
    for i, action in enumerate(report.recommended_actions, 1):
        lines.append(f"{i}. {action}")

    lines += [
        "",
        "---",
        f"*Report auto-generated by Security Operations Agent (Phase 5). Report ID: `{report.report_id}`*",
    ]

    return "\n".join(lines)
