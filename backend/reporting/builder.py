"""
Phase 5: Report Builder.

Assembles a structured IncidentReport from the completed InvestigationState.
Builds the evidence timeline and entity traceability map in deterministic order.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from backend.ingestion.models import SeverityLevel, utc_now
from backend.reporting.models import (
    IncidentReport,
    TimelineEvent,
    EntityTraceability,
    SeverityAuditRecord,
)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_ts(ts: Any) -> datetime:
    if isinstance(ts, datetime):
        if ts.tzinfo is None:
            return ts.replace(tzinfo=timezone.utc)
        return ts
    if isinstance(ts, str):
        try:
            dt = datetime.fromisoformat(ts)
            if dt.tzinfo is None:
                return dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            pass
    return _utc_now()


def build_report(state: Dict[str, Any]) -> IncidentReport:
    """
    Build a structured IncidentReport from an InvestigationState dict.

    Args:
        state: The completed InvestigationState from the investigation graph.

    Returns:
        A fully-populated, immutable IncidentReport.
    """
    incident = state.get("incident")
    if incident is None:
        raise ValueError("Cannot build report: incident not found in state.")

    threat_intel = state.get("threat_intel", {})
    asset_context = state.get("asset_context", {})
    lateral_paths = state.get("lateral_movement_paths", [])
    log_evidence = state.get("log_evidence", [])
    breakdown_dict = state.get("scoring_breakdown") or {}
    floor_enforced = state.get("floor_enforced", False)
    audit_note = state.get("audit_note")
    injection_detected = state.get("adversarial_injection_detected", False)
    injection_reason = state.get("adversarial_injection_reason")
    final_sev = state.get("severity_recommendation", incident.severity)
    recommended_actions = state.get("recommended_actions", [])
    narrative = state.get("narrative", "")

    # ---- Build timeline ----
    timeline: List[TimelineEvent] = []

    # 1. Alerts (sorted by timestamp)
    for alert in sorted(incident.alerts, key=lambda a: _parse_ts(a.timestamp)):
        entities_in_alert = [e.value for e in alert.entities]
        alert_title = getattr(alert, "rule_name", getattr(alert, "title", "Security Alert"))
        alert_desc = getattr(alert, "rule_description", alert_title)
        src_str = alert.source.value if hasattr(alert.source, "value") else str(alert.source)
        timeline.append(TimelineEvent(
            timestamp=_parse_ts(alert.timestamp),
            event_type="alert",
            source=src_str,
            title=alert_title,
            description=f"[{alert.normalized_severity.value.upper()}] {alert_desc}",
            related_entities=entities_in_alert,
            severity_impact=f"Alert severity: {alert.normalized_severity.value}",
            raw_evidence_id=alert.alert_id,
        ))

    # 2. Threat intel hits
    for entity_val, ti in threat_intel.items():
        verdict = ti.get("verdict", "unknown")
        if verdict in ("malicious", "suspicious"):
            abuse = ti.get("abuse_score", 0)
            source = ti.get("source", "threat_intel")
            timeline.append(TimelineEvent(
                timestamp=_utc_now(),
                event_type="threat_intel_hit",
                source=source,
                title=f"Threat Intel: {verdict.upper()} - {entity_val}",
                description=(
                    f"Entity {entity_val} flagged as {verdict} "
                    f"(abuse score: {abuse}, source: {source})"
                ),
                related_entities=[entity_val],
                severity_impact="TI verdict raised floor" if verdict == "malicious" else None,
                raw_evidence_id=None,
            ))

    # 3. Lateral movement events
    if lateral_paths:
        timeline.append(TimelineEvent(
            timestamp=_utc_now(),
            event_type="lateral_movement",
            source="siem_analysis",
            title=f"Lateral Movement Detected ({len(lateral_paths)} path(s))",
            description="Source IP observed connecting to multiple internal hosts.",
            related_entities=[p.split(" -> ")[0] for p in lateral_paths],
            severity_impact="Floor raised to HIGH (lateral movement)",
        ))

    # 4. Log evidence records (up to 10 most relevant)
    for entry in log_evidence[:10]:
        ts = _parse_ts(entry.get("timestamp"))
        related = []
        if entry.get("source_ip"):
            related.append(entry["source_ip"])
        if entry.get("host"):
            related.append(entry["host"])
        timeline.append(TimelineEvent(
            timestamp=ts,
            event_type="log_entry",
            source=entry.get("source", "siem"),
            title=entry.get("message", "Log entry"),
            description=entry.get("message", ""),
            related_entities=related,
            raw_evidence_id=entry.get("log_id"),
        ))

    # Sort timeline chronologically
    timeline.sort(key=lambda e: e.timestamp)

    # ---- Build entity traceability ----
    entity_map: Dict[str, EntityTraceability] = {}

    # From incident entities
    for ent in incident.entities:
        key = ent.value
        if key not in entity_map:
            ti_data = threat_intel.get(key, {})
            asset_data = asset_context.get(key, {})
            entity_map[key] = EntityTraceability(
                entity_value=key,
                entity_type=ent.type.value if hasattr(ent.type, "value") else str(ent.type),
                criticality=asset_data.get("criticality"),
                threat_verdict=ti_data.get("verdict"),
                abuse_score=ti_data.get("abuse_score"),
                timeline_event_indices=[],
            )

    # Map timeline event indices
    for idx, event in enumerate(timeline):
        for ev in event.related_entities:
            if ev in entity_map:
                if idx not in entity_map[ev].timeline_event_indices:
                    entity_map[ev].timeline_event_indices.append(idx)

    # ---- Severity audit record ----
    severity_audit = SeverityAuditRecord(
        deterministic_floor=breakdown_dict.get("deterministic_floor", incident.deterministic_floor.value),
        rule_override_reason=breakdown_dict.get("rule_floor_override"),
        base_score=breakdown_dict.get("base_score", 0.0),
        asset_multiplier=breakdown_dict.get("asset_multiplier", 1.0),
        threat_intel_points=breakdown_dict.get("threat_intel_points", 0.0),
        mitre_multiplier=breakdown_dict.get("mitre_multiplier", 1.0),
        lateral_movement_points=breakdown_dict.get("lateral_movement_points", 0.0),
        raw_calculated_score=breakdown_dict.get("raw_calculated_score", 0.0),
        llm_reasoning=audit_note,
        floor_enforced=floor_enforced,
        final_severity=final_sev.value if hasattr(final_sev, "value") else str(final_sev),
    )

    return IncidentReport(
        report_id=f"RPT-{incident.incident_id}-{uuid.uuid4().hex[:8].upper()}",
        incident_id=incident.incident_id,
        generated_at=_utc_now(),
        incident_title=incident.title,
        final_severity=final_sev if isinstance(final_sev, SeverityLevel) else SeverityLevel(final_sev),
        deterministic_floor=incident.deterministic_floor,
        status=incident.status.value if hasattr(incident.status, "value") else str(incident.status),
        timeline=timeline,
        entities=list(entity_map.values()),
        severity_audit=severity_audit,
        mitre_tactics=incident.tactics,
        mitre_techniques=incident.techniques,
        attack_chain_span=incident.attack_chain_span,
        lateral_movement_paths=lateral_paths,
        adversarial_injection_detected=injection_detected,
        adversarial_injection_reason=injection_reason,
        recommended_actions=recommended_actions,
        executive_summary=narrative,
    )
