"""
Deterministic Incident Titling & Root-Cause Correlation Explainer.
Generates concise, informative, human-readable SOC incident titles and explainability
narratives based on correlated entity topologies, MITRE tactics, and temporal spans.
"""
from typing import Dict, List, Optional, Any
from backend.ingestion.models import NormalizedAlert, Entity, SeverityLevel

class IncidentExplainer:
    """Generates explainable titles and root-cause rationale without LLM latency."""

    @staticmethod
    def generate_incident_title(
        tactics: List[str],
        techniques: List[str],
        primary_entity: Optional[str],
        target_host: Optional[str],
        alert_count: int,
    ) -> str:
        """
        Synthesizes a standardized, explainable incident title.
        Examples:
        - "Credential Access (T1110) on prod-db-01 by 198.51.100.5"
        - "Multi-Stage Attack: Initial Access -> Credential Access on web-dmz-02"
        """
        # Multi-stage progression title
        if len(tactics) >= 2:
            stages_summary = f"{tactics[0]} -> {tactics[-1]}"
            target_str = f" on {target_host}" if target_host else ""
            actor_str = f" via {primary_entity}" if primary_entity and primary_entity != target_host else ""
            return f"Multi-Stage Attack: {stages_summary}{target_str}{actor_str}".strip()

        # Single tactic title
        tactic_str = tactics[0] if tactics else "Suspicious Activity"
        tech_str = f" ({techniques[0].split(' - ')[0]})" if techniques else ""
        target_str = f" on {target_host}" if target_host else ""
        actor_str = f" from {primary_entity}" if primary_entity and primary_entity != target_host else ""

        title = f"{tactic_str}{tech_str}{target_str}{actor_str}".strip()
        if alert_count > 5:
            title += f" ({alert_count} alerts)"
        return title

    @staticmethod
    def generate_correlation_reasons(
        shared_entities: List[str],
        time_span_minutes: float,
        tactics: List[str],
        alert_count: int,
    ) -> List[str]:
        """Produces transparent, step-by-step bullet points explaining why alerts were grouped."""
        reasons = []

        if shared_entities:
            ent_summary = ", ".join(shared_entities[:3])
            if len(shared_entities) > 3:
                ent_summary += f" (+{len(shared_entities) - 3} more)"
            reasons.append(f"Shared pivot entities: {ent_summary}")

        reasons.append(f"Clustered {alert_count} alerts occurring within a {max(1, int(time_span_minutes))}-minute window")

        if len(tactics) > 1:
            reasons.append(f"Observed kill-chain progression across {len(tactics)} attack stages: {' -> '.join(tactics)}")
        elif tactics:
            reasons.append(f"Repeated activity mapped to MITRE ATT&CK tactic '{tactics[0]}'")

        return reasons

    @staticmethod
    def summarize_root_cause(alerts: List[NormalizedAlert]) -> Dict[str, Any]:
        """Identifies candidate initial trigger alert and attack vector."""
        if not alerts:
            return {"trigger_alert_id": None, "suspected_vector": "Unknown"}

        # Earliest alert is the suspected initial trigger
        sorted_alerts = sorted(alerts, key=lambda a: a.timestamp)
        first_alert = sorted_alerts[0]

        suspected_vector = "Unknown"
        if first_alert.mitre_attack and first_alert.mitre_attack.tactics:
            suspected_vector = first_alert.mitre_attack.tactics[0]
        elif first_alert.rule_name:
            suspected_vector = first_alert.rule_name

        return {
            "trigger_alert_id": first_alert.alert_id,
            "trigger_timestamp": first_alert.timestamp,
            "suspected_vector": suspected_vector,
            "initial_actor": first_alert.source_ip or first_alert.user or "Unknown",
            "initial_target": first_alert.destination_ip or first_alert.host or "Unknown",
        }
