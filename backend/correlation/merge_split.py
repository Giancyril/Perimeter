"""
Incident Convergence, Merge & Split Engine.
Handles automatic and analyst-driven merging of converging incident clusters,
maintaining immutable audit provenance, unified timeline chronology, and entity linkage.
"""
from typing import Dict, List, Optional, Set, Tuple, Any
from copy import deepcopy
from backend.correlation.models import CorrelatedIncident, IncidentStatus
from backend.ingestion.models import NormalizedAlert, Entity, SeverityLevel, utc_now

class IncidentClusterManager:
    """Manages multi-incident merging and alert detachment/splitting operations."""

    @staticmethod
    def detect_mergeable_incidents(
        incidents: List[CorrelatedIncident],
        min_shared_entities: int = 1,
    ) -> List[Tuple[str, str, List[str]]]:
        """
        Scans active incidents for entity overlaps.
        Returns list of (incident_id_1, incident_id_2, shared_entity_keys).
        """
        candidates: List[Tuple[str, str, List[str]]] = []
        n = len(incidents)

        for i in range(n):
            inc_a = incidents[i]
            if inc_a.status in (IncidentStatus.RESOLVED, IncidentStatus.CLOSED):
                continue

            keys_a = {f"{e.entity_type.value}:{e.value.lower().strip()}" for e in inc_a.entities}

            for j in range(i + 1, n):
                inc_b = incidents[j]
                if inc_b.status in (IncidentStatus.RESOLVED, IncidentStatus.CLOSED):
                    continue

                keys_b = {f"{e.entity_type.value}:{e.value.lower().strip()}" for e in inc_b.entities}
                shared = list(keys_a.intersection(keys_b))

                if len(shared) >= min_shared_entities:
                    candidates.append((inc_a.incident_id, inc_b.incident_id, shared))

        return candidates

    @staticmethod
    def merge_incidents(
        primary: CorrelatedIncident,
        secondary: CorrelatedIncident,
        reason: str = "Automated cross-cluster entity convergence",
    ) -> CorrelatedIncident:
        """
        Merges secondary incident into primary incident.
        Updates primary in-place with combined alerts, entities, and tactics.
        """
        # Combine alerts without duplicate IDs
        existing_alert_ids = set(primary.alert_ids)
        for a in secondary.alerts:
            if a.alert_id not in existing_alert_ids:
                primary.alerts.append(a)
                primary.alert_ids.append(a.alert_id)
                existing_alert_ids.add(a.alert_id)

        primary.alert_count = len(primary.alerts)

        # Combine entities
        existing_entity_keys = {f"{e.entity_type.value}:{e.value.lower().strip()}" for e in primary.entities}
        for ent in secondary.entities:
            key = f"{ent.entity_type.value}:{ent.value.lower().strip()}"
            if key not in existing_entity_keys:
                primary.entities.append(ent)
                existing_entity_keys.add(key)

        # Combine tactics and techniques
        all_tactics = list(dict.fromkeys(primary.tactics + secondary.tactics))
        all_techs = list(dict.fromkeys(primary.techniques + secondary.techniques))
        primary.tactics = all_tactics
        primary.techniques = all_techs
        primary.attack_chain_span = max(primary.attack_chain_span, secondary.attack_chain_span, len(all_tactics))

        # Adjust time windows
        if secondary.window_start < primary.window_start:
            primary.window_start = secondary.window_start
        if secondary.window_end > primary.window_end:
            primary.window_end = secondary.window_end

        # Highest severity and score preservation
        primary.deterministic_score = max(primary.deterministic_score, secondary.deterministic_score)
        severity_order = [
            SeverityLevel.INFORMATIONAL,
            SeverityLevel.LOW,
            SeverityLevel.MEDIUM,
            SeverityLevel.HIGH,
            SeverityLevel.CRITICAL,
        ]
        if severity_order.index(secondary.severity) > severity_order.index(primary.severity):
            primary.severity = secondary.severity
            primary.deterministic_floor = secondary.deterministic_floor

        # Audit correlation reason
        primary.correlation_reasons.append(
            f"Merged with {secondary.incident_id} ({secondary.alert_count} alerts): {reason}"
        )
        primary.updated_at = utc_now()

        # Mark secondary as resolved/merged
        secondary.status = IncidentStatus.RESOLVED
        secondary.owner = f"Merged into {primary.incident_id}"
        secondary.updated_at = utc_now()

        return primary

    @staticmethod
    def split_incident(
        source_incident: CorrelatedIncident,
        alert_ids_to_extract: List[str],
        new_incident_id: str,
        reason: str = "Analyst manual partition",
    ) -> Tuple[CorrelatedIncident, CorrelatedIncident]:
        """
        Splits a subset of alerts out of source_incident into a brand new incident.
        Maintains parent/child lineage tracking.
        """
        extract_set = set(alert_ids_to_extract)
        extracted_alerts = [a for a in source_incident.alerts if a.alert_id in extract_set]
        retained_alerts = [a for a in source_incident.alerts if a.alert_id not in extract_set]

        if not extracted_alerts:
            raise ValueError("No matching alert IDs found to split.")
        if not retained_alerts:
            raise ValueError("Cannot extract all alerts; at least one alert must remain in source incident.")

        # Update source
        source_incident.alerts = retained_alerts
        source_incident.alert_ids = [a.alert_id for a in retained_alerts]
        source_incident.alert_count = len(retained_alerts)
        source_incident.correlation_reasons.append(f"Split {len(extracted_alerts)} alerts into {new_incident_id}: {reason}")
        source_incident.updated_at = utc_now()

        # Build new child incident
        child_tactics = list(dict.fromkeys(t for a in extracted_alerts for t in a.tactics))
        child_techs = list(dict.fromkeys(t for a in extracted_alerts for t in a.techniques))
        child_entities: List[Entity] = []
        seen_keys: Set[str] = set()
        for a in extracted_alerts:
            for e in a.entities:
                k = f"{e.entity_type.value}:{e.value.lower().strip()}"
                if k not in seen_keys:
                    child_entities.append(e)
                    seen_keys.add(k)

        child = CorrelatedIncident(
            incident_id=new_incident_id,
            title=f"Split from {source_incident.incident_id}: {extracted_alerts[0].title}",
            status=IncidentStatus.NEW,
            window_start=min(a.timestamp for a in extracted_alerts),
            window_end=max(a.timestamp for a in extracted_alerts),
            alert_count=len(extracted_alerts),
            alert_ids=[a.alert_id for a in extracted_alerts],
            alerts=extracted_alerts,
            entities=child_entities,
            primary_entity=source_incident.primary_entity,
            tactics=child_tactics,
            techniques=child_techs,
            attack_chain_span=len(child_tactics) or 1,
            correlation_reasons=[f"Created via split from parent incident {source_incident.incident_id}: {reason}"],
            deterministic_score=source_incident.deterministic_score,
            deterministic_floor=source_incident.deterministic_floor,
            severity=source_incident.severity,
            owner=source_incident.owner,
        )

        return source_incident, child
