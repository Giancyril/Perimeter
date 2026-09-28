"""
Deterministic Event Correlation Engine.
Groups normalized security alerts into incidents by shared entities within sliding time windows,
maps attack progression across MITRE ATT&CK stages, and computes baseline deterministic severity floors.
"""
from typing import Dict, List, Optional, Set, Tuple
from datetime import datetime, timezone
import threading
import uuid

from backend.ingestion.models import NormalizedAlert, Entity, EntityType, SeverityLevel, utc_now
from backend.correlation.models import CorrelatedIncident, IncidentStatus
from backend.correlation.mitre import sort_tactics_by_killchain, infer_mitre_from_rule

IGNORABLE_USERS = {"nobody", "daemon", "sync", "games", "man", "lp", "mail", "news", "uucp", "proxy"}
IGNORABLE_IPS = {"127.0.0.1", "::1", "0.0.0.0"}

class CorrelationEngine:
    """Thread-safe sliding time window correlation engine."""

    def __init__(self, window_seconds: int = 1800):
        self.window_seconds = window_seconds  # Default 30 minutes
        self._incidents: Dict[str, CorrelatedIncident] = {}
        self._entity_index: Dict[str, Set[str]] = {}  # entity_key -> Set[incident_id]
        self._lock = threading.Lock()
        self._incident_counter = 1

    def _parse_timestamp(self, ts: str) -> datetime:
        try:
            return datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except Exception:
            return datetime.now(timezone.utc)

    def _extract_pivot_keys(self, alert: NormalizedAlert) -> List[str]:
        keys = []
        if alert.host:
            keys.append(f"host:{alert.host.lower().strip()}")
        if alert.user and alert.user.lower().strip() not in IGNORABLE_USERS:
            keys.append(f"user:{alert.user.lower().strip()}")
        if alert.source_ip and alert.source_ip not in IGNORABLE_IPS:
            keys.append(f"ip:{alert.source_ip.strip()}")
        if alert.destination_ip and alert.destination_ip not in IGNORABLE_IPS:
            keys.append(f"ip:{alert.destination_ip.strip()}")
        if alert.file_hash:
            keys.append(f"hash:{alert.file_hash.lower().strip()}")
        return keys

    def _compute_deterministic_score(
        self,
        alerts: List[NormalizedAlert],
        tactics: List[str],
        entities: List[Entity],
    ) -> Tuple[int, SeverityLevel]:
        """
        Computes deterministic score (0-100) and floor based on:
        - Max raw rule severity of alerts in the incident
        - Attack chain breadth (+10 per kill-chain stage)
        - Alert volume (+5 per correlated alert, max 20)
        - Asset criticality (+15 for production/database/domain controllers)
        """
        # Base severity from maximum alert severity
        severity_weights = {
            SeverityLevel.CRITICAL: 65,
            SeverityLevel.HIGH: 45,
            SeverityLevel.MEDIUM: 25,
            SeverityLevel.LOW: 15,
            SeverityLevel.INFORMATIONAL: 5,
        }
        max_sev = max((a.normalized_severity for a in alerts), key=lambda s: severity_weights[s])
        score = severity_weights[max_sev]

        # Multi-alert volume correlation bonus (up to +20)
        additional_alerts = max(0, len(alerts) - 1)
        score += min(20, additional_alerts * 5)

        # Multi-stage attack progression bonus (kill-chain spread)
        if len(tactics) > 1:
            score += min(25, (len(tactics) - 1) * 10)

        # Asset criticality bonus
        for ent in entities:
            val = ent.value.lower()
            if any(crit in val for crit in ["prod", "db", "dc", "master", "primary", "gateway", "vault"]):
                score += 15
                break

        score = max(0, min(100, score))

        # Map to deterministic floor
        if score >= 80:
            floor = SeverityLevel.CRITICAL
        elif score >= 60:
            floor = SeverityLevel.HIGH
        elif score >= 40:
            floor = SeverityLevel.MEDIUM
        elif score >= 20:
            floor = SeverityLevel.LOW
        else:
            floor = SeverityLevel.INFORMATIONAL

        return score, floor

    def _generate_title(self, incident: CorrelatedIncident) -> str:
        """Generates an informative, deterministic title without LLM hallucination."""
        tactics_str = " -> ".join(incident.tactics[:3]) if incident.tactics else "Suspicious Activity"
        target_str = incident.primary_entity or (incident.alerts[0].host if incident.alerts else "Infrastructure")
        return f"{tactics_str} detected on {target_str}"

    def correlate(self, alert: NormalizedAlert) -> CorrelatedIncident:
        """Correlates an incoming normalized alert into an existing incident or opens a new incident."""
        alert_ts = self._parse_timestamp(alert.timestamp)
        pivot_keys = self._extract_pivot_keys(alert)

        with self._lock:
            matched_incident: Optional[CorrelatedIncident] = None
            matched_key: Optional[str] = None

            # Search active incidents sharing pivot entities
            candidate_incident_ids: Set[str] = set()
            for key in pivot_keys:
                if key in self._entity_index:
                    candidate_incident_ids.update(self._entity_index[key])

            # Filter candidates within time window
            for inc_id in candidate_incident_ids:
                inc = self._incidents.get(inc_id)
                if not inc or inc.status in [IncidentStatus.RESOLVED, IncidentStatus.CLOSED]:
                    continue

                inc_end_ts = self._parse_timestamp(inc.window_end)
                time_delta = abs((alert_ts - inc_end_ts).total_seconds())

                if time_delta <= self.window_seconds:
                    matched_incident = inc
                    # Identify matching key for explanation
                    for k in pivot_keys:
                        if k in self._entity_index and inc_id in self._entity_index[k]:
                            matched_key = k
                            break
                    break

            if matched_incident:
                # Append alert to existing incident
                matched_incident.alerts.append(alert)
                matched_incident.alert_ids.append(alert.alert_id)
                matched_incident.alert_count = len(matched_incident.alerts)
                matched_incident.window_end = alert.timestamp
                matched_incident.updated_at = utc_now()

                # Merge entities
                existing_entity_keys = {f"{e.type.value}:{e.value}": e for e in matched_incident.entities}
                for new_e in alert.entities:
                    k = f"{new_e.type.value}:{new_e.value}"
                    if k not in existing_entity_keys:
                        matched_incident.entities.append(new_e)

                # Merge tactics and techniques
                all_tactics = list(matched_incident.tactics)
                all_techs = list(matched_incident.techniques)

                if alert.mitre_attack:
                    all_tactics.extend(alert.mitre_attack.tactics)
                    all_techs.extend(alert.mitre_attack.techniques)
                else:
                    inferred = infer_mitre_from_rule(alert.rule_name, alert.rule_id)
                    if inferred:
                        all_tactics.extend(inferred["tactics"])
                        all_techs.extend(inferred["techniques"])

                matched_incident.tactics = sort_tactics_by_killchain(all_tactics)
                matched_incident.techniques = list(set(all_techs))
                matched_incident.attack_chain_span = len(matched_incident.tactics)

                # Explainability reason
                matched_incident.correlation_reasons.append(
                    f"Correlated alert '{alert.rule_name}' via shared pivot {matched_key}"
                )

                # Recalculate deterministic score & floor
                score, floor = self._compute_deterministic_score(
                    matched_incident.alerts,
                    matched_incident.tactics,
                    matched_incident.entities,
                )
                matched_incident.deterministic_score = score
                matched_incident.deterministic_floor = floor
                matched_incident.severity = floor
                matched_incident.title = self._generate_title(matched_incident)

                # Index any newly introduced pivot keys
                for key in pivot_keys:
                    self._entity_index.setdefault(key, set()).add(matched_incident.incident_id)

                return matched_incident

            # Spawn new incident
            new_id = f"INC-2026-{self._incident_counter:04d}"
            self._incident_counter += 1

            tactics = []
            techniques = []
            if alert.mitre_attack:
                tactics = list(alert.mitre_attack.tactics)
                techniques = list(alert.mitre_attack.techniques)
            else:
                inferred = infer_mitre_from_rule(alert.rule_name, alert.rule_id)
                if inferred:
                    tactics = inferred["tactics"]
                    techniques = inferred["techniques"]

            tactics = sort_tactics_by_killchain(tactics)
            primary_entity = alert.host or alert.user or alert.source_ip or "System"

            score, floor = self._compute_deterministic_score([alert], tactics, alert.entities)

            new_incident = CorrelatedIncident(
                incident_id=new_id,
                title=f"{tactics[0] if tactics else 'Alert'} on {primary_entity}",
                status=IncidentStatus.NEW,
                created_at=utc_now(),
                updated_at=utc_now(),
                window_start=alert.timestamp,
                window_end=alert.timestamp,
                alert_count=1,
                alert_ids=[alert.alert_id],
                alerts=[alert],
                entities=list(alert.entities),
                primary_entity=primary_entity,
                tactics=tactics,
                techniques=techniques,
                attack_chain_span=len(tactics),
                correlation_reasons=[f"New incident spawned by initial alert '{alert.rule_name}'"],
                deterministic_score=score,
                deterministic_floor=floor,
                severity=floor,
                owner="SecOps Agent (Auto)",
            )
            new_incident.title = self._generate_title(new_incident)

            self._incidents[new_id] = new_incident
            for key in pivot_keys:
                self._entity_index.setdefault(key, set()).add(new_id)

            return new_incident

    def get_incident(self, incident_id: str) -> Optional[CorrelatedIncident]:
        with self._lock:
            return self._incidents.get(incident_id)

    def list_incidents(
        self,
        limit: int = 50,
        severity: Optional[SeverityLevel] = None,
        status: Optional[IncidentStatus] = None,
        tactic: Optional[str] = None,
    ) -> List[CorrelatedIncident]:
        with self._lock:
            results = list(self._incidents.values())

        if severity:
            results = [inc for inc in results if inc.severity == severity]
        if status:
            results = [inc for inc in results if inc.status == status]
        if tactic:
            results = [inc for inc in results if any(t.lower() == tactic.lower() for t in inc.tactics)]

        results.sort(key=lambda inc: inc.updated_at, reverse=True)
        return results[:limit]

    def clear(self):
        with self._lock:
            self._incidents.clear()
            self._entity_index.clear()
            self._incident_counter = 1

# Global singleton
correlation_engine = CorrelationEngine()
