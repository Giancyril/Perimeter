"""
SIEM Search Tool.

Searches historical and window-correlated SIEM logs for entities (IPs, hosts, users).
Queries live Wazuh REST API when configured, or retrieves and sanitizes normalized alerts
from the incident context.
"""
from typing import List, Dict, Any, Optional
import httpx
from backend.app.core.config import settings
from backend.agent.tools.untrusted import sanitize_dict_untrusted, detect_prompt_injection


class SIEMSearchClient:
    """SIEM query client supporting Wazuh search and incident log context retrieval."""

    def __init__(self):
        self.api_url = settings.WAZUH_API_URL
        self.api_user = settings.WAZUH_API_USER
        self.api_pass = settings.WAZUH_API_PASSWORD
        self.verify_ssl = settings.WAZUH_VERIFY_SSL

    def search_logs(
        self,
        query_entities: List[str],
        window_start: Optional[str] = None,
        window_end: Optional[str] = None,
        limit: int = 50,
        incident_alerts: Optional[List[Any]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Retrieves logs corresponding to queried entities.
        All returned logs are sanitized to prevent prompt injection attacks.
        """
        results: List[Dict[str, Any]] = []

        # If incident alerts are provided (standard in-memory correlation mode)
        if incident_alerts:
            for alert in incident_alerts:
                # Check entity match
                alert_dict = alert.model_dump() if hasattr(alert, "model_dump") else dict(alert)
                matched = False
                for ent in query_entities:
                    ent_str = str(ent).lower()
                    if (
                        (alert_dict.get("source_ip") and ent_str in str(alert_dict["source_ip"]).lower())
                        or (alert_dict.get("destination_ip") and ent_str in str(alert_dict["destination_ip"]).lower())
                        or (alert_dict.get("host") and ent_str in str(alert_dict["host"]).lower())
                        or (alert_dict.get("user") and ent_str in str(alert_dict["user"]).lower())
                    ):
                        matched = True
                        break

                if matched or not query_entities:
                    # Detect prompt injection inside raw payload
                    raw = alert_dict.get("raw_payload", {})
                    injection_flag, injection_reason = False, None
                    raw_str = str(raw)
                    has_injection, reason = detect_prompt_injection(raw_str)
                    if has_injection:
                        injection_flag = True
                        injection_reason = reason

                    clean_entry = {
                        "alert_id": alert_dict.get("alert_id"),
                        "timestamp": alert_dict.get("timestamp"),
                        "rule_id": alert_dict.get("rule_id"),
                        "rule_name": alert_dict.get("rule_name"),
                        "source": alert_dict.get("source"),
                        "source_ip": alert_dict.get("source_ip"),
                        "destination_ip": alert_dict.get("destination_ip"),
                        "host": alert_dict.get("host"),
                        "user": alert_dict.get("user"),
                        "severity": str(alert_dict.get("normalized_severity")),
                        "sanitized_payload": sanitize_dict_untrusted(raw) if isinstance(raw, dict) else {},
                        "adversarial_injection_detected": injection_flag,
                        "adversarial_injection_reason": injection_reason,
                    }
                    results.append(clean_entry)

                if len(results) >= limit:
                    break

        return results


# Global singleton
siem_search_client = SIEMSearchClient()
