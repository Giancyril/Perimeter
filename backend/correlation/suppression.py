"""
Correlation-Time False-Positive Suppression & Triage Engine.
Filters out known benign activity, vulnerability scanners, and scheduled maintenance windows
before alerts consume correlation resources or pollute incident queues.
"""
from typing import Dict, List, Optional, Set, Tuple, Any
from datetime import datetime, timezone
import ipaddress
import re
from pydantic import BaseModel, Field
from backend.ingestion.models import NormalizedAlert, utc_now

class SuppressionRule(BaseModel):
    rule_id: str
    description: str
    enabled: bool = True
    match_rule_regex: Optional[str] = None
    match_cidr: Optional[str] = None
    match_users: List[str] = Field(default_factory=list)
    match_hosts: List[str] = Field(default_factory=list)
    expiration: Optional[str] = None  # ISO timestamp
    hit_count: int = 0
    created_at: str = Field(default_factory=utc_now)
    last_hit_at: Optional[str] = None

class CorrelationSuppressionEngine:
    """Evaluates alerts against active suppression and allowlist rules."""

    def __init__(self):
        self._rules: Dict[str, SuppressionRule] = {}
        self._load_default_rules()

    def _load_default_rules(self):
        # Default internal scanner and backup allowlists
        self.add_rule(SuppressionRule(
            rule_id="vuln-scanner-qualys",
            description="Suppress vulnerability scan alerts from authorized scanner pool",
            match_cidr="10.200.50.0/24",
            match_rule_regex=r"(?i)(port scan|sweep|vulnerability|nmap)",
        ))
        self.add_rule(SuppressionRule(
            rule_id="backup-svc-account",
            description="Suppress scheduled night backup user cron activity",
            match_users=["svc_backup", "backup-daemon", "system-backup"],
            match_rule_regex=r"(?i)(high disk read|large file access|cron)",
        ))

    def add_rule(self, rule: SuppressionRule) -> None:
        self._rules[rule.rule_id] = rule

    def remove_rule(self, rule_id: str) -> bool:
        return self._rules.pop(rule_id, None) is not None

    def list_rules(self) -> List[SuppressionRule]:
        return list(self._rules.values())

    def check_suppression(self, alert: NormalizedAlert) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Evaluates alert against all active suppression rules.
        Returns (is_suppressed, rule_id, rationale).
        """
        now = datetime.now(timezone.utc)

        for rule in self._rules.values():
            if not rule.enabled:
                continue

            # Check expiration
            if rule.expiration:
                try:
                    exp_dt = datetime.fromisoformat(rule.expiration.replace("Z", "+00:00"))
                    if now > exp_dt:
                        continue
                except Exception:
                    pass

            matches = True

            # Match Rule Name regex
            if rule.match_rule_regex:
                if not alert.rule_name or not re.search(rule.match_rule_regex, alert.rule_name):
                    matches = False

            # Match Source IP / CIDR
            if matches and rule.match_cidr and alert.source_ip:
                try:
                    net = ipaddress.ip_network(rule.match_cidr, strict=False)
                    ip = ipaddress.ip_address(alert.source_ip)
                    if ip not in net:
                        matches = False
                except Exception:
                    matches = False
            elif matches and rule.match_cidr and not alert.source_ip:
                matches = False

            # Match Users
            if matches and rule.match_users:
                user_match = alert.user and any(u.lower() == alert.user.lower().strip() for u in rule.match_users)
                if not user_match:
                    matches = False

            # Match Hosts
            if matches and rule.match_hosts:
                host_match = alert.host and any(h.lower() == alert.host.lower().strip() for h in rule.match_hosts)
                if not host_match:
                    matches = False

            if matches:
                rule.hit_count += 1
                rule.last_hit_at = utc_now()
                reason = f"Alert matched suppression rule '{rule.rule_id}': {rule.description}"
                return True, rule.rule_id, reason

        return False, None, None
