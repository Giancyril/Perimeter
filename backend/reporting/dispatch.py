"""
Multi-Channel Report Dispatcher & Notification Hub (Day 5 - Commit 7).

Prepares and dispatches incident reports and executive briefings across
enterprise collaboration and response channels:
1. Slack Block Kit payloads (with action buttons & severity badges).
2. Microsoft Teams Adaptive Cards (JSON v1.5 schema).
3. PagerDuty Events API v2 format.
4. Role-Based Redaction Engine (Executive vs Technical vs External Partner views).
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from backend.ingestion.models import SeverityLevel
from backend.reporting.models import IncidentReport
from backend.reporting.executive_briefing import ExecutiveBriefing


class AudienceRole(str, Enum):
    TECHNICAL_SOC = "TECHNICAL_SOC"       # Full unredacted telemetry
    EXECUTIVE_LEADERSHIP = "EXECUTIVE_LEADERSHIP"  # High-level metrics, masked raw shell commands
    EXTERNAL_PARTNER = "EXTERNAL_PARTNER"  # Strict PII & internal IP/host masking


class ReportDispatcher:
    """
    Transforms IncidentReports and ExecutiveBriefings into platform-specific
    webhook payloads with role-based data redaction.
    """

    def redact_text(self, text: str, role: AudienceRole) -> str:
        """Apply role-based sanitization to text."""
        if role == AudienceRole.TECHNICAL_SOC:
            return text

        redacted = text
        if role == AudienceRole.EXTERNAL_PARTNER:
            # Mask internal IPs (10.x.x.x, 192.168.x.x, 172.16-31.x.x)
            redacted = re.sub(r"\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", "[INTERNAL_IP_MASKED]", redacted)
            redacted = re.sub(r"\b192\.168\.\d{1,3}\.\d{1,3}\b", "[INTERNAL_IP_MASKED]", redacted)
            redacted = re.sub(r"\b172\.(?:1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}\b", "[INTERNAL_IP_MASKED]", redacted)
            # Mask employee domain usernames
            redacted = re.sub(r"\b(?:corp|internal)\\[a-zA-Z0-9._-]+\b", "[USER_MASKED]", redacted)

        if role in (AudienceRole.EXECUTIVE_LEADERSHIP, AudienceRole.EXTERNAL_PARTNER):
            # Shorten long SHA-256 hashes
            redacted = re.sub(r"\b[a-fA-F0-9]{64}\b", "[HASH_REDACTED]", redacted)

        return redacted

    def to_slack_block_kit(
        self,
        report: IncidentReport,
        briefing: Optional[ExecutiveBriefing] = None,
        role: AudienceRole = AudienceRole.TECHNICAL_SOC,
    ) -> Dict[str, Any]:
        """
        Produce a Slack Block Kit interactive message payload.
        """
        sev = report.final_severity
        color = "#e11d48" if sev == SeverityLevel.CRITICAL else "#f97316" if sev == SeverityLevel.HIGH else "#eab308"
        headline = briefing.headline if briefing else report.incident_title
        headline = self.redact_text(headline, role)

        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"🚨 [{sev.value.upper()}] Incident Alert: {report.incident_id}",
                    "emoji": True,
                },
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Incident ID:*\n`{report.incident_id}`"},
                    {"type": "mrkdwn", "text": f"*Severity:*\n*{sev.value.upper()}*"},
                    {"type": "mrkdwn", "text": f"*Floor Enforced:*\n{'✅ Yes' if report.severity_audit.floor_enforced else 'No'}"},
                    {"type": "mrkdwn", "text": f"*Status:*\n`{report.status}`"},
                ],
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Summary:*\n{self.redact_text(report.executive_summary or headline, role)[:500]}",
                },
            },
            {
                "type": "divider",
            },
        ]

        if report.mitre_tactics:
            tactics_str = ", ".join(report.mitre_tactics)
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*MITRE ATT&CK Tactics:*\n`{tactics_str}`",
                },
            })

        # Interactive action buttons
        blocks.append({
            "type": "actions",
            "elements": [
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "Approve Containment", "emoji": True},
                    "style": "danger",
                    "value": f"approve_containment_{report.incident_id}",
                },
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "View in SOC Dashboard", "emoji": True},
                    "url": f"https://soc.company.internal/incidents/{report.incident_id}",
                },
            ],
        })

        return {
            "attachments": [
                {
                    "color": color,
                    "blocks": blocks,
                }
            ]
        }

    def to_teams_adaptive_card(
        self,
        report: IncidentReport,
        briefing: Optional[ExecutiveBriefing] = None,
        role: AudienceRole = AudienceRole.TECHNICAL_SOC,
    ) -> Dict[str, Any]:
        """
        Produce a Microsoft Teams Adaptive Card (JSON v1.5).
        """
        sev = report.final_severity
        headline = briefing.headline if briefing else report.incident_title
        headline = self.redact_text(headline, role)

        card = {
            "type": "AdaptiveCard",
            "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
            "version": "1.5",
            "body": [
                {
                    "type": "TextBlock",
                    "size": "Large",
                    "weight": "Bolder",
                    "text": f"[{sev.value.upper()}] {headline}",
                    "color": "Attention" if sev in (SeverityLevel.CRITICAL, SeverityLevel.HIGH) else "Warning",
                },
                {
                    "type": "FactSet",
                    "facts": [
                        {"title": "Incident ID", "value": report.incident_id},
                        {"title": "Final Severity", "value": sev.value.upper()},
                        {"title": "Deterministic Floor", "value": report.deterministic_floor.value.upper()},
                        {"title": "Attack Stages", "value": str(len(report.timeline))},
                        {"title": "Adversarial Injection Detected", "value": "YES (Override Blocked)" if report.adversarial_injection_detected else "No"},
                    ],
                },
                {
                    "type": "TextBlock",
                    "text": self.redact_text(report.executive_summary or "Autonomous investigation complete.", role)[:600],
                    "wrap": True,
                },
            ],
            "actions": [
                {
                    "type": "Action.OpenUrl",
                    "title": "Open Investigation Workspace",
                    "url": f"https://soc.company.internal/incidents/{report.incident_id}",
                },
                {
                    "type": "Action.Submit",
                    "title": "Trigger Automated Remediation",
                    "data": {"action": "remediate", "incident_id": report.incident_id},
                },
            ],
        }
        return card

    def to_pagerduty_payload(
        self,
        report: IncidentReport,
        routing_key: str = "SOC_ROUTING_KEY_PROD",
    ) -> Dict[str, Any]:
        """
        Format as PagerDuty Events API v2 payload.
        """
        sev = report.final_severity
        severity_str = "critical" if sev == SeverityLevel.CRITICAL else "error" if sev == SeverityLevel.HIGH else "warning"

        return {
            "routing_key": routing_key,
            "event_action": "trigger",
            "dedup_key": f"soc-incident-{report.incident_id}",
            "payload": {
                "summary": f"[{sev.value.upper()}] {report.incident_title} ({report.incident_id})",
                "source": "Autonomous SOC Agent",
                "severity": severity_str,
                "timestamp": report.generated_at.isoformat(),
                "component": "Threat Detection Pipeline",
                "group": "SecOps",
                "class": "Security Incident",
                "custom_details": {
                    "incident_id": report.incident_id,
                    "deterministic_floor": report.deterministic_floor.value,
                    "final_score": report.severity_audit.raw_calculated_score,
                    "tactics": report.mitre_tactics,
                    "adversarial_injection": report.adversarial_injection_detected,
                },
            },
            "client": "Autonomous Security Operations Center",
            "client_url": f"https://soc.company.internal/incidents/{report.incident_id}",
        }
