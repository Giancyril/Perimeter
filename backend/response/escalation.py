"""
Phase 6: Escalation Notification Dispatcher.

Formats and dispatches incident alerts and human-approval requests to
external communication platforms (Slack Block Kit, PagerDuty Events API v2).
"""
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import httpx

from backend.response.models import (
    ProposedAction,
    EscalationChannel,
    EscalationRecord,
    ActionRiskLevel,
)

logger = logging.getLogger("secops.response.escalation")


class EscalationDispatcher:
    """
    Dispatches escalation notifications and interactive containment action approval requests.
    Supports Slack Block Kit and PagerDuty Events v2. Falls back to simulated delivery
    when external webhook URLs are not configured.
    """

    def __init__(
        self,
        slack_webhook_url: Optional[str] = None,
        pagerduty_routing_key: Optional[str] = None,
    ):
        self.slack_webhook_url = slack_webhook_url
        self.pagerduty_routing_key = pagerduty_routing_key
        self.dispatch_history: List[EscalationRecord] = []

    def build_slack_block_kit(
        self,
        incident_id: str,
        incident_title: str,
        severity: str,
        deterministic_floor: str,
        summary: str,
        actions: List[ProposedAction],
    ) -> Dict[str, Any]:
        """Constructs a high-impact Slack Block Kit message with interactive buttons."""
        sev_upper = severity.upper()
        emoji = "[CRITICAL]" if sev_upper == "CRITICAL" else ("[HIGH]" if sev_upper == "HIGH" else "[ALERT]")

        blocks: List[Dict[str, Any]] = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{emoji} Security Incident Escalation: {incident_id}",
                    "emoji": True,
                },
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Incident:*\n{incident_title}"},
                    {"type": "mrkdwn", "text": f"*Severity:*\n*{sev_upper}* (Floor: {deterministic_floor.upper()})"},
                ],
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Executive Summary:*\n>{summary[:300]}...",
                },
            },
            {"type": "divider"},
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Proposed Containment Actions ({len(actions)})* - *Human Approval Required*",
                },
            },
        ]

        # Add interactive action blocks
        for action in actions:
            risk_badge = f"`[{action.risk_level.value.upper()} RISK]`"
            action_desc = f"{risk_badge} *{action.action_type.value.upper()}* -> `{action.target}`\n_{action.reason}_"

            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": action_desc},
                "accessory": {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "Approve", "emoji": True},
                    "style": "primary" if action.risk_level != ActionRiskLevel.CRITICAL else "danger",
                    "value": f"approve:{action.action_id}",
                    "action_id": f"btn_approve_{action.action_id}",
                },
            })

        return {"blocks": blocks}

    def build_pagerduty_payload(
        self,
        incident_id: str,
        incident_title: str,
        severity: str,
        summary: str,
        actions_count: int,
    ) -> Dict[str, Any]:
        """Constructs a PagerDuty Events API v2 payload."""
        pd_severity = "critical" if severity.lower() in ("critical", "high") else "warning"
        return {
            "routing_key": self.pagerduty_routing_key or "SIMULATED_KEY",
            "event_action": "trigger",
            "dedup_key": f"secops-{incident_id}",
            "payload": {
                "summary": f"[{severity.upper()}] {incident_title} ({incident_id})",
                "source": "autonomous-secops-agent",
                "severity": pd_severity,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "custom_details": {
                    "incident_id": incident_id,
                    "summary": summary,
                    "proposed_actions_count": actions_count,
                },
            },
        }

    async def dispatch_slack(
        self,
        incident_id: str,
        incident_title: str,
        severity: str,
        deterministic_floor: str,
        summary: str,
        actions: List[ProposedAction],
        webhook_url: Optional[str] = None,
    ) -> EscalationRecord:
        """Sends Slack Block Kit message to configured webhook."""
        target_url = webhook_url or self.slack_webhook_url
        payload = self.build_slack_block_kit(
            incident_id, incident_title, severity, deterministic_floor, summary, actions
        )

        escalation_id = f"ESC-SLACK-{uuid.uuid4().hex[:8].upper()}"

        if not target_url:
            rec = EscalationRecord(
                escalation_id=escalation_id,
                incident_id=incident_id,
                channel=EscalationChannel.SLACK,
                status="simulated",
                target_destination="simulated_slack_channel",
                summary=f"Dispatched Slack escalation for {incident_id} with {len(actions)} actions",
            )
            self.dispatch_history.append(rec)
            return rec

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(target_url, json=payload)
                resp.raise_for_status()
            rec = EscalationRecord(
                escalation_id=escalation_id,
                incident_id=incident_id,
                channel=EscalationChannel.SLACK,
                status="sent",
                target_destination=target_url[:35] + "...",
                summary=f"Sent Slack escalation for {incident_id} ({len(actions)} actions)",
            )
        except Exception as exc:
            logger.error(f"Failed to dispatch Slack escalation for {incident_id}: {exc}")
            rec = EscalationRecord(
                escalation_id=escalation_id,
                incident_id=incident_id,
                channel=EscalationChannel.SLACK,
                status="failed",
                target_destination=target_url[:35] + "...",
                summary=f"Failed to dispatch Slack escalation for {incident_id}",
                error_message=str(exc),
            )

        self.dispatch_history.append(rec)
        return rec

    async def dispatch_pagerduty(
        self,
        incident_id: str,
        incident_title: str,
        severity: str,
        summary: str,
        actions_count: int,
        routing_key: Optional[str] = None,
    ) -> EscalationRecord:
        """Sends PagerDuty event to Events v2 endpoint."""
        key = routing_key or self.pagerduty_routing_key
        payload = self.build_pagerduty_payload(incident_id, incident_title, severity, summary, actions_count)
        escalation_id = f"ESC-PD-{uuid.uuid4().hex[:8].upper()}"

        if not key:
            rec = EscalationRecord(
                escalation_id=escalation_id,
                incident_id=incident_id,
                channel=EscalationChannel.PAGERDUTY,
                status="simulated",
                target_destination="simulated_pagerduty",
                summary=f"Dispatched PagerDuty incident for {incident_id}",
            )
            self.dispatch_history.append(rec)
            return rec

        pd_url = "https://events.pagerduty.com/v2/enqueue"
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(pd_url, json=payload)
                resp.raise_for_status()
            rec = EscalationRecord(
                escalation_id=escalation_id,
                incident_id=incident_id,
                channel=EscalationChannel.PAGERDUTY,
                status="sent",
                target_destination="pagerduty_v2",
                summary=f"Sent PagerDuty alert for {incident_id}",
            )
        except Exception as exc:
            logger.error(f"Failed to dispatch PagerDuty alert for {incident_id}: {exc}")
            rec = EscalationRecord(
                escalation_id=escalation_id,
                incident_id=incident_id,
                channel=EscalationChannel.PAGERDUTY,
                status="failed",
                target_destination="pagerduty_v2",
                summary=f"Failed to dispatch PagerDuty alert for {incident_id}",
                error_message=str(exc),
            )

        self.dispatch_history.append(rec)
        return rec


# Singleton dispatcher
escalation_dispatcher = EscalationDispatcher()
