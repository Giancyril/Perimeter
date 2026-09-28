"""
Phase 6: Human-in-the-Loop Response Manager.

Coordinates action proposal generation, approval/rejection lifecycle,
safe execution gating, asset risk tier enforcement, and escalation dispatch.
"""
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from backend.response.models import (
    ActionType,
    ActionRiskLevel,
    ActionStatus,
    ProposedAction,
    EscalationChannel,
    EscalationRecord,
)
from backend.response.executor import action_executor, ActionExecutor
from backend.response.escalation import escalation_dispatcher, EscalationDispatcher
from backend.severity.models import AssetCriticalityTier

logger = logging.getLogger("secops.response.manager")


class ResponseManager:
    """
    Central registry and governance gate for all response and containment actions.
    Ensures high-impact actions cannot execute without verified human analyst authorization.
    """

    def __init__(
        self,
        executor: Optional[ActionExecutor] = None,
        dispatcher: Optional[EscalationDispatcher] = None,
    ):
        self.executor = executor or action_executor
        self.dispatcher = dispatcher or escalation_dispatcher
        self._actions: Dict[str, ProposedAction] = {}

    def propose_actions_from_state(self, state: Dict[str, Any]) -> List[ProposedAction]:
        """
        Translates investigation recommended actions and state into structured, risk-classified ProposedActions.
        
        Args:
            state: InvestigationState dict from the LangGraph investigation agent.
            
        Returns:
            List of created ProposedAction models added to the manager's registry.
        """
        incident = state.get("incident")
        if not incident:
            return []

        incident_id = incident.incident_id
        recommended_actions = state.get("recommended_actions", [])
        asset_context = state.get("asset_context", {})
        lateral_paths = state.get("lateral_movement_paths", [])
        threat_intel = state.get("threat_intel", {})

        proposed_list: List[ProposedAction] = []

        # 1. Evaluate explicit recommended actions
        for rec_text in recommended_actions:
            rec_lower = rec_text.lower()
            action_type = ActionType.CUSTOM
            target = "system"
            reason = rec_text
            risk = ActionRiskLevel.MEDIUM

            if "isolate" in rec_lower:
                action_type = ActionType.ISOLATE_HOST
                # Find target host mentioned
                for h in asset_context.keys():
                    if h.lower() in rec_lower:
                        target = h
                        break
                if target == "system" and hasattr(incident, "entities"):
                    for e in incident.entities:
                        if (e.type.value if hasattr(e.type, "value") else str(e.type)) == "host":
                            target = e.value
                            break

                # Critical asset check
                asset_data = asset_context.get(target, {})
                if asset_data.get("criticality") == AssetCriticalityTier.TIER_0_CRITICAL.value:
                    risk = ActionRiskLevel.CRITICAL
                else:
                    risk = ActionRiskLevel.HIGH

            elif "block" in rec_lower:
                action_type = ActionType.BLOCK_IP
                for ip, ti in threat_intel.items():
                    if ip in rec_text or ti.get("verdict") == "malicious":
                        target = ip
                        break
                if target == "system" and incident.primary_entity:
                    target = incident.primary_entity
                risk = ActionRiskLevel.MEDIUM

            elif "disable" in rec_lower or "credential" in rec_lower:
                action_type = ActionType.DISABLE_USER
                for e in getattr(incident, "entities", []):
                    etype = e.type.value if hasattr(e.type, "value") else str(e.type)
                    if etype == "user":
                        target = e.value
                        break
                risk = ActionRiskLevel.HIGH

            elif "revoke" in rec_lower or "token" in rec_lower:
                action_type = ActionType.REVOKE_TOKENS
                for e in getattr(incident, "entities", []):
                    etype = e.type.value if hasattr(e.type, "value") else str(e.type)
                    if etype == "user":
                        target = e.value
                        break
                risk = ActionRiskLevel.MEDIUM

            elif "kill" in rec_lower or "terminate" in rec_lower:
                action_type = ActionType.KILL_PROCESS
                risk = ActionRiskLevel.HIGH

            action_id = f"ACT-{incident_id}-{uuid.uuid4().hex[:6].upper()}"
            action = ProposedAction(
                action_id=action_id,
                incident_id=incident_id,
                action_type=action_type,
                target=target,
                risk_level=risk,
                status=ActionStatus.PENDING_APPROVAL,
                reason=reason,
                proposed_at=datetime.now(timezone.utc),
                proposed_by="investigation_agent",
            )
            self._actions[action_id] = action
            proposed_list.append(action)

        # 2. Defensive fallback: if lateral movement was detected, ensure host isolation is proposed
        if lateral_paths and not any(a.action_type == ActionType.ISOLATE_HOST for a in proposed_list):
            src_host = lateral_paths[0].split(" -> ")[0]
            action_id = f"ACT-{incident_id}-{uuid.uuid4().hex[:6].upper()}"
            action = ProposedAction(
                action_id=action_id,
                incident_id=incident_id,
                action_type=ActionType.ISOLATE_HOST,
                target=src_host,
                risk_level=ActionRiskLevel.HIGH,
                status=ActionStatus.PENDING_APPROVAL,
                reason=f"Lateral movement origin: multi-host pivot confirmed ({len(lateral_paths)} path(s))",
                proposed_at=datetime.now(timezone.utc),
                proposed_by="investigation_agent",
            )
            self._actions[action_id] = action
            proposed_list.append(action)

        return proposed_list

    def list_actions(
        self,
        incident_id: Optional[str] = None,
        status: Optional[ActionStatus] = None,
    ) -> List[ProposedAction]:
        """Returns registered actions filtered by incident ID or status."""
        actions = list(self._actions.values())
        if incident_id:
            actions = [a for a in actions if a.incident_id == incident_id]
        if status:
            actions = [a for a in actions if a.status == status]
        return actions

    def get_action(self, action_id: str) -> Optional[ProposedAction]:
        """Fetches action by ID."""
        return self._actions.get(action_id)

    def approve_action(
        self,
        action_id: str,
        analyst_id: str,
        notes: Optional[str] = None,
        auto_execute: bool = True,
        dry_run: Optional[bool] = None,
    ) -> ProposedAction:
        """
        Analyst approval gate. Transitions action to APPROVED and executes if requested.
        """
        action = self.get_action(action_id)
        if not action:
            raise KeyError(f"Action '{action_id}' not found.")

        if action.status not in (ActionStatus.PROPOSED, ActionStatus.PENDING_APPROVAL):
            raise ValueError(f"Action '{action_id}' is already {action.status.value}; cannot approve.")

        now = datetime.now(timezone.utc)
        action.approved_by = analyst_id
        action.approved_at = now
        action.approval_notes = notes
        action.status = ActionStatus.APPROVED

        logger.info(f"Action {action_id} approved by analyst {analyst_id}.")

        if auto_execute:
            action.status = ActionStatus.EXECUTING
            try:
                receipt = self.executor.execute(action, dry_run=dry_run)
                action.status = ActionStatus.EXECUTED
                action.executed_at = datetime.now(timezone.utc)
                action.execution_result = receipt
            except Exception as exc:
                action.status = ActionStatus.FAILED
                action.execution_result = {"error": str(exc)}
                logger.error(f"Execution error on action {action_id}: {exc}")

        return action

    def reject_action(
        self,
        action_id: str,
        analyst_id: str,
        reason: Optional[str] = None,
    ) -> ProposedAction:
        """Analyst rejection gate. Transitions action to REJECTED with mandatory audit reason."""
        action = self.get_action(action_id)
        if not action:
            raise KeyError(f"Action '{action_id}' not found.")

        if action.status not in (ActionStatus.PROPOSED, ActionStatus.PENDING_APPROVAL):
            raise ValueError(f"Action '{action_id}' is in status {action.status.value}; cannot reject.")

        now = datetime.now(timezone.utc)
        action.rejected_by = analyst_id
        action.rejected_at = now
        action.rejection_reason = reason or "Analyst declined containment action"
        action.status = ActionStatus.REJECTED

        logger.info(f"Action {action_id} rejected by analyst {analyst_id}. Reason: {reason}")
        return action

    def rollback_action(
        self,
        action_id: str,
        analyst_id: str,
        dry_run: Optional[bool] = None,
    ) -> ProposedAction:
        """Reverses an executed containment action."""
        action = self.get_action(action_id)
        if not action:
            raise KeyError(f"Action '{action_id}' not found.")

        if action.status != ActionStatus.EXECUTED:
            raise ValueError(f"Cannot roll back action {action_id} with status {action.status.value}.")

        now = datetime.now(timezone.utc)
        receipt = self.executor.rollback(action, dry_run=dry_run)
        action.status = ActionStatus.ROLLED_BACK
        action.rolled_back_at = now
        action.rolled_back_by = analyst_id
        action.rollback_result = receipt

        logger.info(f"Action {action_id} rolled back by analyst {analyst_id}.")
        return action

    async def escalate_incident(
        self,
        incident: Any,
        summary: str,
        channel: EscalationChannel = EscalationChannel.SLACK,
        webhook_url: Optional[str] = None,
    ) -> EscalationRecord:
        """Triggers outbound notification for an incident along with its proposed actions."""
        incident_id = incident.incident_id
        actions = self.list_actions(incident_id=incident_id)

        sev_str = incident.severity.value if hasattr(incident.severity, "value") else str(incident.severity)
        floor_str = (
            incident.deterministic_floor.value
            if hasattr(incident.deterministic_floor, "value")
            else str(incident.deterministic_floor)
        )

        if channel == EscalationChannel.SLACK:
            return await self.dispatcher.dispatch_slack(
                incident_id=incident_id,
                incident_title=incident.title,
                severity=sev_str,
                deterministic_floor=floor_str,
                summary=summary,
                actions=actions,
                webhook_url=webhook_url,
            )
        elif channel == EscalationChannel.PAGERDUTY:
            return await self.dispatcher.dispatch_pagerduty(
                incident_id=incident_id,
                incident_title=incident.title,
                severity=sev_str,
                summary=summary,
                actions_count=len(actions),
            )
        else:
            raise ValueError(f"Unsupported escalation channel: {channel}")


# Singleton response manager
response_manager = ResponseManager()
