"""
Phase 6: Response Action Executor.

Provides safe, auditable execution of containment actions with dry-run support,
simulated execution providers (Wazuh active-response, Firewall, IAM), and rollback capabilities.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from backend.response.models import ActionType, ProposedAction

logger = logging.getLogger("secops.response.executor")


class ActionExecutionError(Exception):
    """Raised when a response action execution fails."""
    pass


class ActionExecutor:
    """
    Executes response actions against connected security infrastructure.
    Supports dry-run simulation mode (safe default) and live execution.
    All actions and rollbacks produce timestamped audit receipts.
    """

    def __init__(self, default_dry_run: bool = True):
        self.default_dry_run = default_dry_run
        self.execution_history: List[Dict[str, Any]] = []

    def execute(self, action: ProposedAction, dry_run: Optional[bool] = None) -> Dict[str, Any]:
        """
        Execute the proposed containment action.
        
        Args:
            action: The approved ProposedAction to execute.
            dry_run: If True, simulate execution without affecting actual infrastructure.
                     Defaults to instance default (True).
        """
        is_dry_run = self.default_dry_run if dry_run is None else dry_run
        now_str = datetime.now(timezone.utc).isoformat()

        logger.info(
            f"Executing {action.action_type.value} on '{action.target}' "
            f"(incident={action.incident_id}, dry_run={is_dry_run})"
        )

        handler_map = {
            ActionType.ISOLATE_HOST: self._execute_isolate_host,
            ActionType.BLOCK_IP: self._execute_block_ip,
            ActionType.DISABLE_USER: self._execute_disable_user,
            ActionType.REVOKE_TOKENS: self._execute_revoke_tokens,
            ActionType.KILL_PROCESS: self._execute_kill_process,
            ActionType.CUSTOM: self._execute_custom,
        }

        handler = handler_map.get(action.action_type)
        if not handler:
            raise ActionExecutionError(f"Unsupported action type: {action.action_type}")

        try:
            result_payload = handler(action, is_dry_run)
            receipt = {
                "action_id": action.action_id,
                "incident_id": action.incident_id,
                "action_type": action.action_type.value,
                "target": action.target,
                "dry_run": is_dry_run,
                "executed_at": now_str,
                "status": "success",
                "details": result_payload,
            }
            self.execution_history.append(receipt)
            return receipt
        except Exception as exc:
            receipt = {
                "action_id": action.action_id,
                "incident_id": action.incident_id,
                "action_type": action.action_type.value,
                "target": action.target,
                "dry_run": is_dry_run,
                "executed_at": now_str,
                "status": "failed",
                "error": str(exc),
            }
            self.execution_history.append(receipt)
            raise ActionExecutionError(f"Execution failed for {action.action_id}: {exc}") from exc

    def rollback(self, action: ProposedAction, dry_run: Optional[bool] = None) -> Dict[str, Any]:
        """
        Reverses an executed containment action.
        
        Args:
            action: The executed ProposedAction to roll back.
            dry_run: Simulation flag.
        """
        if not action.is_reversible:
            raise ActionExecutionError(
                f"Action {action.action_id} of type {action.action_type.value} is marked non-reversible."
            )

        is_dry_run = self.default_dry_run if dry_run is None else dry_run
        now_str = datetime.now(timezone.utc).isoformat()

        logger.info(
            f"Rolling back {action.action_type.value} on '{action.target}' "
            f"(incident={action.incident_id}, dry_run={is_dry_run})"
        )

        rollback_map = {
            ActionType.ISOLATE_HOST: self._rollback_isolate_host,
            ActionType.BLOCK_IP: self._rollback_block_ip,
            ActionType.DISABLE_USER: self._rollback_disable_user,
            ActionType.REVOKE_TOKENS: self._rollback_revoke_tokens,
            ActionType.KILL_PROCESS: self._rollback_kill_process,
            ActionType.CUSTOM: self._rollback_custom,
        }

        handler = rollback_map.get(action.action_type)
        if not handler:
            raise ActionExecutionError(f"No rollback procedure for action type: {action.action_type}")

        result_payload = handler(action, is_dry_run)
        receipt = {
            "action_id": action.action_id,
            "incident_id": action.incident_id,
            "action_type": action.action_type.value,
            "target": action.target,
            "dry_run": is_dry_run,
            "rolled_back_at": now_str,
            "status": "rolled_back",
            "details": result_payload,
        }
        self.execution_history.append(receipt)
        return receipt

    # ---- Implementation handlers ----

    def _execute_isolate_host(self, action: ProposedAction, dry_run: bool) -> Dict[str, Any]:
        return {
            "mechanism": "EDR_Network_Containment",
            "host": action.target,
            "isolated": True,
            "allowed_exceptions": ["EDR Management Agent (TCP 1514)", "DHCP (UDP 67/68)"],
            "message": f"Host '{action.target}' network traffic contained to SecOps management.",
        }

    def _rollback_isolate_host(self, action: ProposedAction, dry_run: bool) -> Dict[str, Any]:
        return {
            "mechanism": "EDR_Network_Containment",
            "host": action.target,
            "isolated": False,
            "message": f"Host '{action.target}' network containment released; full connectivity restored.",
        }

    def _execute_block_ip(self, action: ProposedAction, dry_run: bool) -> Dict[str, Any]:
        rule_name = f"SEC-AUTO-BLOCK-{action.target.replace('.', '_')}"
        return {
            "mechanism": "Edge_Firewall_NullRoute",
            "ip": action.target,
            "rule_id": rule_name,
            "action": "DROP_ALL_INBOUND_OUTBOUND",
            "message": f"IP '{action.target}' null-routed at edge perimeter firewall.",
        }

    def _rollback_block_ip(self, action: ProposedAction, dry_run: bool) -> Dict[str, Any]:
        rule_name = f"SEC-AUTO-BLOCK-{action.target.replace('.', '_')}"
        return {
            "mechanism": "Edge_Firewall_NullRoute",
            "ip": action.target,
            "rule_id": rule_name,
            "action": "REMOVED",
            "message": f"Firewall rule '{rule_name}' for IP '{action.target}' removed.",
        }

    def _execute_disable_user(self, action: ProposedAction, dry_run: bool) -> Dict[str, Any]:
        return {
            "mechanism": "Identity_Provider_Directory",
            "user": action.target,
            "account_status": "LOCKED_DISABLED",
            "sessions_terminated": True,
            "message": f"User account '{action.target}' disabled and all active sessions revoked.",
        }

    def _rollback_disable_user(self, action: ProposedAction, dry_run: bool) -> Dict[str, Any]:
        return {
            "mechanism": "Identity_Provider_Directory",
            "user": action.target,
            "account_status": "ACTIVE_ENABLED",
            "message": f"User account '{action.target}' re-enabled. Password reset required on next login.",
        }

    def _execute_revoke_tokens(self, action: ProposedAction, dry_run: bool) -> Dict[str, Any]:
        return {
            "mechanism": "OAuth_Kerberos_Session_Manager",
            "user": action.target,
            "tokens_revoked": ["refresh_token", "access_token", "kerberos_tgt"],
            "message": f"All active tokens and TGTs for '{action.target}' invalidated.",
        }

    def _rollback_revoke_tokens(self, action: ProposedAction, dry_run: bool) -> Dict[str, Any]:
        return {
            "mechanism": "OAuth_Kerberos_Session_Manager",
            "user": action.target,
            "message": "Tokens cannot be un-revoked. User must re-authenticate to obtain new credentials.",
        }

    def _execute_kill_process(self, action: ProposedAction, dry_run: bool) -> Dict[str, Any]:
        pid = action.parameters.get("pid", "unknown")
        return {
            "mechanism": "EDR_Process_Termination",
            "target": action.target,
            "pid": pid,
            "signal": "SIGKILL (9)",
            "message": f"Process '{action.target}' (PID {pid}) forcibly terminated.",
        }

    def _rollback_kill_process(self, action: ProposedAction, dry_run: bool) -> Dict[str, Any]:
        return {
            "mechanism": "EDR_Process_Termination",
            "target": action.target,
            "message": "Terminated process cannot be rolled back. Service restart required if needed.",
        }

    def _execute_custom(self, action: ProposedAction, dry_run: bool) -> Dict[str, Any]:
        command = action.parameters.get("command", "none")
        return {
            "mechanism": "Custom_Remediation_Playbook",
            "command": command,
            "message": f"Custom action executed: {command}",
        }

    def _rollback_custom(self, action: ProposedAction, dry_run: bool) -> Dict[str, Any]:
        return {
            "mechanism": "Custom_Remediation_Playbook",
            "message": "Custom action rollback invoked.",
        }


# Singleton executor with dry-run default
action_executor = ActionExecutor(default_dry_run=True)
