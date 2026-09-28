"""
Phase 6: Response Action Models & Human-in-the-Loop State Definitions.

Defines the action catalog, risk levels, lifecycle states, and audit models
governing autonomous proposals and human-gated containment execution.
"""
from __future__ import annotations

from enum import Enum
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ActionType(str, Enum):
    """Categorized response action types supported by the response execution engine."""
    ISOLATE_HOST = "isolate_host"        # Network isolation via EDR/firewall
    BLOCK_IP = "block_ip"                # Edge firewall blocklist
    DISABLE_USER = "disable_user"        # Active Directory / IAM credential disable
    REVOKE_TOKENS = "revoke_tokens"      # Revoke OAuth/Kerberos/JWT sessions
    KILL_PROCESS = "kill_process"        # Terminate rogue endpoint process
    CUSTOM = "custom"                    # Custom analyst-defined action


class ActionRiskLevel(str, Enum):
    """
    Risk tier defining the required approval threshold:
    - LOW: Non-disruptive, eligible for automated execution if policy allows.
    - MEDIUM: Moderate operational impact.
    - HIGH: Service-affecting containment; requires standard human analyst approval.
    - CRITICAL: High-blast-radius containment (e.g. Domain Controller, Core DB);
                requires senior analyst sign-off and explicit justification.
    """
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ActionStatus(str, Enum):
    """Lifecycle state of a response action."""
    PROPOSED = "proposed"              # Formulated by the investigation agent
    PENDING_APPROVAL = "pending_approval" # Queued awaiting human analyst decision
    APPROVED = "approved"              # Approved by analyst, queued for executor
    REJECTED = "rejected"              # Rejected by analyst with rationale
    EXECUTING = "executing"            # In-flight execution
    EXECUTED = "executed"              # Successfully completed
    FAILED = "failed"                  # Execution encountered an error
    ROLLED_BACK = "rolled_back"        # Containment was successfully reversed


class ProposedAction(BaseModel):
    """
    Structured response action proposed by the investigation agent or created by an analyst.
    Enforces strict auditability with approval metadata and reversible rollback support.
    """
    action_id: str
    incident_id: str
    action_type: ActionType
    target: str                          # IP, hostname, username, or process name
    parameters: Dict[str, Any] = Field(default_factory=dict)
    risk_level: ActionRiskLevel
    status: ActionStatus = ActionStatus.PROPOSED
    
    # Proposal metadata
    proposed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    proposed_by: str = "investigation_agent"
    reason: str

    # Human-in-the-loop decision trail
    approved_by: Optional[str] = None
    approved_at: Optional[datetime] = None
    approval_notes: Optional[str] = None
    rejected_by: Optional[str] = None
    rejected_at: Optional[datetime] = None
    rejection_reason: Optional[str] = None

    # Execution & Rollback trail
    executed_at: Optional[datetime] = None
    execution_result: Optional[Dict[str, Any]] = None
    is_reversible: bool = True
    rolled_back_at: Optional[datetime] = None
    rolled_back_by: Optional[str] = None
    rollback_result: Optional[Dict[str, Any]] = None


class ActionDecisionRequest(BaseModel):
    """Payload for human analyst approval or rejection decisions."""
    analyst_id: str
    notes: Optional[str] = None
    reason: Optional[str] = None


class EscalationChannel(str, Enum):
    """Notification channels for incident alerting and approval requests."""
    SLACK = "slack"
    PAGERDUTY = "pagerduty"
    EMAIL = "email"
    WEBHOOK = "webhook"


class EscalationRecord(BaseModel):
    """Audit record of an outbound escalation notification dispatch."""
    escalation_id: str
    incident_id: str
    channel: EscalationChannel
    dispatched_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    status: str                         # "sent" | "simulated" | "failed"
    target_destination: str             # Channel name or webhook endpoint URL
    summary: str
    error_message: Optional[str] = None
