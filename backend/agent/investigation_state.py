"""
Investigation State Machine and Checkpoint Manager for Investigation Agent.

Enforces formal state transitions across the investigation lifecycle:
TRIAGING -> HYPOTHESIZING -> ENRICHING -> VERIFYING -> AWAITING_APPROVAL -> SYNTHESIZING -> CLOSED
Prevents illegal state skips and maintains an auditable transition ledger.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set


class InvestigationPhase(str, Enum):
    INITIALIZED = "INITIALIZED"
    TRIAGING = "TRIAGING"
    HYPOTHESIZING = "HYPOTHESIZING"
    ENRICHING_INTEL = "ENRICHING_INTEL"
    VERIFYING_EVIDENCE = "VERIFYING_EVIDENCE"
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    SYNTHESIZING_REPORT = "SYNTHESIZING_REPORT"
    ESCALATED = "ESCALATED"
    COMPLETED = "COMPLETED"
    CLOSED_FALSE_POSITIVE = "CLOSED_FALSE_POSITIVE"


@dataclass
class StateTransitionRecord:
    from_phase: InvestigationPhase
    to_phase: InvestigationPhase
    reason: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "from_phase": self.from_phase.value,
            "to_phase": self.to_phase.value,
            "reason": self.reason,
            "timestamp": self.timestamp.isoformat(),
            "metadata": self.metadata,
        }


class InvestigationStateMachine:
    """State transition validator and checkpoint manager for security investigations."""

    ALLOWED_TRANSITIONS: Dict[InvestigationPhase, Set[InvestigationPhase]] = {
        InvestigationPhase.INITIALIZED: {
            InvestigationPhase.TRIAGING,
            InvestigationPhase.CLOSED_FALSE_POSITIVE,
        },
        InvestigationPhase.TRIAGING: {
            InvestigationPhase.HYPOTHESIZING,
            InvestigationPhase.CLOSED_FALSE_POSITIVE,
            InvestigationPhase.ESCALATED,
        },
        InvestigationPhase.HYPOTHESIZING: {
            InvestigationPhase.ENRICHING_INTEL,
            InvestigationPhase.VERIFYING_EVIDENCE,
            InvestigationPhase.CLOSED_FALSE_POSITIVE,
        },
        InvestigationPhase.ENRICHING_INTEL: {
            InvestigationPhase.VERIFYING_EVIDENCE,
            InvestigationPhase.AWAITING_APPROVAL,
            InvestigationPhase.ESCALATED,
        },
        InvestigationPhase.VERIFYING_EVIDENCE: {
            InvestigationPhase.AWAITING_APPROVAL,
            InvestigationPhase.SYNTHESIZING_REPORT,
            InvestigationPhase.HYPOTHESIZING,  # Loop back if new evidence emerges
            InvestigationPhase.ESCALATED,
        },
        InvestigationPhase.AWAITING_APPROVAL: {
            InvestigationPhase.SYNTHESIZING_REPORT,
            InvestigationPhase.VERIFYING_EVIDENCE,
            InvestigationPhase.ESCALATED,
        },
        InvestigationPhase.SYNTHESIZING_REPORT: {
            InvestigationPhase.COMPLETED,
            InvestigationPhase.ESCALATED,
        },
        InvestigationPhase.ESCALATED: {
            InvestigationPhase.COMPLETED,
            InvestigationPhase.SYNTHESIZING_REPORT,
        },
        InvestigationPhase.COMPLETED: set(),  # Terminal state
        InvestigationPhase.CLOSED_FALSE_POSITIVE: set(),  # Terminal state
    }

    def __init__(self, investigation_id: Optional[str] = None) -> None:
        self.investigation_id = investigation_id or f"inv-{uuid.uuid4().hex[:8]}"
        self.current_phase = InvestigationPhase.INITIALIZED
        self.history: List[StateTransitionRecord] = []
        self.created_at = datetime.now(timezone.utc)
        self.updated_at = self.created_at

    @property
    def is_terminal(self) -> bool:
        return self.current_phase in (
            InvestigationPhase.COMPLETED,
            InvestigationPhase.CLOSED_FALSE_POSITIVE,
        )

    def can_transition(self, target_phase: InvestigationPhase) -> bool:
        """Checks if transition from current phase to target phase is legally permitted."""
        allowed = self.ALLOWED_TRANSITIONS.get(self.current_phase, set())
        return target_phase in allowed

    def transition(
        self,
        target_phase: InvestigationPhase,
        reason: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> StateTransitionRecord:
        """Executes a validated state transition and records the ledger entry."""
        if not self.can_transition(target_phase):
            raise ValueError(
                f"Illegal state transition from {self.current_phase.value} to {target_phase.value}. "
                f"Permitted destinations: {[p.value for p in self.ALLOWED_TRANSITIONS.get(self.current_phase, set())]}"
            )

        now = datetime.now(timezone.utc)
        record = StateTransitionRecord(
            from_phase=self.current_phase,
            to_phase=target_phase,
            reason=reason,
            timestamp=now,
            metadata=metadata or {},
        )

        self.history.append(record)
        self.current_phase = target_phase
        self.updated_at = now
        return record

    def to_dict(self) -> Dict[str, Any]:
        """Serializes state machine snapshot for database persistence or LangGraph checkpoint."""
        return {
            "investigation_id": self.investigation_id,
            "current_phase": self.current_phase.value,
            "is_terminal": self.is_terminal,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "transitions_count": len(self.history),
            "history": [r.to_dict() for r in self.history],
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> InvestigationStateMachine:
        """Reconstructs state machine instance from a persisted dictionary."""
        machine = cls(investigation_id=data["investigation_id"])
        machine.current_phase = InvestigationPhase(data["current_phase"])
        machine.created_at = datetime.fromisoformat(data["created_at"])
        machine.updated_at = datetime.fromisoformat(data["updated_at"])

        for h in data.get("history", []):
            rec = StateTransitionRecord(
                from_phase=InvestigationPhase(h["from_phase"]),
                to_phase=InvestigationPhase(h["to_phase"]),
                reason=h["reason"],
                timestamp=datetime.fromisoformat(h["timestamp"]),
                metadata=h.get("metadata", {}),
            )
            machine.history.append(rec)

        return machine
