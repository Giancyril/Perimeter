"""
Hardened Non-Downgrade Invariant & Audit Floor Enforcer for Severity Engine.

Guarantees the core security invariant: final_severity >= deterministic_floor.
Blocks LLM hallucinations, prompt injections, and adversarial overrides from
downgrading critical/high incidents. Emits cryptographically verifiable audit proofs.
"""
from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from backend.ingestion.models import SeverityLevel


SEVERITY_RANK: Dict[SeverityLevel, int] = {
    SeverityLevel.INFORMATIONAL: 0,
    SeverityLevel.LOW: 1,
    SeverityLevel.MEDIUM: 2,
    SeverityLevel.HIGH: 3,
    SeverityLevel.CRITICAL: 4,
}


class DowngradeViolationType(str, Enum):
    LLM_DOWNGRADE_ATTEMPT = "LLM_DOWNGRADE_ATTEMPT"
    RULE_OVERRIDE_VIOLATION = "RULE_OVERRIDE_VIOLATION"
    PROMPT_INJECTION_TAMPERING = "PROMPT_INJECTION_TAMPERING"
    UNTRUSTED_METADATA_SPOOF = "UNTRUSTED_METADATA_SPOOF"


@dataclass
class FloorEnforcementRecord:
    record_id: str
    incident_id: str
    deterministic_floor: SeverityLevel
    proposed_severity: SeverityLevel
    enforced_severity: SeverityLevel
    downgrade_prevented: bool
    violation_type: Optional[DowngradeViolationType] = None
    audit_hash: str = ""
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    explanation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "record_id": self.record_id,
            "incident_id": self.incident_id,
            "deterministic_floor": self.deterministic_floor.value,
            "proposed_severity": self.proposed_severity.value,
            "enforced_severity": self.enforced_severity.value,
            "downgrade_prevented": self.downgrade_prevented,
            "violation_type": self.violation_type.value if self.violation_type else None,
            "audit_hash": self.audit_hash,
            "timestamp": self.timestamp.isoformat(),
            "explanation": self.explanation,
        }


class HardenedFloorEnforcer:
    """Enforces non-downgrade invariants and maintains cryptographic enforcement ledger."""

    def __init__(self) -> None:
        self._audit_log: List[FloorEnforcementRecord] = []

    def _compute_audit_hash(
        self,
        incident_id: str,
        floor: SeverityLevel,
        proposed: SeverityLevel,
        enforced: SeverityLevel,
        iso_ts: str,
    ) -> str:
        payload = f"{incident_id}|{floor.value}|{proposed.value}|{enforced.value}|{iso_ts}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def enforce(
        self,
        incident_id: str,
        deterministic_floor: SeverityLevel,
        proposed_severity: SeverityLevel,
        adversarial_injection_detected: bool = False,
        justification: Optional[str] = None,
    ) -> FloorEnforcementRecord:
        """Strictly enforces the floor. If proposed < floor, clamps to floor and logs violation."""
        floor_rank = SEVERITY_RANK[deterministic_floor]
        proposed_rank = SEVERITY_RANK[proposed_severity]

        now = datetime.now(timezone.utc)
        iso_ts = now.isoformat()
        rec_id = f"enf-{uuid.uuid4().hex[:10]}"

        if proposed_rank < floor_rank:
            # Downgrade attempt blocked!
            enforced = deterministic_floor
            downgrade_prevented = True
            v_type = (
                DowngradeViolationType.PROMPT_INJECTION_TAMPERING
                if adversarial_injection_detected
                else DowngradeViolationType.LLM_DOWNGRADE_ATTEMPT
            )
            explanation = (
                f"SECURITY INVARIANT ENFORCED: Proposed severity '{proposed_severity.value}' is lower "
                f"than deterministic floor '{deterministic_floor.value}'. Clamped to floor. "
                f"Reason: {v_type.value}. Justification rejected: '{justification or 'None provided'}'."
            )
        else:
            # Upgrade or equal is valid
            enforced = proposed_severity
            downgrade_prevented = False
            v_type = None
            explanation = (
                f"Proposed severity '{proposed_severity.value}' satisfies or exceeds "
                f"deterministic floor '{deterministic_floor.value}'."
            )

        audit_hash = self._compute_audit_hash(
            incident_id=incident_id,
            floor=deterministic_floor,
            proposed=proposed_severity,
            enforced=enforced,
            iso_ts=iso_ts,
        )

        record = FloorEnforcementRecord(
            record_id=rec_id,
            incident_id=incident_id,
            deterministic_floor=deterministic_floor,
            proposed_severity=proposed_severity,
            enforced_severity=enforced,
            downgrade_prevented=downgrade_prevented,
            violation_type=v_type,
            audit_hash=audit_hash,
            timestamp=now,
            explanation=explanation,
        )

        self._audit_log.append(record)
        return record

    def verify_audit_proof(self, record: FloorEnforcementRecord) -> bool:
        """Validates that the audit hash matches the record properties without tampering."""
        computed = self._compute_audit_hash(
            incident_id=record.incident_id,
            floor=record.deterministic_floor,
            proposed=record.proposed_severity,
            enforced=record.enforced_severity,
            iso_ts=record.timestamp.isoformat(),
        )
        return computed == record.audit_hash

    @property
    def total_enforcements(self) -> int:
        return len(self._audit_log)

    @property
    def total_downgrades_blocked(self) -> int:
        return sum(1 for r in self._audit_log if r.downgrade_prevented)
