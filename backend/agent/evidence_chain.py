"""
Immutable Evidence Chain-of-Custody Tracker for Investigation Agent.

Maintains cryptographically linked, tamper-evident audit records of all
evidence collected during an incident investigation using SHA-256 hash chains.
Ensures forensic validity and evidence traceability from ingestion to reporting.
"""
from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


class EvidenceType(str, Enum):
    RAW_ALERT = "RAW_ALERT"
    ENDPOINT_LOG = "ENDPOINT_LOG"
    THREAT_INTEL_REPORT = "THREAT_INTEL_REPORT"
    MEMORY_SNAPSHOT = "MEMORY_SNAPSHOT"
    NETWORK_FLOW = "NETWORK_FLOW"
    FILE_ARTIFACT = "FILE_ARTIFACT"
    AGENT_REASONING = "AGENT_REASONING"
    COMMAND_EXECUTION = "COMMAND_EXECUTION"


@dataclass
class EvidenceItem:
    id: str
    evidence_type: EvidenceType
    source: str
    description: str
    raw_data: Any
    sha256_hash: str
    prev_hash: str
    chain_index: int
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    verified: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "evidence_type": self.evidence_type.value,
            "source": self.source,
            "description": self.description,
            "sha256_hash": self.sha256_hash,
            "prev_hash": self.prev_hash,
            "chain_index": self.chain_index,
            "timestamp": self.timestamp.isoformat(),
            "verified": self.verified,
        }


class EvidenceChain:
    """Tamper-evident, cryptographically chained evidence registry."""

    GENESIS_HASH = "0" * 64

    def __init__(self, incident_id: str) -> None:
        self.incident_id = incident_id
        self._items: List[EvidenceItem] = []
        self._current_hash = self.GENESIS_HASH

    @property
    def total_evidence_count(self) -> int:
        return len(self._items)

    @property
    def current_head_hash(self) -> str:
        return self._current_hash

    def _canonicalize(self, data: Any) -> str:
        if isinstance(data, (dict, list)):
            return json.dumps(data, sort_keys=True, default=str)
        return str(data)

    def _compute_hash(
        self,
        prev_hash: str,
        chain_index: int,
        evidence_type: str,
        source: str,
        payload_str: str,
        iso_timestamp: str,
    ) -> str:
        content = f"{prev_hash}|{chain_index}|{evidence_type}|{source}|{payload_str}|{iso_timestamp}"
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    def record(
        self,
        evidence_type: EvidenceType,
        source: str,
        description: str,
        raw_data: Any,
        timestamp: Optional[datetime] = None,
    ) -> EvidenceItem:
        """Records an evidence item into the chain with cryptographic linking."""
        now = timestamp or datetime.now(timezone.utc)
        iso_ts = now.isoformat()
        payload_str = self._canonicalize(raw_data)
        chain_index = len(self._items)

        item_hash = self._compute_hash(
            prev_hash=self._current_hash,
            chain_index=chain_index,
            evidence_type=evidence_type.value,
            source=source,
            payload_str=payload_str,
            iso_timestamp=iso_ts,
        )

        item = EvidenceItem(
            id=f"ev-{uuid.uuid4().hex[:10]}",
            evidence_type=evidence_type,
            source=source,
            description=description,
            raw_data=raw_data,
            sha256_hash=item_hash,
            prev_hash=self._current_hash,
            chain_index=chain_index,
            timestamp=now,
            verified=True,
        )

        self._items.append(item)
        self._current_hash = item_hash
        return item

    def verify_integrity(self) -> bool:
        """Verifies the SHA-256 chain from genesis to head without breaks."""
        expected_prev = self.GENESIS_HASH

        for idx, item in enumerate(self._items):
            if item.chain_index != idx:
                return False
            if item.prev_hash != expected_prev:
                return False

            payload_str = self._canonicalize(item.raw_data)
            computed = self._compute_hash(
                prev_hash=item.prev_hash,
                chain_index=item.chain_index,
                evidence_type=item.evidence_type.value,
                source=item.source,
                payload_str=payload_str,
                iso_timestamp=item.timestamp.isoformat(),
            )
            if computed != item.sha256_hash:
                return False

            expected_prev = item.sha256_hash

        return True

    def get_items_by_type(self, evidence_type: EvidenceType) -> List[EvidenceItem]:
        return [i for i in self._items if i.evidence_type == evidence_type]

    def export_timeline(self) -> List[Dict[str, Any]]:
        """Exports ordered chronological sequence of evidence collection."""
        sorted_items = sorted(self._items, key=lambda x: x.timestamp)
        return [item.to_dict() for item in sorted_items]

    def export_audit_manifest(self) -> Dict[str, Any]:
        """Produces a cryptographically attested summary for SOC report inclusion."""
        is_valid = self.verify_integrity()
        return {
            "incident_id": self.incident_id,
            "total_items": len(self._items),
            "head_hash": self._current_hash,
            "chain_valid": is_valid,
            "types_breakdown": {
                t.value: len(self.get_items_by_type(t)) for t in EvidenceType
            },
        }
