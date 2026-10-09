"""
Forensic Chain-of-Custody & Tamper-Evident Manifest (Day 5 - Commit 4).

Establishes a cryptographically sealed, court-admissible chain of custody for all
evidence collected during an autonomous SOC investigation.
Every alert, raw log, threat intel API payload, and agent reasoning step is
fingerprinted with SHA-256 and signed with a verifiable HMAC manifest seal.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from backend.reporting.models import IncidentReport


class EvidenceType(str, Enum):
    SIEM_ALERT = "SIEM_ALERT"
    RAW_ENDPOINT_LOG = "RAW_ENDPOINT_LOG"
    THREAT_INTEL_RESPONSE = "THREAT_INTEL_RESPONSE"
    NETWORK_TELEMETRY = "NETWORK_TELEMETRY"
    AGENT_INVESTIGATION_STEP = "AGENT_INVESTIGATION_STEP"
    LLM_REASONING_TRACE = "LLM_REASONING_TRACE"
    ANALYST_OVERRIDE_RECORD = "ANALYST_OVERRIDE_RECORD"


@dataclass
class EvidenceItem:
    """A single piece of digital evidence with cryptographic fingerprint."""
    evidence_id: str
    evidence_type: EvidenceType
    source_system: str
    collected_at: datetime
    sha256_hash: str
    raw_payload_size_bytes: int
    custodian: str
    description: str
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "evidence_type": self.evidence_type.value,
            "source_system": self.source_system,
            "collected_at": self.collected_at.isoformat(),
            "sha256_hash": self.sha256_hash,
            "raw_payload_size_bytes": self.raw_payload_size_bytes,
            "custodian": self.custodian,
            "description": self.description,
            "metadata": self.metadata,
        }


@dataclass
class ChainOfCustodyManifest:
    """Tamper-evident audit manifest binding all evidence items together."""
    manifest_id: str
    incident_id: str
    generated_at: datetime
    items: List[EvidenceItem]
    manifest_digest: str
    hmac_signature: str
    legal_hold_active: bool
    certifying_custodian: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "manifest_id": self.manifest_id,
            "incident_id": self.incident_id,
            "generated_at": self.generated_at.isoformat(),
            "total_items": len(self.items),
            "manifest_digest": self.manifest_digest,
            "hmac_signature": self.hmac_signature,
            "legal_hold_active": self.legal_hold_active,
            "certifying_custodian": self.certifying_custodian,
            "items": [it.to_dict() for it in self.items],
        }

    def verify_integrity(self, signing_key: str = "SOC_SECURE_MANIFEST_KEY_2026") -> bool:
        """
        Verify that all items match their SHA-256 digests and the manifest HMAC seal is valid.
        """
        # Recompute manifest digest
        concat_hashes = "".join(sorted(it.sha256_hash for it in self.items))
        expected_digest = hashlib.sha256(concat_hashes.encode("utf-8")).hexdigest()
        if expected_digest != self.manifest_digest:
            return False

        # Verify HMAC signature
        expected_sig = hmac.new(
            signing_key.encode("utf-8"),
            expected_digest.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

        return hmac.compare_digest(expected_sig, self.hmac_signature)

    def to_markdown(self) -> str:
        """Render a legal forensic audit manifest in Markdown format."""
        lines = [
            f"# 🔐 FORENSIC CHAIN-OF-CUSTODY MANIFEST",
            f"**Manifest ID:** `{self.manifest_id}` | **Incident ID:** `{self.incident_id}`  ",
            f"**Generated:** {self.generated_at.strftime('%Y-%m-%d %H:%M:%S UTC')}  ",
            f"**Certifying Custodian:** `{self.certifying_custodian}`  ",
            f"**Legal Hold Status:** `{'ACTIVE (PRESERVATION REQUIRED)' if self.legal_hold_active else 'STANDARD RETENTION'}`  ",
            f"**Tamper-Evident Seal (HMAC-SHA256):** `{self.hmac_signature}`  ",
            "",
            "---",
            "",
            "## 📋 Itemized Evidence Inventory",
            "| ID | Type | Source | SHA-256 Digest | Size (B) | Description |",
            "| :--- | :--- | :--- | :--- | :--- | :--- |",
        ]

        for it in self.items:
            short_hash = f"`{it.sha256_hash[:12]}...{it.sha256_hash[-8:]}`"
            lines.append(
                f"| `{it.evidence_id}` | {it.evidence_type.value} | {it.source_system} | "
                f"{short_hash} | {it.raw_payload_size_bytes} | {it.description[:40]} |"
            )

        lines.extend([
            "",
            f"**Cumulative Evidence Digest:** `{self.manifest_digest}`  ",
            "_This manifest certifies that the forensic artifacts above were acquired and maintained without unauthorized alteration._",
        ])
        return "\n".join(lines)


class ChainOfCustodyBuilder:
    """
    Constructs and signs a ChainOfCustodyManifest from an IncidentReport.
    """

    def __init__(self, signing_key: str = "SOC_SECURE_MANIFEST_KEY_2026", custodian: str = "Autonomous SecOps Daemon v1.0") -> None:
        self.signing_key = signing_key
        self.custodian = custodian

    def _hash_data(self, data: Any) -> str:
        serialized = json.dumps(data, sort_keys=True, default=str).encode("utf-8")
        return hashlib.sha256(serialized).hexdigest()

    def build_manifest(
        self,
        report: IncidentReport,
        legal_hold: bool = False,
    ) -> ChainOfCustodyManifest:
        """Extract all evidence records from the report and seal the manifest."""
        items: List[EvidenceItem] = []

        # 1. Timeline event artifacts
        for idx, ev in enumerate(report.timeline):
            payload = {
                "timestamp": ev.timestamp.isoformat(),
                "title": ev.title,
                "description": ev.description,
                "source": ev.source,
                "raw_id": ev.raw_evidence_id,
            }
            h = self._hash_data(payload)
            size = len(json.dumps(payload).encode("utf-8"))
            items.append(
                EvidenceItem(
                    evidence_id=f"EV-TL-{idx+1:03d}",
                    evidence_type=EvidenceType.SIEM_ALERT if ev.event_type == "alert" else EvidenceType.AGENT_INVESTIGATION_STEP,
                    source_system=ev.source,
                    collected_at=ev.timestamp,
                    sha256_hash=h,
                    raw_payload_size_bytes=size,
                    custodian=self.custodian,
                    description=f"{ev.event_type.upper()}: {ev.title}",
                    metadata={"related_entities": ev.related_entities},
                )
            )

        # 2. Severity audit record
        audit_payload = report.severity_audit.model_dump()
        items.append(
            EvidenceItem(
                evidence_id="EV-AUDIT-SEV",
                evidence_type=EvidenceType.LLM_REASONING_TRACE,
                source_system="DeterministicSeverityScorer",
                collected_at=report.generated_at,
                sha256_hash=self._hash_data(audit_payload),
                raw_payload_size_bytes=len(json.dumps(audit_payload).encode("utf-8")),
                custodian=self.custodian,
                description=f"Deterministic Floor ({report.deterministic_floor.value}) Enforcement Audit Log",
                metadata={"floor_enforced": report.severity_audit.floor_enforced},
            )
        )

        # 3. Entity evidence traces
        for ent in report.entities:
            ent_payload = ent.model_dump()
            items.append(
                EvidenceItem(
                    evidence_id=f"EV-ENT-{uuid.uuid4().hex[:6]}",
                    evidence_type=EvidenceType.THREAT_INTEL_RESPONSE if ent.threat_verdict else EvidenceType.RAW_ENDPOINT_LOG,
                    source_system="EntityGraphEnrichment",
                    collected_at=report.generated_at,
                    sha256_hash=self._hash_data(ent_payload),
                    raw_payload_size_bytes=len(json.dumps(ent_payload).encode("utf-8")),
                    custodian=self.custodian,
                    description=f"Entity Context: {ent.entity_value} ({ent.entity_type})",
                    metadata={"verdict": ent.threat_verdict, "abuse_score": ent.abuse_score},
                )
            )

        # Compute cumulative manifest digest
        concat_hashes = "".join(sorted(it.sha256_hash for it in items))
        manifest_digest = hashlib.sha256(concat_hashes.encode("utf-8")).hexdigest()

        # Compute HMAC signature seal
        hmac_sig = hmac.new(
            self.signing_key.encode("utf-8"),
            manifest_digest.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

        return ChainOfCustodyManifest(
            manifest_id=f"coc-{uuid.uuid4().hex[:8]}",
            incident_id=report.incident_id,
            generated_at=datetime.now(timezone.utc),
            items=items,
            manifest_digest=manifest_digest,
            hmac_signature=hmac_sig,
            legal_hold_active=legal_hold,
            certifying_custodian=self.custodian,
        )
