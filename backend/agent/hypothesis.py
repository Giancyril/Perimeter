"""
Attack Hypothesis Engine for Investigation Agent.

Generates, evaluates, and ranks attack hypotheses based on observed alerts,
MITRE ATT&CK techniques, extracted IOCs, and entity interactions.
Supports dynamic hypothesis testing with supporting/refuting evidence tracking.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set

from backend.correlation.models import CorrelatedIncident
from backend.ingestion.models import NormalizedAlert


class HypothesisCategory(str, Enum):
    INITIAL_COMPROMISE = "INITIAL_COMPROMISE"
    CREDENTIAL_THEFT = "CREDENTIAL_THEFT"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    PERSISTENCE_ESTABLISHED = "PERSISTENCE_ESTABLISHED"
    LATERAL_MOVEMENT = "LATERAL_MOVEMENT"
    DATA_EXFILTRATION = "DATA_EXFILTRATION"
    RANSOMWARE_DEPLOYMENT = "RANSOMWARE_DEPLOYMENT"
    SUPPLY_CHAIN_ATTACK = "SUPPLY_CHAIN_ATTACK"
    INSIDER_THREAT = "INSIDER_THREAT"
    COMMAND_AND_CONTROL = "COMMAND_AND_CONTROL"


class HypothesisStatus(str, Enum):
    UNVERIFIED = "UNVERIFIED"
    SUPPORTED = "SUPPORTED"
    REFUTED = "REFUTED"
    INCONCLUSIVE = "INCONCLUSIVE"


class HypothesisConfidence(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    VERY_HIGH = "VERY_HIGH"


@dataclass
class AttackHypothesis:
    id: str
    title: str
    category: HypothesisCategory
    description: str
    confidence: float  # 0.0 to 1.0
    confidence_level: HypothesisConfidence
    status: HypothesisStatus = HypothesisStatus.UNVERIFIED
    supporting_evidence: List[str] = field(default_factory=list)
    refuting_evidence: List[str] = field(default_factory=list)
    recommended_verifications: List[str] = field(default_factory=list)
    mitre_tactics: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    target_entities: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "category": self.category.value,
            "description": self.description,
            "confidence": round(self.confidence, 3),
            "confidence_level": self.confidence_level.value,
            "status": self.status.value,
            "supporting_evidence": self.supporting_evidence,
            "refuting_evidence": self.refuting_evidence,
            "recommended_verifications": self.recommended_verifications,
            "mitre_tactics": self.mitre_tactics,
            "mitre_techniques": self.mitre_techniques,
            "target_entities": self.target_entities,
        }


class HypothesisEngine:
    """Generates and tests threat hypotheses for correlated incidents."""

    def __init__(self) -> None:
        self._pattern_catalog = self._build_catalog()

    def _build_catalog(self) -> List[Dict[str, Any]]:
        return [
            {
                "category": HypothesisCategory.RANSOMWARE_DEPLOYMENT,
                "title": "Ransomware Pre-Deployment or Mass Encryption Activity",
                "keywords": ["encrypt", "ransom", "vssadmin", "shadowcopy", "bitlocker", "wmic shadowcopy", "wbadmin"],
                "techniques": ["T1486", "T1490"],
                "base_score": 0.85,
                "verifications": [
                    "Check endpoint process ancestry for vssadmin delete shadows",
                    "Inspect file modification velocity on network shares",
                    "Scan memory for known ransomware canary patterns",
                ],
            },
            {
                "category": HypothesisCategory.CREDENTIAL_THEFT,
                "title": "LSASS Memory Dumping / Credential Access Activity",
                "keywords": ["lsass", "mimikatz", "procdump", "ntds.dit", "sekurlsa", "sam dump", "kerberoast"],
                "techniques": ["T1003", "T1003.001", "T1558"],
                "base_score": 0.80,
                "verifications": [
                    "Review Windows Event 4624/4625 for logon anomalies",
                    "Check endpoint Sysmon Event 10 (ProcessAccess to lsass.exe)",
                    "Verify if Kerberos tickets requested with RC4 encryption",
                ],
            },
            {
                "category": HypothesisCategory.LATERAL_MOVEMENT,
                "title": "Internal Lateral Movement via Remote Service Execution",
                "keywords": ["psexec", "wmic process call", "winrm", "remote desktop", "smbexec", "dcom"],
                "techniques": ["T1021", "T1021.001", "T1021.002", "T1570"],
                "base_score": 0.75,
                "verifications": [
                    "Correlate source and destination IP SMB sessions",
                    "Audit Event ID 7045 (New Service Installed) on target hosts",
                    "Inspect internal RPC/WinRM network telemetry",
                ],
            },
            {
                "category": HypothesisCategory.DATA_EXFILTRATION,
                "title": "Staged Data Exfiltration via Encrypted / Cloud Channel",
                "keywords": ["mega.nz", "rclone", "curl -t", "exfil", "dropbox", "archive", "7z a -p"],
                "techniques": ["T1048", "T1567", "T1560"],
                "base_score": 0.70,
                "verifications": [
                    "Analyze egress flow volume to unknown external destinations",
                    "Inspect cloud storage API call frequency",
                    "Check staging directory file creation events (/tmp, %TEMP%)",
                ],
            },
            {
                "category": HypothesisCategory.PERSISTENCE_ESTABLISHED,
                "title": "Persistence Mechanism via Scheduled Task / Registry Run Key",
                "keywords": ["schtasks", "reg add", "currentversion\\run", "startup", "systemd service", "crontab"],
                "techniques": ["T1053", "T1547", "T1543"],
                "base_score": 0.65,
                "verifications": [
                    "Enumerate active scheduled tasks created within last 24h",
                    "Inspect Run and RunOnce registry key modifications",
                    "Audit root/system crontab and unit file modifications",
                ],
            },
            {
                "category": HypothesisCategory.COMMAND_AND_CONTROL,
                "title": "Beaconing or Persistent C2 Channel to Malicious Infrastructure",
                "keywords": ["beacon", "c2", "cobalt", "covenant", "dns tunnel", "powershell -enc", "reverse shell"],
                "techniques": ["T1071", "T1573", "T1090"],
                "base_score": 0.75,
                "verifications": [
                    "Examine outbound connection jitter and periodicity",
                    "Query threat intelligence reputation for destination IP/domain",
                    "Review command line arguments for encoded script blocks",
                ],
            },
            {
                "category": HypothesisCategory.PRIVILEGE_ESCALATION,
                "title": "Local Privilege Escalation to SYSTEM or Root",
                "keywords": ["privilege", "uac bypass", "setuid", "token impersonation", "cve-", "getsystem", "sudo exploit"],
                "techniques": ["T1068", "T1548", "T1134"],
                "base_score": 0.70,
                "verifications": [
                    "Verify process token elevation from standard user to SYSTEM",
                    "Check endpoint kernel patch level against active CVE list",
                    "Inspect security audit logs for SeDebugPrivilege assignment",
                ],
            },
        ]

    def _calc_confidence_level(self, score: float) -> HypothesisConfidence:
        if score >= 0.85:
            return HypothesisConfidence.VERY_HIGH
        if score >= 0.70:
            return HypothesisConfidence.HIGH
        if score >= 0.50:
            return HypothesisConfidence.MEDIUM
        return HypothesisConfidence.LOW

    def generate(
        self,
        alerts: List[NormalizedAlert],
        iocs: Optional[List[Any]] = None,
    ) -> List[AttackHypothesis]:
        """Generates and ranks attack hypotheses matching the input alerts."""
        if not alerts:
            return []

        alert_text_blobs = [
            f"{a.rule_name} {a.rule_description or ''} {a.command_line or ''}".lower()
            for a in alerts
        ]
        all_techniques: Set[str] = set()
        all_tactics: Set[str] = set()
        all_entities: Set[str] = set()

        for a in alerts:
            all_techniques.update(a.mitre_attack.techniques)
            all_tactics.update(a.mitre_attack.tactics)
            for e in a.entities:
                all_entities.add(f"{e.type.value}:{e.value}")

        hypotheses: List[AttackHypothesis] = []

        for pattern in self._pattern_catalog:
            matched_keywords = [
                kw for kw in pattern["keywords"]
                if any(kw in blob for blob in alert_text_blobs)
            ]
            matched_techniques = [
                t for t in pattern["techniques"]
                if any(t in tech or tech in t for tech in all_techniques)
            ]

            if not matched_keywords and not matched_techniques:
                continue

            score = pattern["base_score"]
            if matched_keywords and matched_techniques:
                score = min(1.0, score + 0.15)
            elif matched_keywords:
                score = max(0.40, score - 0.10)
            elif matched_techniques:
                score = max(0.50, score - 0.05)

            if len(alerts) >= 3:
                score = min(1.0, score + 0.05)

            evidence_items = []
            if matched_keywords:
                evidence_items.append(f"Keywords matched: {', '.join(matched_keywords)}")
            if matched_techniques:
                evidence_items.append(f"MITRE techniques corroborated: {', '.join(matched_techniques)}")
            evidence_items.append(f"{len(alerts)} alerts correlated across entities: {', '.join(list(all_entities)[:3])}")

            hyp = AttackHypothesis(
                id=f"hyp-{uuid.uuid4().hex[:8]}",
                title=pattern["title"],
                category=pattern["category"],
                description=f"High-confidence attack hypothesis indicating {pattern['title']}. Triggered by {len(alerts)} correlated events.",
                confidence=score,
                confidence_level=self._calc_confidence_level(score),
                status=HypothesisStatus.UNVERIFIED,
                supporting_evidence=evidence_items,
                recommended_verifications=pattern["verifications"],
                mitre_tactics=list(all_tactics),
                mitre_techniques=matched_techniques or list(all_techniques)[:3],
                target_entities=list(all_entities),
            )
            hypotheses.append(hyp)

        if not hypotheses:
            default_score = 0.50
            hypotheses.append(
                AttackHypothesis(
                    id=f"hyp-{uuid.uuid4().hex[:8]}",
                    title="Unspecified Malicious Activity or Policy Violation",
                    category=HypothesisCategory.INITIAL_COMPROMISE,
                    description="Activity flagged by security rules requiring manual investigation.",
                    confidence=default_score,
                    confidence_level=HypothesisConfidence.MEDIUM,
                    status=HypothesisStatus.UNVERIFIED,
                    supporting_evidence=[f"Detected {len(alerts)} alerts across entities."],
                    recommended_verifications=["Review source logs", "Verify alert rule logic"],
                    mitre_tactics=list(all_tactics),
                    mitre_techniques=list(all_techniques),
                    target_entities=list(all_entities),
                )
            )

        hypotheses.sort(key=lambda h: h.confidence, reverse=True)
        return hypotheses

    def evaluate_evidence(
        self,
        hypothesis: AttackHypothesis,
        evidence: str,
        supports: bool = True,
    ) -> AttackHypothesis:
        """Updates hypothesis state and recalculates confidence with new evidence."""
        if supports:
            hypothesis.supporting_evidence.append(evidence)
            hypothesis.confidence = min(1.0, hypothesis.confidence + 0.10)
        else:
            hypothesis.refuting_evidence.append(evidence)
            hypothesis.confidence = max(0.0, hypothesis.confidence - 0.20)

        hypothesis.confidence_level = self._calc_confidence_level(hypothesis.confidence)

        if hypothesis.confidence >= 0.70 and len(hypothesis.supporting_evidence) >= 2:
            hypothesis.status = HypothesisStatus.SUPPORTED
        elif hypothesis.confidence < 0.30 or len(hypothesis.refuting_evidence) >= 2:
            hypothesis.status = HypothesisStatus.REFUTED
        else:
            hypothesis.status = HypothesisStatus.INCONCLUSIVE

        return hypothesis
