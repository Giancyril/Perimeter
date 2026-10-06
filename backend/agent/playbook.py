"""
Dynamic Investigation Playbook Router for Investigation Agent.

Maps correlated incidents and validated attack hypotheses to operational
containment and investigation workflows. Sequences automated vs human-gated steps.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from backend.ingestion.models import NormalizedAlert


class PlaybookType(str, Enum):
    RANSOMWARE_CONTAINMENT = "RANSOMWARE_CONTAINMENT"
    PHISHING_CREDENTIAL_HARVEST = "PHISHING_CREDENTIAL_HARVEST"
    DATA_EXFILTRATION_TRIAGE = "DATA_EXFILTRATION_TRIAGE"
    UNAUTHORIZED_LATERAL_MOVEMENT = "UNAUTHORIZED_LATERAL_MOVEMENT"
    INSIDER_PRIVILEGE_ABUSE = "INSIDER_PRIVILEGE_ABUSE"
    GENERIC_INCIDENT_TRIAGE = "GENERIC_INCIDENT_TRIAGE"


class StepActionType(str, Enum):
    QUERY_THREAT_INTEL = "QUERY_THREAT_INTEL"
    ENDPOINT_ISOLATION = "ENDPOINT_ISOLATION"
    RESET_CREDENTIALS = "RESET_CREDENTIALS"
    COLLECT_MEMORY_DUMP = "COLLECT_MEMORY_DUMP"
    BLOCK_IP_FIREWALL = "BLOCK_IP_FIREWALL"
    TERMINATE_PROCESS = "TERMINATE_PROCESS"
    NOTIFY_SOC_LEAD = "NOTIFY_SOC_LEAD"
    AUDIT_EVENT_LOGS = "AUDIT_EVENT_LOGS"


class StepStatus(str, Enum):
    PENDING = "PENDING"
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    SKIPPED = "SKIPPED"
    FAILED = "FAILED"


@dataclass
class PlaybookStep:
    step_number: int
    name: str
    action_type: StepActionType
    description: str
    requires_human_approval: bool
    automated: bool
    status: StepStatus = StepStatus.PENDING
    output: Optional[str] = None
    execution_time_seconds: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "step_number": self.step_number,
            "name": self.name,
            "action_type": self.action_type.value,
            "description": self.description,
            "requires_human_approval": self.requires_human_approval,
            "automated": self.automated,
            "status": self.status.value,
            "output": self.output,
            "execution_time_seconds": self.execution_time_seconds,
        }


@dataclass
class InvestigationPlaybook:
    id: str
    playbook_type: PlaybookType
    name: str
    description: str
    estimated_duration_minutes: int
    priority: str  # P1_CRITICAL, P2_HIGH, P3_MEDIUM, P4_LOW
    steps: List[PlaybookStep] = field(default_factory=list)

    @property
    def total_steps(self) -> int:
        return len(self.steps)

    @property
    def completed_steps(self) -> int:
        return sum(1 for s in self.steps if s.status == StepStatus.COMPLETED)

    @property
    def pending_approval_steps(self) -> List[PlaybookStep]:
        return [s for s in self.steps if s.requires_human_approval and s.status in (StepStatus.PENDING, StepStatus.AWAITING_APPROVAL)]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "playbook_type": self.playbook_type.value,
            "name": self.name,
            "description": self.description,
            "estimated_duration_minutes": self.estimated_duration_minutes,
            "priority": self.priority,
            "total_steps": self.total_steps,
            "completed_steps": self.completed_steps,
            "steps": [s.to_dict() for s in self.steps],
        }


class PlaybookRouter:
    """Routes alerts/incidents to the appropriate SOC investigation playbook."""

    def route(
        self,
        alerts: List[NormalizedAlert],
        hypothesis_category: Optional[str] = None,
        severity: Optional[str] = None,
    ) -> InvestigationPlaybook:
        """Determines the appropriate playbook based on alerts and active hypothesis."""
        text_blob = " ".join(
            f"{a.rule_name} {a.rule_description or ''}".lower() for a in alerts
        )

        cat_upper = (hypothesis_category or "").upper()

        if "RANSOMWARE" in cat_upper or any(kw in text_blob for kw in ["encrypt", "ransom", "vssadmin"]):
            return self._build_ransomware_playbook()
        elif "CREDENTIAL" in cat_upper or any(kw in text_blob for kw in ["lsass", "mimikatz", "procdump"]):
            return self._build_credential_playbook()
        elif "LATERAL" in cat_upper or any(kw in text_blob for kw in ["psexec", "winrm", "wmic process"]):
            return self._build_lateral_movement_playbook()
        elif "EXFILTRATION" in cat_upper or any(kw in text_blob for kw in ["exfil", "mega.nz", "rclone"]):
            return self._build_exfiltration_playbook()
        else:
            return self._build_generic_playbook()

    def _build_ransomware_playbook(self) -> InvestigationPlaybook:
        return InvestigationPlaybook(
            id=f"pb-{uuid.uuid4().hex[:8]}",
            playbook_type=PlaybookType.RANSOMWARE_CONTAINMENT,
            name="Ransomware Host Containment & Encryption Halt",
            description="Emergency procedures to disconnect infected assets, prevent lateral encryption, and preserve shadow copies.",
            estimated_duration_minutes=25,
            priority="P1_CRITICAL",
            steps=[
                PlaybookStep(
                    step_number=1,
                    name="Extract Network & File IOCs",
                    action_type=StepActionType.QUERY_THREAT_INTEL,
                    description="Query AbuseIPDB and VirusTotal for process hashes and C2 endpoints.",
                    requires_human_approval=False,
                    automated=True,
                ),
                PlaybookStep(
                    step_number=2,
                    name="Isolate Compromised Host from Network",
                    action_type=StepActionType.ENDPOINT_ISOLATION,
                    description="Trigger EDR network containment to sever outbound connection.",
                    requires_human_approval=True,
                    automated=False,
                ),
                PlaybookStep(
                    step_number=3,
                    name="Block External C2 IP at Firewall",
                    action_type=StepActionType.BLOCK_IP_FIREWALL,
                    description="Add malicious destination IP to edge perimeter blocklist.",
                    requires_human_approval=True,
                    automated=False,
                ),
                PlaybookStep(
                    step_number=4,
                    name="Capture Memory & Process Tree",
                    action_type=StepActionType.COLLECT_MEMORY_DUMP,
                    description="Preserve volatile RAM and parent-child process relationships for forensics.",
                    requires_human_approval=False,
                    automated=True,
                ),
                PlaybookStep(
                    step_number=5,
                    name="Notify On-Call SOC Lead",
                    action_type=StepActionType.NOTIFY_SOC_LEAD,
                    description="Escalate incident to SOC commander via PagerDuty/Slack.",
                    requires_human_approval=False,
                    automated=True,
                ),
            ],
        )

    def _build_credential_playbook(self) -> InvestigationPlaybook:
        return InvestigationPlaybook(
            id=f"pb-{uuid.uuid4().hex[:8]}",
            playbook_type=PlaybookType.PHISHING_CREDENTIAL_HARVEST,
            name="Credential Access & Account Compromise Triage",
            description="Triage LSASS dumping, Kerberoasting, and enforce identity credential revocation.",
            estimated_duration_minutes=20,
            priority="P2_HIGH",
            steps=[
                PlaybookStep(
                    step_number=1,
                    name="Identify Targeted User Accounts",
                    action_type=StepActionType.AUDIT_EVENT_LOGS,
                    description="Parse Windows Event 4624/4768/4769 logs for affected accounts.",
                    requires_human_approval=False,
                    automated=True,
                ),
                PlaybookStep(
                    step_number=2,
                    name="Revoke Active Kerberos / OAuth Tokens",
                    action_type=StepActionType.RESET_CREDENTIALS,
                    description="Force password reset and invalidate active sessions in IdP.",
                    requires_human_approval=True,
                    automated=False,
                ),
                PlaybookStep(
                    step_number=3,
                    name="Terminate Suspicious Process",
                    action_type=StepActionType.TERMINATE_PROCESS,
                    description="Kill offending lsass dumping or memory inspection binary.",
                    requires_human_approval=True,
                    automated=False,
                ),
                PlaybookStep(
                    step_number=4,
                    name="Audit Cross-Domain Logons",
                    action_type=StepActionType.AUDIT_EVENT_LOGS,
                    description="Audit secondary authentication attempts across domain controllers.",
                    requires_human_approval=False,
                    automated=True,
                ),
            ],
        )

    def _build_lateral_movement_playbook(self) -> InvestigationPlaybook:
        return InvestigationPlaybook(
            id=f"pb-{uuid.uuid4().hex[:8]}",
            playbook_type=PlaybookType.UNAUTHORIZED_LATERAL_MOVEMENT,
            name="Lateral Movement & Pivot Containment",
            description="Trace RPC, SMB, and WinRM hops across workstations and server VLANs.",
            estimated_duration_minutes=30,
            priority="P2_HIGH",
            steps=[
                PlaybookStep(
                    step_number=1,
                    name="Map Source-Destination Pivot Path",
                    action_type=StepActionType.AUDIT_EVENT_LOGS,
                    description="Reconstruct source and target IP connection graph.",
                    requires_human_approval=False,
                    automated=True,
                ),
                PlaybookStep(
                    step_number=2,
                    name="Block Lateral SMB / RPC Traffic",
                    action_type=StepActionType.BLOCK_IP_FIREWALL,
                    description="Isolate internal VLAN segment or block port 445/5985 traffic.",
                    requires_human_approval=True,
                    automated=False,
                ),
                PlaybookStep(
                    step_number=3,
                    name="Isolate Originating Source Endpoint",
                    action_type=StepActionType.ENDPOINT_ISOLATION,
                    description="Isolate patient-zero workstation initiating lateral hops.",
                    requires_human_approval=True,
                    automated=False,
                ),
            ],
        )

    def _build_exfiltration_playbook(self) -> InvestigationPlaybook:
        return InvestigationPlaybook(
            id=f"pb-{uuid.uuid4().hex[:8]}",
            playbook_type=PlaybookType.DATA_EXFILTRATION_TRIAGE,
            name="Data Exfiltration Interception & Session Severing",
            description="Identify unauthorized egress data streams and block target cloud/external endpoints.",
            estimated_duration_minutes=15,
            priority="P1_CRITICAL",
            steps=[
                PlaybookStep(
                    step_number=1,
                    name="Determine Destination IP & Cloud Bucket",
                    action_type=StepActionType.QUERY_THREAT_INTEL,
                    description="Extract exfiltration destination endpoints and query reputation.",
                    requires_human_approval=False,
                    automated=True,
                ),
                PlaybookStep(
                    step_number=2,
                    name="Sever External TCP Session",
                    action_type=StepActionType.BLOCK_IP_FIREWALL,
                    description="Immediately drop active stateful firewall connection to egress IP.",
                    requires_human_approval=True,
                    automated=False,
                ),
                PlaybookStep(
                    step_number=3,
                    name="Estimate Exfiltrated Byte Volume",
                    action_type=StepActionType.AUDIT_EVENT_LOGS,
                    description="Calculate total network transfer size from NetFlow/Zeek logs.",
                    requires_human_approval=False,
                    automated=True,
                ),
            ],
        )

    def _build_generic_playbook(self) -> InvestigationPlaybook:
        return InvestigationPlaybook(
            id=f"pb-{uuid.uuid4().hex[:8]}",
            playbook_type=PlaybookType.GENERIC_INCIDENT_TRIAGE,
            name="Standard Incident Triage & Evidence Collection",
            description="Default investigation workflow for alerts without dedicated specialized playbook.",
            estimated_duration_minutes=30,
            priority="P3_MEDIUM",
            steps=[
                PlaybookStep(
                    step_number=1,
                    name="Enrich IOCs via Threat Intelligence",
                    action_type=StepActionType.QUERY_THREAT_INTEL,
                    description="Enrich observable IPs, domains, and hashes.",
                    requires_human_approval=False,
                    automated=True,
                ),
                PlaybookStep(
                    step_number=2,
                    name="Collect Correlated Endpoint Logs",
                    action_type=StepActionType.AUDIT_EVENT_LOGS,
                    description="Gather 1-hour temporal window of syslog/winevent entries.",
                    requires_human_approval=False,
                    automated=True,
                ),
            ],
        )

    def advance_step(
        self,
        playbook: InvestigationPlaybook,
        step_number: int,
        output: str,
        approved: bool = False,
    ) -> PlaybookStep:
        """Executes or advances a specific step within an active playbook."""
        target_step = next((s for s in playbook.steps if s.step_number == step_number), None)
        if not target_step:
            raise ValueError(f"Step number {step_number} not found in playbook {playbook.id}")

        if target_step.requires_human_approval and not approved:
            target_step.status = StepStatus.AWAITING_APPROVAL
            target_step.output = "Execution paused awaiting human SOC approval."
            return target_step

        target_step.status = StepStatus.COMPLETED
        target_step.output = output
        return target_step
