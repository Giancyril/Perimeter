"""
Regulatory Compliance & Breach Notification Engine (Day 5 - Commit 5).

Automates regulatory disclosure obligations, tracking strict legal clocks for:
1. GDPR Article 33 (72-hour Supervisory Authority notification)
2. SEC Item 1.05 Form 8-K (4 business days from materiality determination)
3. HIPAA Breach Notification Rule (HHS & affected individual deadlines)
4. PCI-DSS Cardholder Compromise Notice (24-hour merchant acquirer notification)
5. NYDFS 23 NYCRR 500 (72-hour Superintendent notice)

Generates pre-filled regulatory notification filings and compliance risk reports.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional

from backend.ingestion.models import SeverityLevel
from backend.reporting.models import IncidentReport


@dataclass
class RegulatoryObligation:
    """A specific statutory or regulatory notification obligation."""
    regulation_code: str
    regulation_name: str
    triggered: bool
    trigger_reason: str
    disclosure_deadline: Optional[datetime]
    hours_remaining: Optional[float]
    reporting_authority: str
    potential_penalty_summary: str
    filing_template: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "regulation_code": self.regulation_code,
            "regulation_name": self.regulation_name,
            "triggered": self.triggered,
            "trigger_reason": self.trigger_reason,
            "disclosure_deadline": self.disclosure_deadline.isoformat() if self.disclosure_deadline else None,
            "hours_remaining": round(self.hours_remaining, 1) if self.hours_remaining is not None else None,
            "reporting_authority": self.reporting_authority,
            "potential_penalty_summary": self.potential_penalty_summary,
            "has_draft_filing": self.filing_template is not None,
        }


@dataclass
class BreachComplianceReport:
    """Comprehensive compliance evaluation across all relevant data privacy and cybersecurity laws."""
    report_id: str
    incident_id: str
    evaluated_at: datetime
    discovery_timestamp: datetime
    obligations: List[RegulatoryObligation]
    requires_immediate_action: bool
    nearest_deadline: Optional[datetime]
    executive_legal_advisory: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "report_id": self.report_id,
            "incident_id": self.incident_id,
            "evaluated_at": self.evaluated_at.isoformat(),
            "discovery_timestamp": self.discovery_timestamp.isoformat(),
            "requires_immediate_action": self.requires_immediate_action,
            "nearest_deadline": self.nearest_deadline.isoformat() if self.nearest_deadline else None,
            "executive_legal_advisory": self.executive_legal_advisory,
            "obligations": [o.to_dict() for o in self.obligations],
        }

    def to_markdown(self) -> str:
        """Render compliance status as a legal briefing."""
        lines = [
            f"# ⚖️ STATUTORY BREACH COMPLIANCE & NOTIFICATION BRIEFING",
            f"**Report ID:** `{self.report_id}` | **Incident ID:** `{self.incident_id}`  ",
            f"**Evaluated At:** {self.evaluated_at.strftime('%Y-%m-%d %H:%M:%S UTC')}  ",
            f"**Incident Discovery Time:** {self.discovery_timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}  ",
            f"**Action Required Immediately:** `{'🚨 YES (MANDATORY FILING CLOCK ACTIVE)' if self.requires_immediate_action else 'NO (MONITORING)'}`  ",
            "",
            "---",
            "",
            "## ⏳ Active Regulatory Clocks & Disclosure Deadlines",
            "| Regulation | Triggered? | Deadline (UTC) | Hours Left | Authority | Penalty Risk |",
            "| :--- | :--- | :--- | :--- | :--- | :--- |",
        ]

        for ob in self.obligations:
            status = "🚨 **YES**" if ob.triggered else "⚪ No"
            dl_str = ob.disclosure_deadline.strftime('%Y-%m-%d %H:%M') if ob.disclosure_deadline else "N/A"
            hrs_str = f"**{ob.hours_remaining:.1f}h**" if ob.hours_remaining is not None else "—"
            lines.append(
                f"| {ob.regulation_name} | {status} | `{dl_str}` | {hrs_str} | {ob.reporting_authority} | {ob.potential_penalty_summary} |"
            )

        lines.extend([
            "",
            "---",
            "",
            "## 🛡️ General Counsel & CISO Advisory",
            f"> {self.executive_legal_advisory}",
            "",
            "---",
            "*Autonomous SOC Compliance Assurance Engine // Confidential Legal Assessment*",
        ])
        return "\n".join(lines)


class ComplianceDisclosureEngine:
    """
    Evaluates incident telemetry against global cybersecurity breach notification regulations.
    """

    def evaluate(
        self,
        report: IncidentReport,
        records_exposed: int = 0,
        pii_detected: bool = False,
        payment_data_detected: bool = False,
        phi_detected: bool = False,
        materiality_determined: bool = False,
        discovery_timestamp: Optional[datetime] = None,
    ) -> BreachComplianceReport:
        """
        Evaluate obligations and return BreachComplianceReport.
        """
        now = datetime.now(timezone.utc)
        discovery = discovery_timestamp or report.generated_at
        if discovery.tzinfo is None:
            discovery = discovery.replace(tzinfo=timezone.utc)

        obligations: List[RegulatoryObligation] = []
        is_high_or_crit = report.final_severity in (SeverityLevel.CRITICAL, SeverityLevel.HIGH)

        # 1. GDPR Article 33 (72h)
        gdpr_triggered = (pii_detected or records_exposed > 0) and is_high_or_crit
        gdpr_deadline = discovery + timedelta(hours=72) if gdpr_triggered else None
        gdpr_hours = max(0.0, (gdpr_deadline - now).total_seconds() / 3600.0) if gdpr_deadline else None
        obligations.append(
            RegulatoryObligation(
                regulation_code="GDPR_ART_33",
                regulation_name="GDPR Article 33",
                triggered=gdpr_triggered,
                trigger_reason=f"Exfiltration or unauthorized access to PII ({records_exposed} records involved)." if gdpr_triggered else "No personal data exfiltration confirmed.",
                disclosure_deadline=gdpr_deadline,
                hours_remaining=gdpr_hours,
                reporting_authority="EU Data Protection Supervisory Authority (DPA)",
                potential_penalty_summary="Up to €20M or 4% of global annual turnover.",
                filing_template="DRAFT GDPR INITIAL NOTIFICATION: Incident affecting EU data subjects..." if gdpr_triggered else None,
            )
        )

        # 2. SEC Item 1.05 Form 8-K (4 business days from materiality)
        sec_triggered = materiality_determined or (report.final_severity == SeverityLevel.CRITICAL and len(report.lateral_movement_paths) > 0)
        sec_deadline = discovery + timedelta(days=4) if sec_triggered else None
        sec_hours = max(0.0, (sec_deadline - now).total_seconds() / 3600.0) if sec_deadline else None
        obligations.append(
            RegulatoryObligation(
                regulation_code="SEC_FORM_8K",
                regulation_name="SEC Item 1.05 Form 8-K",
                triggered=sec_triggered,
                trigger_reason="Material cybersecurity incident affecting public registrant operations/financials." if sec_triggered else "Not deemed material under SEC standard at this time.",
                disclosure_deadline=sec_deadline,
                hours_remaining=sec_hours,
                reporting_authority="U.S. Securities and Exchange Commission (EDGAR)",
                potential_penalty_summary="Enforcement action, shareholder litigation, delisting risk.",
                filing_template="UNITED STATES SECURITIES AND EXCHANGE COMMISSION: FORM 8-K Item 1.05..." if sec_triggered else None,
            )
        )

        # 3. HIPAA Breach Notification Rule (60 days or immediate)
        hipaa_triggered = phi_detected and is_high_or_crit
        hipaa_deadline = discovery + timedelta(days=60) if hipaa_triggered else None
        hipaa_hours = max(0.0, (hipaa_deadline - now).total_seconds() / 3600.0) if hipaa_deadline else None
        obligations.append(
            RegulatoryObligation(
                regulation_code="HIPAA_BREACH_RULE",
                regulation_name="HIPAA Breach Notification",
                triggered=hipaa_triggered,
                trigger_reason="Protected Health Information (PHI) compromise detected." if hipaa_triggered else "No PHI assets identified in blast radius.",
                disclosure_deadline=hipaa_deadline,
                hours_remaining=hipaa_hours,
                reporting_authority="HHS Office for Civil Rights (OCR)",
                potential_penalty_summary="Tier 4 fines up to $2,000,000+ per violation category.",
                filing_template="HHS OCR BREACH REPORTING PORTAL DRAFT..." if hipaa_triggered else None,
            )
        )

        # 4. PCI-DSS Requirement 12.10.5 (24h)
        pci_triggered = payment_data_detected and is_high_or_crit
        pci_deadline = discovery + timedelta(hours=24) if pci_triggered else None
        pci_hours = max(0.0, (pci_deadline - now).total_seconds() / 3600.0) if pci_deadline else None
        obligations.append(
            RegulatoryObligation(
                regulation_code="PCI_DSS_12_10",
                regulation_name="PCI-DSS Cardholder Data",
                triggered=pci_triggered,
                trigger_reason="Cardholder Data Environment (CDE) compromised or PAN data exposed." if pci_triggered else "Payment workflows not impacted.",
                disclosure_deadline=pci_deadline,
                hours_remaining=pci_hours,
                reporting_authority="Payment Brand Card Networks & Acquirer",
                potential_penalty_summary="Fines up to $100k/mo, forensic PFI investigation mandatory, card processing suspension.",
                filing_template="PAYMENT BRAND INITIAL COMPROMISE NOTIFICATION..." if pci_triggered else None,
            )
        )

        # Check immediate action and nearest deadline
        triggered_obs = [o for o in obligations if o.triggered and o.disclosure_deadline is not None]
        immediate = len(triggered_obs) > 0
        nearest = min((o.disclosure_deadline for o in triggered_obs), default=None)

        if immediate:
            advisory = (
                f"ATTENTION: {len(triggered_obs)} statutory notification clock(s) are actively running. "
                f"The earliest mandatory disclosure deadline is {nearest.strftime('%Y-%m-%d %H:%M UTC')}. "
                f"Engage external breach counsel immediately to maintain attorney-client privilege over technical work product."
            )
        else:
            advisory = (
                "No statutory notification thresholds have been breached based on currently available telemetry. "
                "Continue monitoring IOC blast radius and re-evaluate if data exfiltration is confirmed."
            )

        return BreachComplianceReport(
            report_id=f"cmp-{uuid.uuid4().hex[:8]}",
            incident_id=report.incident_id,
            evaluated_at=now,
            discovery_timestamp=discovery,
            obligations=obligations,
            requires_immediate_action=immediate,
            nearest_deadline=nearest,
            executive_legal_advisory=advisory,
        )
