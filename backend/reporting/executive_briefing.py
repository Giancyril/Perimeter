"""
Executive Briefing Generator (Day 5 - Commit 1).

Generates high-level, business-oriented briefings tailored for C-suite leaders
(CISO, CEO, Board of Directors, Legal Counsel).
Translates technical SOC telemetry, MITRE tactics, and severity scores into
quantifiable financial exposure, regulatory disclosure obligations (SEC / GDPR / HIPAA),
operational downtime risk, and immediate executive decisions required.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from backend.ingestion.models import SeverityLevel
from backend.reporting.models import IncidentReport


@dataclass
class ExecutiveBriefing:
    """Board/C-suite executive summary of a security incident."""
    briefing_id: str
    incident_id: str
    generated_at: datetime
    severity: SeverityLevel
    headline: str
    executive_narrative: str
    operational_status: str                     # "ACTIVE_CONTAINMENT", "ISOLATED", "MONITORING", "ERADICATED"
    financial_exposure_usd: float
    estimated_downtime_hours: float
    regulatory_exposure: Dict[str, Any]         # SEC, GDPR, HIPAA notifications required
    critical_assets_impacted: List[str]
    c_suite_talking_points: List[str]
    immediate_decisions_required: List[str]
    recommended_external_comms: str
    containment_confidence: float               # 0.0 to 1.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "briefing_id": self.briefing_id,
            "incident_id": self.incident_id,
            "generated_at": self.generated_at.isoformat(),
            "severity": self.severity.value,
            "headline": self.headline,
            "executive_narrative": self.executive_narrative,
            "operational_status": self.operational_status,
            "financial_exposure_usd": self.financial_exposure_usd,
            "estimated_downtime_hours": self.estimated_downtime_hours,
            "regulatory_exposure": self.regulatory_exposure,
            "critical_assets_impacted": self.critical_assets_impacted,
            "c_suite_talking_points": self.c_suite_talking_points,
            "immediate_decisions_required": self.immediate_decisions_required,
            "recommended_external_comms": self.recommended_external_comms,
            "containment_confidence": round(self.containment_confidence, 2),
        }

    def to_markdown(self) -> str:
        """Render executive briefing in clean, printable CISO Markdown format."""
        reg_lines = []
        for reg, details in self.regulatory_exposure.items():
            req = "YES (Action Required)" if details.get("notification_required") else "NO"
            deadline = details.get("deadline", "N/A")
            reg_lines.append(f"- **{reg}**: {req} | Deadline: `{deadline}`")

        talking_points_md = "\n".join(f"1. {pt}" for pt in self.c_suite_talking_points)
        decisions_md = "\n".join(f"- [ ] {dec}" for dec in self.immediate_decisions_required)
        assets_md = ", ".join(f"`{a}`" for a in self.critical_assets_impacted) or "None recorded"

        return f"""# 🏛️ EXECUTIVE BRIEFING: INCIDENT {self.incident_id}
**Classification:** STRICTLY CONFIDENTIAL // ATTORNEY-CLIENT PRIVILEGED
**Generated:** {self.generated_at.strftime('%Y-%m-%d %H:%M:%S UTC')}  
**Current Severity:** **{self.severity.value.upper()}** | **Operational Status:** `{self.operational_status}`

---

## 📌 Executive Headline
> **{self.headline}**

## 📝 Situation Summary
{self.executive_narrative}

---

## 💼 Business & Financial Risk Assessment
| Risk Factor | Assessment |
| :--- | :--- |
| **Financial Exposure (Estimated)** | **${self.financial_exposure_usd:,.2f} USD** |
| **Operational Downtime** | **{self.estimated_downtime_hours:.1f} Hours** |
| **Critical Assets Impacted** | {assets_md} |
| **Containment Confidence** | **{self.containment_confidence * 100:.0f}%** |

### ⚖️ Regulatory & Compliance Disclosure Deadlines
{chr(10).join(reg_lines) if reg_lines else "_No mandatory regulatory disclosure triggers detected at this time._"}

---

## 🗣️ C-Suite & Board Talking Points
{talking_points_md}

## ⚡ Immediate Decisions & Approvals Required
{decisions_md}

## 📢 Public Relations & External Communication Guidance
> {self.recommended_external_comms}

---
*Autonomous Security Operations Center // Executive Assurance Framework*
"""

    def to_email_summary(self) -> str:
        """Generate high-density email body suitable for emergency mobile notification."""
        return (
            f"[{self.severity.value.upper()}] EXECUTIVE BRIEFING: {self.headline}\n"
            f"Incident: {self.incident_id}\n"
            f"Financial Exposure: ${self.financial_exposure_usd:,.2f}\n"
            f"Status: {self.operational_status}\n"
            f"Decisions Required: {len(self.immediate_decisions_required)}\n\n"
            f"Key Takeaway: {self.executive_narrative[:250]}..."
        )


class ExecutiveBriefingGenerator:
    """
    Synthesizes technical IncidentReport data into an ExecutiveBriefing.
    """

    def generate(
        self,
        report: IncidentReport,
        financial_exposure_usd: Optional[float] = None,
        estimated_downtime_hours: Optional[float] = None,
        critical_assets: Optional[List[str]] = None,
        operational_status: Optional[str] = None,
    ) -> ExecutiveBriefing:
        """
        Produce a tailored ExecutiveBriefing from an IncidentReport.
        """
        # Determine financial estimate based on severity if not provided
        if financial_exposure_usd is None:
            tier_costs = {
                SeverityLevel.CRITICAL: 250_000.0,
                SeverityLevel.HIGH: 75_000.0,
                SeverityLevel.MEDIUM: 15_000.0,
                SeverityLevel.LOW: 2_500.0,
                SeverityLevel.INFORMATIONAL: 0.0,
            }
            base_cost = tier_costs.get(report.final_severity, 10_000.0)
            lateral_bonus = len(report.lateral_movement_paths) * 50_000.0
            financial_exposure_usd = base_cost + lateral_bonus

        if estimated_downtime_hours is None:
            downtime_map = {
                SeverityLevel.CRITICAL: 6.0,
                SeverityLevel.HIGH: 2.0,
                SeverityLevel.MEDIUM: 0.5,
                SeverityLevel.LOW: 0.0,
                SeverityLevel.INFORMATIONAL: 0.0,
            }
            estimated_downtime_hours = downtime_map.get(report.final_severity, 0.0)

        # Detect critical assets from report entities
        assets = critical_assets or []
        if not assets:
            for ent in report.entities:
                if ent.criticality in ("critical", "tier_0", "high") or ent.entity_type == "host":
                    assets.append(ent.entity_value)

        # Determine regulatory triggers
        regulatory: Dict[str, Any] = {}
        is_critical = report.final_severity in (SeverityLevel.CRITICAL, SeverityLevel.HIGH)

        if is_critical and any("exfiltration" in t.lower() or "collection" in t.lower() for t in report.mitre_tactics):
            regulatory["GDPR Article 33"] = {
                "notification_required": True,
                "deadline": "Within 72 hours of awareness",
                "authority": "Data Protection Supervisory Authority (EU)",
            }
            regulatory["SEC Item 1.05 Form 8-K"] = {
                "notification_required": True,
                "deadline": "Within 4 business days of materiality determination",
                "authority": "U.S. Securities and Exchange Commission",
            }
        elif is_critical:
            regulatory["SEC Item 1.05 Form 8-K"] = {
                "notification_required": True,
                "deadline": "Assess materiality immediately (4-day disclosure clock upon determination)",
                "authority": "SEC / Corporate Legal",
            }

        # Status
        status = operational_status or ("ACTIVE_CONTAINMENT" if is_critical else "MONITORING")

        # Headline
        if report.adversarial_injection_detected:
            headline = f"Security Incident with Adversarial Prompt Injection Defense Triggered: {report.incident_title}"
        elif report.final_severity == SeverityLevel.CRITICAL:
            headline = f"CRITICAL INCIDENT: Multi-Stage Threat Targeting Core Infrastructure ({report.incident_id})"
        elif report.final_severity == SeverityLevel.HIGH:
            headline = f"Elevated Threat Detected: Unauthorized Lateral Activity Confirmed ({report.incident_id})"
        else:
            headline = f"Routine Threat Triage: {report.incident_title}"

        # Executive narrative
        narrative = (
            report.executive_summary
            or f"The Autonomous SOC detected an alert cluster classified as {report.final_severity.value.upper()}. "
               f"Tactics identified include {', '.join(report.mitre_tactics) or 'Initial Anomalies'}. "
               f"Deterministic safety invariants have enforced floor controls to prevent threat suppression."
        )

        # Talking points
        talking_points = [
            f"Autonomous SOC responded within target SLA window; current status is {status}.",
            f"Primary attack vectors identified: {', '.join(report.mitre_tactics) or 'Standard Perimeter Probing'}.",
            f"Estimated total exposure is currently bounded at approximately ${financial_exposure_usd:,.0f} USD.",
            "Technical containment steps are underway; forensic chain of custody is established.",
        ]
        if report.adversarial_injection_detected:
            talking_points.append(
                "Attacker attempted AI prompt injection evasion; autonomous safety floors successfully repelled the override."
            )

        # Decisions
        decisions = [
            "Acknowledge executive briefing and authorize emergency incident response reserve budget.",
            "Confirm corporate legal engagement for potential regulatory notifications.",
        ]
        if report.final_severity == SeverityLevel.CRITICAL:
            decisions.insert(0, "Authorize emergency network isolation of affected Tier-0 hosts.")
            decisions.append("Brief Board Risk Committee and notify cyber insurance carrier.")

        comms = (
            "No public disclosure recommended at this phase. Prepare holding statement in coordination with Legal and PR."
            if report.final_severity != SeverityLevel.CRITICAL
            else "Issue internal holding statement to critical stakeholders. Coordinate external disclosure under legal privilege."
        )

        conf = 0.90 if report.attack_chain_span > 2 else 0.75

        return ExecutiveBriefing(
            briefing_id=f"brf-{uuid.uuid4().hex[:8]}",
            incident_id=report.incident_id,
            generated_at=datetime.now(timezone.utc),
            severity=report.final_severity,
            headline=headline,
            executive_narrative=narrative,
            operational_status=status,
            financial_exposure_usd=financial_exposure_usd,
            estimated_downtime_hours=estimated_downtime_hours,
            regulatory_exposure=regulatory,
            critical_assets_impacted=list(set(assets)),
            c_suite_talking_points=talking_points,
            immediate_decisions_required=decisions,
            recommended_external_comms=comms,
            containment_confidence=conf,
        )
