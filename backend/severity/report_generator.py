"""
Severity Report Generator (Day 4 - Commit 7).

Produces human-readable Markdown and machine-readable JSON reports
for CompositeSeverityResult objects, suitable for SOC analyst review,
SIEM ingestion, and audit trail storage.
"""
from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from backend.severity.composite_scorer import CompositeSeverityResult
from backend.ingestion.models import SeverityLevel

_SEVERITY_EMOJI = {
    SeverityLevel.CRITICAL: "[CRITICAL]",
    SeverityLevel.HIGH: "[HIGH]",
    SeverityLevel.MEDIUM: "[MEDIUM]",
    SeverityLevel.LOW: "[LOW]",
    SeverityLevel.INFORMATIONAL: "[INFORMATIONAL]",
}

_SEVERITY_DESCRIPTIONS = {
    SeverityLevel.CRITICAL: "Immediate executive escalation required. Stop-the-line response.",
    SeverityLevel.HIGH: "Urgent response needed within 1 hour. Assign senior analyst.",
    SeverityLevel.MEDIUM: "Respond within 4 hours. Standard investigation workflow.",
    SeverityLevel.LOW: "Investigate during business hours. No immediate action.",
    SeverityLevel.INFORMATIONAL: "Log and monitor. No response action required.",
}


class SeverityReportGenerator:
    """
    Generates structured Markdown and JSON reports from CompositeSeverityResult.

    Usage::

        gen = SeverityReportGenerator()
        md  = gen.to_markdown(result)
        js  = gen.to_json(result)
        gen.save_report(result, output_dir=Path("reports/"))
    """

    def to_markdown(self, result: CompositeSeverityResult) -> str:
        """Render a human-readable Markdown severity report."""
        sev = result.final_severity
        badge = _SEVERITY_EMOJI.get(sev, "[UNKNOWN]")
        desc = _SEVERITY_DESCRIPTIONS.get(sev, "")
        enforcement = result.enforcement_record
        biz = result.business_impact

        is_enforced = enforcement.downgrade_prevented or getattr(enforcement, "enforcement_applied", False)

        lines: List[str] = [
            f"# {badge} Severity Report - {result.incident_id}",
            "",
            f"**Report ID:** `{result.result_id}`",
            f"**Generated:** {result.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}",
            "",
            "---",
            "",
            "## Final Verdict",
            "",
            "| Attribute | Value |",
            "|-----------|-------|",
            f"| **Final Severity** | **{sev.value.upper()}** |",
            f"| **Final Score** | {result.final_score:.1f} / 100 |",
            f"| **Deterministic Floor** | {result.deterministic_floor.value.upper()} |",
            f"| **Floor Enforced** | {'Yes' if is_enforced else 'No'} |",
            "",
            f"> {desc}",
            "",
            "---",
            "",
            "## Score Pipeline",
            "",
            "| Stage | Score |",
            "|-------|-------|",
            f"| Base Score (raw) | {result.raw_base_score:.1f} |",
            f"| After Environmental Drift | {result.drift_adjusted_score:.1f} |",
            f"| After Threat Actor Weighting | {result.actor_weighted_score:.1f} |",
            f"| After Historical Calibration | {result.calibrated_score:.1f} |",
            f"| **Final (+ Business Impact)** | **{result.final_score:.1f}** |",
            "",
        ]

        # Risk matrix section
        rm = result.pipeline_stages.get("risk_matrix", {})
        if rm:
            lines += [
                "---", "",
                "## Risk Matrix (Financial / Regulatory)", "",
                "| Field | Value |",
                "|-------|-------|",
                f"| Likelihood | {rm.get('likelihood', '---')} |",
                f"| Impact | {rm.get('impact', '---')} |",
                f"| Financial Exposure | ${rm.get('estimated_financial_exposure_usd', 0):,.0f} |",
                f"| Risk Matrix Score | {rm.get('risk_matrix_score', 0):.1f} |",
                f"| Risk Matrix Severity | {rm.get('severity_level', '---').upper()} |",
                "",
            ]

        # Drift section
        drift = result.pipeline_stages.get("environmental_drift", {})
        if drift:
            lines += [
                "---", "",
                "## Environmental Drift Adjustment", "",
                "| Field | Value |",
                "|-------|-------|",
                f"| Multiplier | {drift.get('drift_multiplier', 1.0):.3f} |",
                f"| Is Business Hours | {drift.get('is_business_hours', '---')} |",
                f"| Is Change Freeze | {drift.get('is_change_freeze', '---')} |",
                f"| Reason | {drift.get('adjustment_reason', '---')} |",
                "",
            ]

        # Actor weighting section
        actor = result.pipeline_stages.get("actor_weighting", {})
        if actor:
            lines += [
                "---", "",
                "## Threat Actor Weighting", "",
                "| Field | Value |",
                "|-------|-------|",
                f"| Actor | {actor.get('actor_name', 'Unknown')} |",
                f"| Capability Score | {actor.get('capability_score', 0):.1f} |",
                f"| Attribution Confidence | {actor.get('attribution_confidence', 0):.0%} |",
                f"| 0-Day Detected | {'Yes' if actor.get('observed_0day') else 'No'} |",
                f"| Wiper Detected | {'Yes' if actor.get('observed_wiper') else 'No'} |",
                f"| EDR Tampering | {'Yes' if actor.get('observed_edr_tampering') else 'No'} |",
                f"| Composite Multiplier | {actor.get('composite_multiplier', 1.0):.3f} |",
                "",
            ]

        # Business impact section
        biz_dict = biz.to_dict()
        lines += [
            "---", "",
            "## Business Impact", "",
            "| Field | Value |",
            "|-------|-------|",
            f"| Impact Score | {biz_dict.get('business_impact_score', 0):.1f} |",
            f"| Highest Criticality | {biz_dict.get('highest_criticality', '---')} |",
            f"| SLA Breached | {'Yes' if biz_dict.get('sla_breached') else 'No'} |",
            f"| Ack Deadline | {biz_dict.get('ack_deadline', '---')} |",
            f"| Remediation Deadline | {biz_dict.get('remediation_deadline', '---')} |",
            "",
        ]

        if is_enforced:
            explanation = getattr(enforcement, "explanation", getattr(enforcement, "enforcement_reason", "Floor applied"))
            lines += [
                "---", "",
                "## Floor Enforcement Applied", "",
                "> The deterministic severity floor overrode a lower proposed severity.", "",
                "| Field | Value |",
                "|-------|-------|",
                f"| Proposed | {enforcement.proposed_severity.value.upper()} |",
                f"| Enforced | {enforcement.enforced_severity.value.upper()} |",
                f"| Reason | {explanation} |",
                "",
            ]

        lines += ["---", "", "_Report generated by SOC Severity Engine v4_", ""]
        return "\n".join(lines)

    def to_json(self, result: CompositeSeverityResult) -> str:
        """Return machine-readable JSON of the full result."""
        return json.dumps(result.to_dict(), indent=2, default=str)

    def save_report(
        self,
        result: CompositeSeverityResult,
        output_dir: Path,
        formats: Optional[List[str]] = None,
    ) -> Dict[str, Path]:
        """Persist the report to disk in requested formats (md, json)."""
        if formats is None:
            formats = ["md", "json"]

        output_dir.mkdir(parents=True, exist_ok=True)
        stem = f"{result.incident_id}_{result.result_id}"
        written: Dict[str, Path] = {}

        if "md" in formats:
            md_path = output_dir / f"{stem}.md"
            md_path.write_text(self.to_markdown(result), encoding="utf-8")
            written["md"] = md_path

        if "json" in formats:
            json_path = output_dir / f"{stem}.json"
            json_path.write_text(self.to_json(result), encoding="utf-8")
            written["json"] = json_path

        return written


class BulkReportManager:
    """Manages bulk report generation and aggregated statistics."""

    def __init__(self) -> None:
        self._generator = SeverityReportGenerator()
        self._results: List[CompositeSeverityResult] = []

    def add_result(self, result: CompositeSeverityResult) -> None:
        self._results.append(result)

    def generate_summary(self) -> Dict[str, Any]:
        """Statistical summary across all collected results."""
        if not self._results:
            return {"error": "No results collected"}
        severity_counts = Counter(r.final_severity.value for r in self._results)
        scores = [r.final_score for r in self._results]
        floor_enforcements = sum(
            1 for r in self._results
            if r.enforcement_record.downgrade_prevented or getattr(r.enforcement_record, "enforcement_applied", False)
        )
        return {
            "total_incidents": len(self._results),
            "severity_distribution": dict(severity_counts),
            "score_statistics": {
                "min": round(min(scores), 2),
                "max": round(max(scores), 2),
                "mean": round(sum(scores) / len(scores), 2),
            },
            "floor_enforcement_count": floor_enforcements,
            "floor_enforcement_rate": round(floor_enforcements / len(self._results), 3),
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

    def save_all(
        self, output_dir: Path, formats: Optional[List[str]] = None
    ) -> List[Dict[str, Path]]:
        """Save all collected results to output_dir."""
        return [
            self._generator.save_report(r, output_dir=output_dir, formats=formats)
            for r in self._results
        ]
