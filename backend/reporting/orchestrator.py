"""
Unified Multi-Stage Incident Report Orchestrator (Day 5 - Commit 9).

Orchestrates the entire suite of Day 5 reporting engines into an integrated,
single-call publishing pipeline:
- Technical Incident Report & Timeline
- C-Suite Executive Briefing & Talking Points
- OASIS STIX 2.1 Threat Intel Bundle
- MITRE ATT&CK Attack Graphs & ASCII Kill-Chain
- Cryptographically Signed Chain-of-Custody Manifest
- Global Statutory Breach Compliance Audit (GDPR, SEC, HIPAA)
- Root Cause Analysis & D3FEND Countermeasures
- Multi-Channel Collaboration Payloads (Slack, Teams, PagerDuty)
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from backend.reporting.models import IncidentReport
from backend.reporting.builder import build_report
from backend.reporting.executive_briefing import ExecutiveBriefing, ExecutiveBriefingGenerator
from backend.reporting.stix_exporter import STIX21Exporter
from backend.reporting.attack_graph import AttackGraphVisualizer, AttackPathSummary
from backend.reporting.chain_of_custody import ChainOfCustodyManifest, ChainOfCustodyBuilder
from backend.reporting.compliance_engine import BreachComplianceReport, ComplianceDisclosureEngine
from backend.reporting.root_cause_analyzer import RootCauseReport, RootCauseAnalyzer
from backend.reporting.dispatch import ReportDispatcher, AudienceRole
from backend.reporting.markdown import render_markdown


@dataclass
class IncidentReportPackage:
    """Complete publication dossier holding all technical, executive, and legal report artifacts."""
    package_id: str
    incident_id: str
    generated_at: datetime
    incident_report: IncidentReport
    markdown_report: str
    executive_briefing: ExecutiveBriefing
    stix_bundle: Dict[str, Any]
    attack_path_summary: AttackPathSummary
    mermaid_flowchart: str
    mermaid_sequence: str
    ascii_kill_chain: str
    chain_of_custody: ChainOfCustodyManifest
    compliance_report: BreachComplianceReport
    root_cause_analysis: RootCauseReport
    slack_payload: Dict[str, Any]
    teams_payload: Dict[str, Any]
    pagerduty_payload: Dict[str, Any]

    def to_summary_dict(self) -> Dict[str, Any]:
        return {
            "package_id": self.package_id,
            "incident_id": self.incident_id,
            "generated_at": self.generated_at.isoformat(),
            "severity": self.incident_report.final_severity.value,
            "floor_enforced": self.incident_report.severity_audit.floor_enforced,
            "briefing_id": self.executive_briefing.briefing_id,
            "manifest_digest": self.chain_of_custody.manifest_digest,
            "regulatory_action_required": self.compliance_report.requires_immediate_action,
            "rca_action_count": len(self.root_cause_analysis.action_items),
        }

    def export_all(self, output_dir: Path) -> Dict[str, Path]:
        """Persist all dossier artifacts to disk in structured format."""
        output_dir.mkdir(parents=True, exist_ok=True)
        written: Dict[str, Path] = {}

        stem = f"{self.incident_id}_{self.package_id}"

        # 1. Technical Markdown
        p_md = output_dir / f"{stem}_technical_report.md"
        p_md.write_text(self.markdown_report, encoding="utf-8")
        written["technical_markdown"] = p_md

        # 2. Executive Briefing
        p_brf = output_dir / f"{stem}_executive_briefing.md"
        p_brf.write_text(self.executive_briefing.to_markdown(), encoding="utf-8")
        written["executive_briefing"] = p_brf

        # 3. STIX 2.1 Bundle
        p_stix = output_dir / f"{stem}_stix21_bundle.json"
        p_stix.write_text(json.dumps(self.stix_bundle, indent=2), encoding="utf-8")
        written["stix_bundle"] = p_stix

        # 4. Attack Graph (Mermaid Flowchart)
        p_mmd = output_dir / f"{stem}_attack_graph.mmd"
        p_mmd.write_text(self.mermaid_flowchart, encoding="utf-8")
        written["attack_graph_mermaid"] = p_mmd

        # 5. Chain of Custody
        p_coc = output_dir / f"{stem}_chain_of_custody.md"
        p_coc.write_text(self.chain_of_custody.to_markdown(), encoding="utf-8")
        written["chain_of_custody"] = p_coc

        # 6. Compliance Briefing
        p_cmp = output_dir / f"{stem}_compliance_briefing.md"
        p_cmp.write_text(self.compliance_report.to_markdown(), encoding="utf-8")
        written["compliance_briefing"] = p_cmp

        # 7. Root Cause Analysis
        p_rca = output_dir / f"{stem}_root_cause_analysis.md"
        p_rca.write_text(self.root_cause_analysis.to_markdown(), encoding="utf-8")
        written["root_cause_analysis"] = p_rca

        # 8. Webhook Dispatch Payloads
        p_web = output_dir / f"{stem}_dispatch_payloads.json"
        web_dict = {
            "slack": self.slack_payload,
            "teams": self.teams_payload,
            "pagerduty": self.pagerduty_payload,
        }
        p_web.write_text(json.dumps(web_dict, indent=2), encoding="utf-8")
        written["dispatch_payloads"] = p_web

        return written


class ReportOrchestrator:
    """
    Central pipeline orchestrator generating all multi-stage reporting artifacts.
    """

    def __init__(self) -> None:
        self.briefing_gen = ExecutiveBriefingGenerator()
        self.stix_exporter = STIX21Exporter()
        self.graph_visualizer = AttackGraphVisualizer()
        self.coc_builder = ChainOfCustodyBuilder()
        self.compliance_engine = ComplianceDisclosureEngine()
        self.rca_analyzer = RootCauseAnalyzer()
        self.dispatcher = ReportDispatcher()

    def build_package(
        self,
        source: Union[Dict[str, Any], IncidentReport],
        # Context parameters
        financial_exposure_usd: Optional[float] = None,
        estimated_downtime_hours: Optional[float] = None,
        records_exposed: int = 0,
        pii_detected: bool = False,
        payment_data_detected: bool = False,
        legal_hold: bool = False,
    ) -> IncidentReportPackage:
        """
        Synthesize complete multi-artifact incident dossier from state or report.
        """
        # Resolve to IncidentReport
        if isinstance(source, dict):
            report = build_report(source)
        else:
            report = source

        pkg_id = f"pkg-{report.incident_id.lower()[:8]}"

        # 1. Technical Markdown
        md_text = render_markdown(report)

        # 2. Executive Briefing
        briefing = self.briefing_gen.generate(
            report=report,
            financial_exposure_usd=financial_exposure_usd,
            estimated_downtime_hours=estimated_downtime_hours,
        )

        # 3. STIX 2.1
        stix_bundle = self.stix_exporter.to_bundle(report)

        # 4. Attack Graphs & Kill Chain
        path_summary = self.graph_visualizer.analyze_path(report)
        flowchart = self.graph_visualizer.to_mermaid_flowchart(report)
        sequence = self.graph_visualizer.to_mermaid_sequence(report)
        ascii_kc = self.graph_visualizer.to_ascii_kill_chain(report)

        # 5. Chain of Custody Manifest
        coc = self.coc_builder.build_manifest(report, legal_hold=legal_hold)

        # 6. Compliance Evaluation
        compliance = self.compliance_engine.evaluate(
            report=report,
            records_exposed=records_exposed,
            pii_detected=pii_detected,
            payment_data_detected=payment_data_detected,
        )

        # 7. Root Cause Analysis
        rca = self.rca_analyzer.analyze(report)

        # 8. Webhook Dispatch Payloads
        slack = self.dispatcher.to_slack_block_kit(report, briefing=briefing)
        teams = self.dispatcher.to_teams_adaptive_card(report, briefing=briefing)
        pd = self.dispatcher.to_pagerduty_payload(report)

        return IncidentReportPackage(
            package_id=pkg_id,
            incident_id=report.incident_id,
            generated_at=datetime.now(timezone.utc),
            incident_report=report,
            markdown_report=md_text,
            executive_briefing=briefing,
            stix_bundle=stix_bundle,
            attack_path_summary=path_summary,
            mermaid_flowchart=flowchart,
            mermaid_sequence=sequence,
            ascii_kill_chain=ascii_kc,
            chain_of_custody=coc,
            compliance_report=compliance,
            root_cause_analysis=rca,
            slack_payload=slack,
            teams_payload=teams,
            pagerduty_payload=pd,
        )


report_orchestrator = ReportOrchestrator()
