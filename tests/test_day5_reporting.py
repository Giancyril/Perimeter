"""
Comprehensive Test Suite for Day 5 Advanced Reporting & Executive Briefing.

Validates:
1. Executive Briefing Generation (financial exposure, talking points, SEC/GDPR flags)
2. OASIS STIX 2.1 Threat Intel Bundle Exporter (spec compliance, indicators, patterns)
3. MITRE ATT&CK Attack Graph Visualizer (Mermaid flowcharts, sequence, ASCII kill chain)
4. Forensic Chain-of-Custody Manifest (SHA-256 hashes, HMAC verification, tamper detection)
5. Regulatory Compliance Engine (GDPR 72h, SEC 8-K 4-day, HIPAA, PCI-DSS clocks)
6. Root Cause Analysis (5-Whys, MITRE D3FEND mappings, remediation tickets)
7. Multi-Channel Report Dispatcher (Slack Block Kit, Teams Adaptive Cards, PagerDuty, Redaction)
8. Historical Report Diff Engine (revision changelog, entity expansion, injection flagging)
9. Unified Report Orchestrator (IncidentReportPackage synthesis & multi-artifact disk export)
"""
from __future__ import annotations

import json
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import List

import pytest

from backend.ingestion.models import SeverityLevel
from backend.reporting.models import (
    IncidentReport,
    TimelineEvent,
    EntityTraceability,
    SeverityAuditRecord,
)
from backend.reporting.executive_briefing import ExecutiveBriefingGenerator, ExecutiveBriefing
from backend.reporting.stix_exporter import STIX21Exporter
from backend.reporting.attack_graph import AttackGraphVisualizer, AttackPathSummary
from backend.reporting.chain_of_custody import (
    ChainOfCustodyBuilder,
    ChainOfCustodyManifest,
    EvidenceType,
)
from backend.reporting.compliance_engine import (
    ComplianceDisclosureEngine,
    BreachComplianceReport,
)
from backend.reporting.root_cause_analyzer import (
    RootCauseAnalyzer,
    RootCauseReport,
)
from backend.reporting.dispatch import (
    ReportDispatcher,
    AudienceRole,
)
from backend.reporting.report_diff import (
    ReportDiffEngine,
    ReportDiffResult,
)
from backend.reporting.orchestrator import (
    ReportOrchestrator,
    IncidentReportPackage,
)


def _make_test_report(
    incident_id: str = "INC-DAY5-001",
    severity: SeverityLevel = SeverityLevel.HIGH,
    tactics: List[str] = None,
    techniques: List[str] = None,
    lateral_paths: List[str] = None,
    adversarial_injection: bool = False,
) -> IncidentReport:
    """Helper to synthesize a realistic IncidentReport for Day 5 testing."""
    now = datetime(2026, 10, 9, 12, 0, 0, tzinfo=timezone.utc)
    if tactics is None:
        tactics = ["Initial Access", "Execution", "Lateral Movement"]
    if techniques is None:
        techniques = ["T1059.001", "T1078", "T1021.002"]
    if lateral_paths is None:
        lateral_paths = ["workstation-01 -> workstation-02", "workstation-02 -> dc-01"]

    timeline = [
        TimelineEvent(
            timestamp=now - timedelta(minutes=45),
            event_type="alert",
            source="wazuh",
            title="Suspicious PowerShell Encoded Command",
            description="PowerShell spawned by WINWORD with encoded base64 payload.",
            related_entities=["192.168.1.50", "workstation-01", "corp\\jsmith"],
            raw_evidence_id="ALT-001",
        ),
        TimelineEvent(
            timestamp=now - timedelta(minutes=30),
            event_type="threat_intel_hit",
            source="abuseipdb",
            title="External C2 IP Connection Hit",
            description="Outbound connection to known C2 server with high abuse score.",
            related_entities=["198.51.100.23", "workstation-01"],
            raw_evidence_id="ALT-002",
        ),
        TimelineEvent(
            timestamp=now - timedelta(minutes=15),
            event_type="lateral_movement",
            source="siem",
            title="Internal SMB Pivot to Domain Controller",
            description="Compromised credentials used to initiate remote service on dc-01.",
            related_entities=["workstation-01", "dc-01", "corp\\admin_svc"],
            raw_evidence_id="ALT-003",
        ),
    ]

    entities = [
        EntityTraceability(
            entity_value="198.51.100.23",
            entity_type="ip",
            threat_verdict="malicious",
            abuse_score=100,
            timeline_event_indices=[1],
        ),
        EntityTraceability(
            entity_value="workstation-01",
            entity_type="host",
            criticality="tier_2",
            timeline_event_indices=[0, 1, 2],
        ),
        EntityTraceability(
            entity_value="dc-01",
            entity_type="host",
            criticality="critical",
            timeline_event_indices=[2],
        ),
        EntityTraceability(
            entity_value="corp\\jsmith",
            entity_type="user",
            criticality="standard",
            timeline_event_indices=[0],
        ),
    ]

    audit = SeverityAuditRecord(
        deterministic_floor=severity.value,
        rule_override_reason="Tier-0 critical asset (dc-01) exposure confirmed",
        base_score=40.0,
        asset_multiplier=1.5,
        threat_intel_points=25.0,
        mitre_multiplier=1.3,
        lateral_movement_points=20.0,
        raw_calculated_score=85.0,
        floor_enforced=True,
        final_severity=severity.value,
    )

    return IncidentReport(
        report_id=f"RPT-{incident_id}",
        incident_id=incident_id,
        generated_at=now,
        incident_title="Multi-Stage Ransomware Attack with Lateral SMB Propagation",
        final_severity=severity,
        deterministic_floor=severity,
        status="INVESTIGATED",
        timeline=timeline,
        entities=entities,
        severity_audit=audit,
        mitre_tactics=tactics,
        mitre_techniques=techniques,
        attack_chain_span=len(tactics),
        lateral_movement_paths=lateral_paths,
        adversarial_injection_detected=adversarial_injection,
        adversarial_injection_reason="Prompt injection payload in HTTP User-Agent blocked" if adversarial_injection else None,
        recommended_actions=["Isolate dc-01 immediately", "Reset corp\\admin_svc credentials", "Block 198.51.100.23 on firewall"],
        executive_summary="Targeted attack initiated via spearphishing with rapid lateral movement toward domain tier-0 infrastructure.",
    )


# ---------------------------------------------------------------------------
# 1. Executive Briefing Tests
# ---------------------------------------------------------------------------

class TestExecutiveBriefing:
    def setup_method(self):
        self.generator = ExecutiveBriefingGenerator()
        self.report = _make_test_report(severity=SeverityLevel.CRITICAL)

    def test_generate_creates_valid_briefing(self):
        briefing = self.generator.generate(self.report)
        assert isinstance(briefing, ExecutiveBriefing)
        assert briefing.incident_id == self.report.incident_id
        assert briefing.severity == SeverityLevel.CRITICAL
        assert briefing.financial_exposure_usd > 0
        assert len(briefing.c_suite_talking_points) >= 3
        assert len(briefing.immediate_decisions_required) >= 2

    def test_briefing_markdown_contains_required_sections(self):
        briefing = self.generator.generate(self.report)
        md = briefing.to_markdown()
        assert "EXECUTIVE BRIEFING" in md
        assert self.report.incident_id in md
        assert "Business & Financial Risk Assessment" in md
        assert "C-Suite & Board Talking Points" in md

    def test_briefing_email_summary(self):
        briefing = self.generator.generate(self.report)
        email = briefing.to_email_summary()
        assert "EXECUTIVE BRIEFING" in email
        assert self.report.incident_id in email

    def test_adversarial_injection_reflects_in_headline(self):
        report_inj = _make_test_report(adversarial_injection=True)
        briefing = self.generator.generate(report_inj)
        assert "Prompt Injection" in briefing.headline or any("injection" in pt.lower() for pt in briefing.c_suite_talking_points)


# ---------------------------------------------------------------------------
# 2. STIX 2.1 Threat Intel Exporter Tests
# ---------------------------------------------------------------------------

class TestSTIX21Exporter:
    def setup_method(self):
        self.exporter = STIX21Exporter()
        self.report = _make_test_report()

    def test_to_bundle_has_stix_format(self):
        bundle = self.exporter.to_bundle(self.report)
        assert bundle["type"] == "bundle"
        assert bundle["spec_version"] == "2.1"
        assert bundle["id"].startswith("bundle--")
        assert len(bundle["objects"]) >= 4

    def test_bundle_contains_incident_and_indicators(self):
        bundle = self.exporter.to_bundle(self.report)
        obj_types = [o["type"] for o in bundle["objects"]]
        assert "incident" in obj_types
        assert "attack-pattern" in obj_types
        assert "indicator" in obj_types
        assert "relationship" in obj_types

    def test_export_to_file(self, tmp_path):
        p = tmp_path / "stix_test.json"
        exported = self.exporter.export_to_file(self.report, p)
        assert exported.exists()
        loaded = json.loads(exported.read_text(encoding="utf-8"))
        assert loaded["spec_version"] == "2.1"


# ---------------------------------------------------------------------------
# 3. MITRE Attack Graph Visualizer Tests
# ---------------------------------------------------------------------------

class TestAttackGraphVisualizer:
    def setup_method(self):
        self.visualizer = AttackGraphVisualizer()
        self.report = _make_test_report()

    def test_analyze_path_returns_metrics(self):
        summary = self.visualizer.analyze_path(self.report)
        assert isinstance(summary, AttackPathSummary)
        assert summary.total_stages == len(self.report.timeline)
        assert summary.attack_span_minutes >= 0

    def test_mermaid_flowchart_contains_entities(self):
        flow = self.visualizer.to_mermaid_flowchart(self.report)
        assert "flowchart LR" in flow
        assert "dc_01" in flow or "dc-01" in flow

    def test_mermaid_sequence_diagram(self):
        seq = self.visualizer.to_mermaid_sequence(self.report)
        assert "sequenceDiagram" in seq

    def test_ascii_kill_chain_table(self):
        kc = self.visualizer.to_ascii_kill_chain(self.report)
        assert "MITRE ATT&CK Phase" in kc
        assert "[X] YES" in kc

    def test_dot_graph(self):
        dot = self.visualizer.to_dot(self.report)
        assert "digraph AttackGraph" in dot


# ---------------------------------------------------------------------------
# 4. Chain of Custody Tests
# ---------------------------------------------------------------------------

class TestChainOfCustody:
    def setup_method(self):
        self.builder = ChainOfCustodyBuilder()
        self.report = _make_test_report()

    def test_build_manifest_and_verify_signature(self):
        manifest = self.builder.build_manifest(self.report, legal_hold=True)
        assert isinstance(manifest, ChainOfCustodyManifest)
        assert manifest.legal_hold_active is True
        assert len(manifest.items) >= 4
        assert manifest.verify_integrity() is True

    def test_tamper_detection_fails_verification(self):
        manifest = self.builder.build_manifest(self.report)
        assert manifest.verify_integrity() is True
        # Alter an evidence item digest
        manifest.items[0].sha256_hash = "0000000000000000000000000000000000000000000000000000000000000000"
        assert manifest.verify_integrity() is False

    def test_manifest_markdown(self):
        manifest = self.builder.build_manifest(self.report)
        md = manifest.to_markdown()
        assert "FORENSIC CHAIN-OF-CUSTODY MANIFEST" in md
        assert manifest.manifest_id in md


# ---------------------------------------------------------------------------
# 5. Regulatory Compliance Engine Tests
# ---------------------------------------------------------------------------

class TestComplianceDisclosureEngine:
    def setup_method(self):
        self.engine = ComplianceDisclosureEngine()
        self.report = _make_test_report(severity=SeverityLevel.CRITICAL)

    def test_gdpr_triggered_when_pii_exposed(self):
        result = self.engine.evaluate(self.report, records_exposed=50000, pii_detected=True)
        assert result.requires_immediate_action is True
        gdpr = next((o for o in result.obligations if o.regulation_code == "GDPR_ART_33"), None)
        assert gdpr is not None
        assert gdpr.triggered is True
        assert gdpr.hours_remaining is not None
        assert gdpr.hours_remaining > 0

    def test_pci_dss_triggered_when_payment_data_involved(self):
        result = self.engine.evaluate(self.report, payment_data_detected=True)
        pci = next((o for o in result.obligations if o.regulation_code == "PCI_DSS_12_10"), None)
        assert pci is not None
        assert pci.triggered is True
        assert pci.hours_remaining is not None
        assert pci.hours_remaining > 0

    def test_compliance_markdown(self):
        result = self.engine.evaluate(self.report, pii_detected=True)
        md = result.to_markdown()
        assert "STATUTORY BREACH COMPLIANCE" in md
        assert "GDPR Article 33" in md


# ---------------------------------------------------------------------------
# 6. Root Cause Analysis Tests
# ---------------------------------------------------------------------------

class TestRootCauseAnalyzer:
    def setup_method(self):
        self.analyzer = RootCauseAnalyzer()
        self.report = _make_test_report()

    def test_analyze_generates_5_whys(self):
        rca = self.analyzer.analyze(self.report)
        assert isinstance(rca, RootCauseReport)
        assert len(rca.five_whys_chain) == 5
        assert len(rca.preventative_gaps) >= 2
        assert len(rca.action_items) >= 2

    def test_d3fend_countermeasures_mapped(self):
        rca = self.analyzer.analyze(self.report)
        assert len(rca.d3fend_countermeasures) >= 1
        d3_ids = [c["d3fend_id"] for c in rca.d3fend_countermeasures]
        assert any(id.startswith("D3-") for id in d3_ids)

    def test_rca_markdown(self):
        rca = self.analyzer.analyze(self.report)
        md = rca.to_markdown()
        assert "POST-INCIDENT REVIEW & ROOT CAUSE ANALYSIS" in md
        assert "5-Whys Causal Decomposition" in md


# ---------------------------------------------------------------------------
# 7. Report Dispatcher & Redaction Tests
# ---------------------------------------------------------------------------

class TestReportDispatcher:
    def setup_method(self):
        self.dispatcher = ReportDispatcher()
        self.report = _make_test_report()

    def test_slack_block_kit_structure(self):
        payload = self.dispatcher.to_slack_block_kit(self.report)
        assert "attachments" in payload
        blocks = payload["attachments"][0]["blocks"]
        assert any(b["type"] == "header" for b in blocks)
        assert any(b["type"] == "actions" for b in blocks)

    def test_teams_adaptive_card_structure(self):
        card = self.dispatcher.to_teams_adaptive_card(self.report)
        assert card["type"] == "AdaptiveCard"
        assert card["version"] == "1.5"

    def test_pagerduty_payload_structure(self):
        pd = self.dispatcher.to_pagerduty_payload(self.report)
        assert pd["event_action"] == "trigger"
        assert pd["payload"]["severity"] in ("critical", "error", "warning")

    def test_role_based_redaction_for_external_partners(self):
        raw_text = "Attacker connected from 192.168.1.50 using corp\\jsmith account."
        redacted = self.dispatcher.redact_text(raw_text, role=AudienceRole.EXTERNAL_PARTNER)
        assert "192.168.1.50" not in redacted
        assert "corp\\jsmith" not in redacted
        assert "[INTERNAL_IP_MASKED]" in redacted
        assert "[USER_MASKED]" in redacted


# ---------------------------------------------------------------------------
# 8. Report Diff Engine Tests
# ---------------------------------------------------------------------------

class TestReportDiffEngine:
    def setup_method(self):
        self.diff_engine = ReportDiffEngine()
        self.report_v1 = _make_test_report(severity=SeverityLevel.MEDIUM, lateral_paths=[])
        self.report_v2 = _make_test_report(
            severity=SeverityLevel.CRITICAL,
            lateral_paths=["workstation-01 -> workstation-02", "workstation-02 -> dc-01"],
            adversarial_injection=True,
        )

    def test_detects_severity_upgrade(self):
        diff = self.diff_engine.diff(self.report_v1, self.report_v2)
        assert isinstance(diff, ReportDiffResult)
        assert diff.severity_upgraded is True
        assert diff.prior_severity == SeverityLevel.MEDIUM
        assert diff.current_severity == SeverityLevel.CRITICAL

    def test_detects_new_injection(self):
        diff = self.diff_engine.diff(self.report_v1, self.report_v2)
        assert diff.newly_detected_adversarial_injection is True

    def test_detects_new_lateral_movement(self):
        diff = self.diff_engine.diff(self.report_v1, self.report_v2)
        assert len(diff.new_lateral_movement_paths) == 2

    def test_diff_markdown(self):
        diff = self.diff_engine.diff(self.report_v1, self.report_v2)
        md = diff.to_markdown()
        assert "INCIDENT REVISION AUDIT // DIFF REPORT" in md


# ---------------------------------------------------------------------------
# 9. Unified Report Orchestrator Tests
# ---------------------------------------------------------------------------

class TestReportOrchestrator:
    def setup_method(self):
        self.orchestrator = ReportOrchestrator()
        self.report = _make_test_report()

    def test_build_package_contains_all_artifacts(self):
        pkg = self.orchestrator.build_package(
            self.report,
            records_exposed=10000,
            pii_detected=True,
            legal_hold=True,
        )
        assert isinstance(pkg, IncidentReportPackage)
        assert pkg.executive_briefing is not None
        assert pkg.stix_bundle is not None
        assert pkg.chain_of_custody is not None
        assert pkg.compliance_report is not None
        assert pkg.root_cause_analysis is not None
        assert pkg.slack_payload is not None

    def test_export_all_writes_all_files(self, tmp_path):
        pkg = self.orchestrator.build_package(self.report)
        exported = pkg.export_all(output_dir=tmp_path)
        expected_keys = [
            "technical_markdown",
            "executive_briefing",
            "stix_bundle",
            "attack_graph_mermaid",
            "chain_of_custody",
            "compliance_briefing",
            "root_cause_analysis",
            "dispatch_payloads",
        ]
        for k in expected_keys:
            assert k in exported
            assert exported[k].exists()
            assert exported[k].stat().st_size > 0
