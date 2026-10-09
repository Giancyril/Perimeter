"""
Day 5 Advanced Incident Reporting & Executive Briefing Demonstration.

Showcases the complete autonomous reporting lifecycle:
1. IncidentReport synthesis with technical timeline & entity evidence.
2. Executive Briefing with quantified financial risk & C-suite talking points.
3. OASIS STIX 2.1 Threat Intelligence Bundle serialization.
4. Mermaid Attack Graph, Sequence Diagram & ASCII Kill-Chain rendering.
5. Forensic Chain-of-Custody with SHA-256 fingerprinting & HMAC tamper verification.
6. Statutory breach disclosure tracking (GDPR 72h clock & SEC Form 8-K).
7. Root Cause Analysis (5-Whys & MITRE D3FEND defensive countermeasures).
8. Multi-channel dispatch formatting (Slack Block Kit & Teams Adaptive Cards).
9. Revision diffing tracking incident progression.
10. Multi-artifact dossier export to disk.
"""
import sys
from pathlib import Path
from datetime import datetime, timezone, timedelta

# Ensure project root is on PYTHONPATH
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.ingestion.models import SeverityLevel
from backend.reporting.models import (
    IncidentReport,
    TimelineEvent,
    EntityTraceability,
    SeverityAuditRecord,
)
from backend.reporting import (
    ReportOrchestrator,
    ReportDiffEngine,
    AudienceRole,
)


def run_day5_demo() -> None:
    print("=" * 75)
    print(" AUTONOMOUS SOC: EVIDENCE-LINKED REPORTING & EXECUTIVE BRIEFING (DAY 5)")
    print("=" * 75)

    orchestrator = ReportOrchestrator()
    diff_engine = ReportDiffEngine()

    now = datetime.now(timezone.utc)

    timeline = [
        TimelineEvent(
            timestamp=now - timedelta(hours=2),
            event_type="alert",
            source="wazuh",
            title="Credential Dumping via LSASS Memory Read",
            description="Mimikatz command executed by compromised service account.",
            related_entities=["10.0.4.15", "srv-app-01", r"corp\svc_backup"],
            raw_evidence_id="ALT-2026-901",
        ),
        TimelineEvent(
            timestamp=now - timedelta(hours=1, minutes=30),
            event_type="threat_intel_hit",
            source="abuseipdb",
            title="Known Ransomware Operator C2 Callback",
            description="Connection established to BlackCat/ALPHV infrastructure.",
            related_entities=["198.51.100.99", "srv-app-01"],
            raw_evidence_id="ALT-2026-902",
        ),
        TimelineEvent(
            timestamp=now - timedelta(minutes=45),
            event_type="lateral_movement",
            source="siem",
            title="Lateral Movement to Payments Processing Cluster",
            description="SMB session opened to Tier-0 PCI-DSS scoped server.",
            related_entities=["srv-app-01", "pci-payment-db01", r"corp\svc_backup"],
            raw_evidence_id="ALT-2026-903",
        ),
    ]

    entities = [
        EntityTraceability(
            entity_value="198.51.100.99",
            entity_type="ip",
            threat_verdict="malicious",
            abuse_score=100,
            timeline_event_indices=[1],
        ),
        EntityTraceability(
            entity_value="srv-app-01",
            entity_type="host",
            criticality="tier_1",
            timeline_event_indices=[0, 1, 2],
        ),
        EntityTraceability(
            entity_value="pci-payment-db01",
            entity_type="host",
            criticality="critical",
            timeline_event_indices=[2],
        ),
    ]

    audit = SeverityAuditRecord(
        deterministic_floor="CRITICAL",
        rule_override_reason="Tier-0 mission-critical asset exposure confirmed",
        base_score=40.0,
        asset_multiplier=1.5,
        threat_intel_points=25.0,
        mitre_multiplier=1.3,
        lateral_movement_points=20.0,
        raw_calculated_score=92.0,
        floor_enforced=True,
        final_severity="CRITICAL",
    )

    report_v1 = IncidentReport(
        report_id="RPT-INC-2026-7788-V1",
        incident_id="INC-2026-7788",
        generated_at=now - timedelta(hours=1),
        incident_title="Lateral Infiltration of Core Payment Processing Infrastructure",
        final_severity=SeverityLevel.HIGH,
        deterministic_floor=SeverityLevel.HIGH,
        status="TRIAGED",
        timeline=timeline[:2],
        entities=entities[:2],
        severity_audit=audit,
        mitre_tactics=["Initial Access", "Credential Access"],
        mitre_techniques=["T1003.001", "T1071.001"],
        attack_chain_span=2,
        lateral_movement_paths=[],
        adversarial_injection_detected=False,
        recommended_actions=[r"Revoke corp\svc_backup session", "Block 198.51.100.99"],
        executive_summary="Preliminary alert indicates credential theft on app server.",
    )

    report_v2 = IncidentReport(
        report_id="RPT-INC-2026-7788-V2",
        incident_id="INC-2026-7788",
        generated_at=now,
        incident_title="Ransomware Operator Pivot into Tier-0 PCI Payment Database",
        final_severity=SeverityLevel.CRITICAL,
        deterministic_floor=SeverityLevel.CRITICAL,
        status="CONTAINED",
        timeline=timeline,
        entities=entities,
        severity_audit=audit,
        mitre_tactics=["Initial Access", "Credential Access", "Lateral Movement"],
        mitre_techniques=["T1003.001", "T1071.001", "T1021.002"],
        attack_chain_span=3,
        lateral_movement_paths=["srv-app-01 -> pci-payment-db01 via SMB:445"],
        adversarial_injection_detected=True,
        adversarial_injection_reason="Prompt injection command in base64 log payload",
        recommended_actions=["Emergency network isolation of pci-payment-db01", "Trigger PCI-DSS notification"],
        executive_summary="Confirmed high-consequence APT ransomware actor pivoting to payment databases.",
    )

    print("\n[STAGE 1] Synthesizing Multi-Stage Incident Report Package...")
    package = orchestrator.build_package(
        source=report_v2,
        financial_exposure_usd=385000.0,
        estimated_downtime_hours=4.5,
        records_exposed=150000,
        pii_detected=True,
        payment_data_detected=True,
        legal_hold=True,
    )
    print(f" -> Package ID:          {package.package_id}")
    print(f" -> Final Severity:      {package.incident_report.final_severity.value.upper()}")
    print(f" -> Financial Exposure:  ${package.executive_briefing.financial_exposure_usd:,.2f}")
    print(f" -> Chain of Custody:    {package.chain_of_custody.manifest_id} (HMAC verified: {package.chain_of_custody.verify_integrity()})")

    print("\n[STAGE 2] Checking Global Statutory Breach Disclosures...")
    for ob in package.compliance_report.obligations:
        status = "TRIGGERED" if ob.triggered else "NOT TRIGGERED"
        dl = f"{ob.hours_remaining:.1f}h remaining" if ob.hours_remaining else "N/A"
        print(f" -> {ob.regulation_name:<28}: [{status}] - {dl} (Authority: {ob.reporting_authority})")

    print("\n[STAGE 3] Root Cause Analysis & MITRE D3FEND Countermeasures...")
    print(f" -> Root Cause: {package.root_cause_analysis.root_cause_summary[:90]}...")
    for act in package.root_cause_analysis.action_items:
        print(f"    * [{act.priority}] {act.title} (Owner: {act.owner_team}, D3FEND: {act.d3fend_reference})")

    print("\n[STAGE 4] Comparing Incident Revisions (V1 -> V2 Evolution Diff)...")
    diff = diff_engine.diff(report_v1, report_v2)
    print(f" -> Severity Upgraded:       {diff.severity_upgraded} ({diff.prior_severity.value.upper()} -> {diff.current_severity.value.upper()})")
    print(f" -> New Lateral Paths:       {diff.new_lateral_movement_paths}")
    print(f" -> Prompt Injection Found:  {diff.newly_detected_adversarial_injection}")
    print(f" -> Change Narrative:        {diff.change_summary}")

    print("\n[STAGE 5] Exporting All 8 Dossier Artifacts to Disk...")
    out_dir = Path(__file__).resolve().parent.parent / "reports" / "day5_dossier"
    written = package.export_all(out_dir)
    for name, p in written.items():
        print(f" -> {name:<24}: {p.name} ({p.stat().st_size} bytes)")

    print("\n" + "=" * 75)
    print(" DAY 5 DEMO COMPLETE: ALL ENGINES OPERATING AT ENTERPRISE SOC GRADE!")
    print("=" * 75)


if __name__ == "__main__":
    run_day5_demo()
