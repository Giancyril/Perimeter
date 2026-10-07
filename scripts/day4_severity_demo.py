"""
Day 4 Severity Assessment Engine - End-to-End Live Demonstration.

Demonstrates:
1. Dynamic Risk Matrix evaluation with GDPR / PCI-DSS compliance checks.
2. Temporal environmental drift adjustment during an active change freeze.
3. Advanced Threat Actor weighting (e.g. APT29 / Lazarus Group with 0-Day & EDR tampering).
4. Mission-critical business impact calculation with SLA deadlines.
5. Historical score calibration with automated analyst bias feedback.
6. Non-downgrade invariant enforcement (blocking prompt-injection downgrades).
7. Structured Markdown & JSON audit report generation.
"""
import sys
from pathlib import Path
from datetime import datetime, timezone

# Ensure project root is on PYTHONPATH
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.ingestion.models import SeverityLevel
from backend.severity import (
    CompositeSeverityOrchestrator,
    SeverityReportGenerator,
    BulkReportManager,
    LikelihoodLevel,
    ImpactLevel,
    RegulatoryFramework,
    BusinessUnitType,
    AnalystVerdict,
)


def run_demo() -> None:
    print("=" * 70)
    print(" SOC SEVERITY ASSESSMENT ENGINE (DAY 4) - END-TO-END DEMONSTRATION")
    print("=" * 70)

    orchestrator = CompositeSeverityOrchestrator()
    generator = SeverityReportGenerator()
    bulk_manager = BulkReportManager()

    # Scenario 1: Critical Ransomware / APT Attack against Mission-Critical Payments
    print("\n[SCENARIO 1] High-Confidence APT Attack with 0-Day on Payment Checkout")
    result_apt = orchestrator.score(
        incident_id="INC-2026-0901",
        base_score=68.0,
        deterministic_floor=SeverityLevel.HIGH,
        likelihood=LikelihoodLevel.ALMOST_CERTAIN,
        impact=ImpactLevel.CATASTROPHIC,
        records_exposed=250000,
        downtime_hours=3.5,
        crown_jewel_affected=True,
        regulatory_frameworks=[RegulatoryFramework.GDPR, RegulatoryFramework.PCI_DSS],
        change_freeze_active=True,
        config_drift_score=0.75,
        actor_name="Lazarus Group",
        attribution_confidence=0.92,
        observed_0day=True,
        observed_wiper=False,
        observed_edr_tampering=True,
        affected_units=[BusinessUnitType.PAYMENTS_CHECKOUT, BusinessUnitType.IDENTITY_AUTHENTICATION],
        customer_facing_outage=True,
    )

    bulk_manager.add_result(result_apt)
    print(f" -> Final Severity: {result_apt.final_severity.value.upper()}")
    print(f" -> Final Score:    {result_apt.final_score:.1f} / 100")
    print(f" -> Deterministic Floor: {result_apt.deterministic_floor.value.upper()}")
    print(f" -> SLA Ack Deadline:   {result_apt.business_impact.ack_deadline.isoformat()}")

    # Scenario 2: Adversarial Prompt Injection Downgrade Attempt
    print("\n[SCENARIO 2] Adversarial Prompt Injection Downgrade Attempt Blocked")
    result_injected = orchestrator.score(
        incident_id="INC-2026-0902",
        base_score=15.0,
        deterministic_floor=SeverityLevel.CRITICAL,
        proposed_severity=SeverityLevel.LOW,
        adversarial_injection_detected=True,
    )

    bulk_manager.add_result(result_injected)
    print(f" -> Final Enforced: {result_injected.final_severity.value.upper()}")
    print(f" -> Downgrade Prevented: {result_injected.enforcement_record.downgrade_prevented}")
    print(f" -> Violation: {result_injected.enforcement_record.violation_type.value if result_injected.enforcement_record.violation_type else 'None'}")

    # Scenario 3: Analyst Feedback Loop & Calibration
    print("\n[SCENARIO 3] Feeding Analyst Verdict into Feedback Loop")
    orchestrator.record_analyst_feedback(
        incident_id="INC-2026-0901",
        model_score=result_apt.final_score,
        model_severity=result_apt.final_severity,
        verdict=AnalystVerdict.TRUE_POSITIVE_CONFIRMED,
        analyst_id="lead-soc-analyst-42",
        notes="Confirmed T1059 and 0-Day exploit targeting payment gateway.",
    )
    print(" -> Analyst feedback successfully incorporated into empirical calibration.")

    # Generate Reports
    reports_dir = Path(__file__).resolve().parent.parent / "reports"
    written = generator.save_report(result_apt, output_dir=reports_dir, formats=["md", "json"])
    print(f"\n[REPORTS GENERATED]")
    for fmt, p in written.items():
        print(f" -> {fmt.upper()}: {p.name}")

    summary = bulk_manager.generate_summary()
    print("\n[BULK METRICS SUMMARY]")
    print(f" -> Total Incidents Evaluated: {summary['total_incidents']}")
    print(f" -> Severity Distribution:    {summary['severity_distribution']}")
    print(f" -> Floor Enforcements:       {summary['floor_enforcement_count']}")
    print("\n[DEMO COMPLETE] Day 4 Advanced Severity Engine functioning flawlessly.")


if __name__ == "__main__":
    run_demo()
