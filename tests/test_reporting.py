"""
Phase 5: Evidence-Linked Report Generation Tests.

Validates:
- Structured IncidentReport generation from InvestigationState
- Chronological timeline assembly and event indexing
- Entity-to-evidence traceability mapping
- Severity audit and invariant preservation in reports
- Markdown export format and structure
- Publication-ready PDF rendering via reportlab
- Full LangGraph agent graph integration
- FastAPI REST endpoints: JSON report, Markdown stream, and PDF download
"""
from datetime import datetime, timezone, timedelta
import pytest
from httpx import AsyncClient, ASGITransport

from backend.correlation import correlation_engine, CorrelatedIncident, IncidentStatus
from backend.ingestion.models import (
    NormalizedAlert, Entity, EntityType, EntityRole,
    SeverityLevel, AlertSourceType, MitreAttackMetadata,
)
from backend.agent.graph import investigate_incident
from backend.reporting.models import IncidentReport, TimelineEvent, EntityTraceability
from backend.reporting.builder import build_report
from backend.reporting.markdown import render_markdown
from backend.reporting.pdf import render_pdf
from backend.app.main import app


def _create_test_incident(incident_id="INC-RPT-001", alert_count=3) -> CorrelatedIncident:
    """Helper to populate an incident with multiple alerts at staggered timestamps."""
    base_time = datetime(2026, 9, 28, 10, 0, 0, tzinfo=timezone.utc)
    alerts = []
    tactics = ["Initial Access", "Execution", "Lateral Movement"]
    hosts = ["workstation-01", "workstation-02", "dc-01.corp"]

    for i in range(alert_count):
        ts = base_time + timedelta(minutes=10 * i)
        alerts.append(
            NormalizedAlert(
                alert_id=f"ALT-RPT-{i+1}",
                fingerprint=f"fp-rpt-{i+1}",
                source=AlertSourceType.WAZUH,
                rule_id=f"R-RPT-{i+1}",
                rule_name=f"Suspicious activity stage {i+1}",
                rule_description=f"Detailed description of activity stage {i+1}",
                raw_severity="high" if i > 0 else "medium",
                normalized_severity=SeverityLevel.HIGH if i > 0 else SeverityLevel.MEDIUM,
                timestamp=ts.isoformat(),
                source_ip="198.51.100.77",
                host=hosts[i],
                raw_payload={"stage": i + 1},
                entities=[
                    Entity(type=EntityType.IP, value="198.51.100.77", role=EntityRole.SOURCE),
                    Entity(type=EntityType.HOST, value=hosts[i], role=EntityRole.TARGET),
                    Entity(type=EntityType.USER, value="jdoe", role=EntityRole.TARGET),
                ],
                mitre_attack=MitreAttackMetadata(
                    tactic=tactics[i],
                    technique=f"T105{i}",
                    technique_name=f"Technique {i}",
                ),
            )
        )

    incident = CorrelatedIncident(
        incident_id=incident_id,
        title="Multi-stage Lateral Movement Campaign",
        status=IncidentStatus.ACTIVE,
        created_at=base_time.isoformat(),
        updated_at=(base_time + timedelta(minutes=30)).isoformat(),
        window_start=base_time.isoformat(),
        window_end=(base_time + timedelta(minutes=30)).isoformat(),
        alert_count=len(alerts),
        alert_ids=[a.alert_id for a in alerts],
        alerts=alerts,
        entities=list({e.value: e for a in alerts for e in a.entities}.values()),
        primary_entity="198.51.100.77",
        tactics=tactics,
        techniques=[f"T105{i}" for i in range(alert_count)],
        attack_chain_span=len(tactics),
        correlation_reasons=["Shared attacker IP 198.51.100.77 across hosts"],
        deterministic_score=65.0,
        deterministic_floor=SeverityLevel.HIGH,
        severity=SeverityLevel.HIGH,
    )
    correlation_engine._incidents[incident_id] = incident
    return incident


class TestReportBuilder:
    """Tests for assembling the structured IncidentReport."""

    def test_build_report_basic_fields(self):
        incident = _create_test_incident("INC-RPT-BUILD-01")
        mock_state = {
            "incident": incident,
            "threat_intel": {
                "198.51.100.77": {
                    "verdict": "malicious",
                    "abuse_score": 95,
                    "source": "virustotal",
                }
            },
            "asset_context": {
                "dc-01.corp": {"criticality": "tier_0_critical", "owner": "secops"},
            },
            "lateral_movement_paths": ["workstation-01 -> dc-01.corp"],
            "log_evidence": [
                {"timestamp": datetime(2026, 9, 28, 10, 15, tzinfo=timezone.utc), "message": "Kerberos ticket request", "host": "dc-01.corp"}
            ],
            "scoring_breakdown": {
                "base_score": 50.0,
                "asset_multiplier": 1.5,
                "threat_intel_points": 20.0,
                "mitre_multiplier": 1.2,
                "lateral_movement_points": 15.0,
                "raw_calculated_score": 85.0,
                "deterministic_floor": "high",
            },
            "floor_enforced": True,
            "audit_note": "Downgrade rejected; floor preserved at HIGH",
            "adversarial_injection_detected": False,
            "severity_recommendation": SeverityLevel.CRITICAL,
            "recommended_actions": ["Isolate dc-01.corp immediately", "Revoke compromised tokens"],
            "narrative": "Executive investigation summary...",
        }

        report = build_report(mock_state)

        assert isinstance(report, IncidentReport)
        assert report.incident_id == "INC-RPT-BUILD-01"
        assert report.report_id.startswith("RPT-INC-RPT-BUILD-01-")
        assert report.final_severity == SeverityLevel.CRITICAL
        assert report.deterministic_floor == SeverityLevel.HIGH
        assert report.status == "active"
        assert len(report.recommended_actions) == 2
        assert report.adversarial_injection_detected is False

    def test_chronological_timeline_ordering(self):
        incident = _create_test_incident("INC-RPT-CHRONO-01")
        mock_state = {
            "incident": incident,
            "threat_intel": {
                "198.51.100.77": {"verdict": "malicious", "abuse_score": 90, "source": "abuseipdb"}
            },
            "asset_context": {},
            "lateral_movement_paths": ["workstation-01 -> workstation-02"],
            "log_evidence": [
                {"timestamp": datetime(2026, 9, 28, 10, 5, tzinfo=timezone.utc), "message": "Log mid-event", "source_ip": "198.51.100.77"}
            ],
        }

        report = build_report(mock_state)

        # Timeline must be strictly sorted by timestamp ascending
        for i in range(len(report.timeline) - 1):
            assert report.timeline[i].timestamp <= report.timeline[i + 1].timestamp

    def test_entity_traceability_indexing(self):
        incident = _create_test_incident("INC-RPT-TRACE-01")
        mock_state = {
            "incident": incident,
            "threat_intel": {
                "198.51.100.77": {"verdict": "malicious", "abuse_score": 100, "source": "threat_intel"}
            },
            "asset_context": {"dc-01.corp": {"criticality": "tier_0_critical"}},
            "lateral_movement_paths": [],
            "log_evidence": [],
        }

        report = build_report(mock_state)

        attacker_ent = next((e for e in report.entities if e.entity_value == "198.51.100.77"), None)
        assert attacker_ent is not None
        assert attacker_ent.threat_verdict == "malicious"
        assert attacker_ent.abuse_score == 100
        assert len(attacker_ent.timeline_event_indices) > 0

    def test_severity_audit_record_preservation(self):
        incident = _create_test_incident("INC-RPT-AUDIT-01")
        mock_state = {
            "incident": incident,
            "scoring_breakdown": {
                "base_score": 40.0,
                "asset_multiplier": 1.25,
                "threat_intel_points": 15.0,
                "mitre_multiplier": 1.1,
                "lateral_movement_points": 0.0,
                "raw_calculated_score": 65.0,
                "deterministic_floor": "high",
            },
            "floor_enforced": True,
            "audit_note": "Rule applied: floor locked to HIGH",
            "severity_recommendation": SeverityLevel.HIGH,
        }

        report = build_report(mock_state)

        audit = report.severity_audit
        assert audit.deterministic_floor == "high"
        assert audit.floor_enforced is True
        assert audit.llm_reasoning == "Rule applied: floor locked to HIGH"
        assert audit.base_score == 40.0
        assert audit.final_severity == "high"


class TestMarkdownRenderer:
    """Tests for rendering reports to Markdown."""

    def test_render_markdown_contains_all_key_sections(self):
        incident = _create_test_incident("INC-RPT-MD-01")
        mock_state = {
            "incident": incident,
            "threat_intel": {"198.51.100.77": {"verdict": "malicious", "abuse_score": 88}},
            "asset_context": {"dc-01.corp": {"criticality": "tier_0_critical"}},
            "lateral_movement_paths": ["workstation-01 -> dc-01.corp"],
            "scoring_breakdown": {
                "base_score": 50.0,
                "asset_multiplier": 1.5,
                "threat_intel_points": 20.0,
                "mitre_multiplier": 1.2,
                "lateral_movement_points": 15.0,
                "raw_calculated_score": 85.0,
                "deterministic_floor": "high",
            },
            "floor_enforced": True,
            "recommended_actions": ["Isolate host", "Rotate keys"],
            "narrative": "Comprehensive investigation narrative for SOC analysis.",
        }
        report = build_report(mock_state)
        md = render_markdown(report)

        assert "# [HIGH] Security Incident Report - INC-RPT-MD-01" in md
        assert "## Executive Summary" in md
        assert "## Severity Determination" in md
        assert "| **Base Score** | 50.0 |" in md
        assert "| **Floor Enforced** | YES - LLM downgrade blocked |" in md
        assert "## MITRE ATT&CK Mapping" in md
        assert "## Affected Entities & Evidence Traceability" in md
        assert "198.51.100.77" in md
        assert "## Evidence Timeline" in md
        assert "## Lateral Movement Analysis" in md
        assert "workstation-01 -> dc-01.corp" in md
        assert "## Recommended Containment Actions" in md
        assert "1. Isolate host" in md
        assert "2. Rotate keys" in md


class TestPdfRenderer:
    """Tests for PDF export using reportlab."""

    def test_render_pdf_produces_valid_pdf_bytes(self):
        incident = _create_test_incident("INC-RPT-PDF-01")
        mock_state = {
            "incident": incident,
            "threat_intel": {"198.51.100.77": {"verdict": "malicious", "abuse_score": 95}},
            "asset_context": {"dc-01.corp": {"criticality": "tier_0_critical"}},
            "lateral_movement_paths": ["hostA -> hostB"],
            "scoring_breakdown": {"base_score": 60.0, "raw_calculated_score": 90.0, "deterministic_floor": "critical"},
            "recommended_actions": ["Emergency triage"],
            "narrative": "Incident analysis narrative.",
        }
        report = build_report(mock_state)
        pdf_bytes = render_pdf(report)

        assert isinstance(pdf_bytes, bytes)
        assert len(pdf_bytes) > 2000
        # Valid PDF files must start with %PDF magic bytes
        assert pdf_bytes.startswith(b"%PDF")


class TestAgentGraphIntegration:
    """Tests that investigate_incident populates report fields in InvestigationState."""

    def test_investigate_incident_populates_report(self):
        incident = _create_test_incident("INC-RPT-GRAPH-01")
        state = investigate_incident("INC-RPT-GRAPH-01")

        assert state.get("investigation_complete") is True
        assert state.get("incident_report") is not None
        assert isinstance(state["incident_report"], IncidentReport)
        assert state["incident_report"].incident_id == "INC-RPT-GRAPH-01"
        assert state.get("report_markdown") is not None
        assert "# " in state["report_markdown"]


@pytest.mark.asyncio
class TestReportApiEndpoints:
    """Tests for REST endpoints under /api/v1/incidents/{incident_id}/report."""

    async def test_get_report_json(self):
        incident = _create_test_incident("INC-RPT-API-01")
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get(f"/api/v1/incidents/{incident.incident_id}/report")
            assert response.status_code == 200
            data = response.json()
            assert data["incident_id"] == "INC-RPT-API-01"
            assert "report_id" in data
            assert "timeline" in data
            assert "entities" in data
            assert "severity_audit" in data

    async def test_get_report_markdown(self):
        incident = _create_test_incident("INC-RPT-API-02")
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get(f"/api/v1/incidents/{incident.incident_id}/report/markdown")
            assert response.status_code == 200
            assert "text/markdown" in response.headers["content-type"]
            assert f"INC-RPT-API-02" in response.text
            assert "## Executive Summary" in response.text

    async def test_get_report_pdf(self):
        incident = _create_test_incident("INC-RPT-API-03")
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get(f"/api/v1/incidents/{incident.incident_id}/report/pdf")
            assert response.status_code == 200
            assert response.headers["content-type"] == "application/pdf"
            assert response.content.startswith(b"%PDF")
            assert len(response.content) > 1000

    async def test_get_report_nonexistent_returns_404(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/api/v1/incidents/INC-NONEXISTENT-999/report")
            assert response.status_code == 404
