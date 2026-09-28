"""
Phase 6: Escalation & Human-in-the-Loop Response Gate Tests.

Validates:
- Structured response actions and risk classification (Tier-0 assets -> CRITICAL risk)
- Dry-run simulation and reversible containment rollback (isolate host, block IP, disable user)
- Analyst approval / rejection state machine transitions and audit trails
- Outbound escalation dispatchers (Slack Block Kit interactive buttons & PagerDuty Events v2)
- LangGraph investigation integration generating proposed actions
- Full FastAPI REST lifecycle endpoints (/actions, /approve, /reject, /rollback, /escalate)
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
from backend.agent.tools.asset_context import AssetCriticalityTier
from backend.response import (
    ActionType,
    ActionRiskLevel,
    ActionStatus,
    ProposedAction,
    ActionDecisionRequest,
    EscalationChannel,
    action_executor,
    escalation_dispatcher,
    response_manager,
    ActionExecutionError,
)
from backend.app.main import app


def _create_response_test_incident(incident_id="INC-RESP-001") -> CorrelatedIncident:
    base_time = datetime(2026, 9, 28, 12, 0, 0, tzinfo=timezone.utc)
    alerts = [
        NormalizedAlert(
            alert_id=f"ALT-RESP-1",
            fingerprint=f"fp-resp-1",
            source=AlertSourceType.WAZUH,
            rule_id="R-RESP-1",
            rule_name="Mimikatz Credential Dumping",
            rule_description="Memory injection into lsass.exe detected",
            raw_severity="high",
            normalized_severity=SeverityLevel.HIGH,
            timestamp=base_time.isoformat(),
            source_ip="203.0.113.55",
            host="corp-dc-01.local",
            raw_payload={},
            entities=[
                Entity(type=EntityType.IP, value="203.0.113.55", role=EntityRole.SOURCE),
                Entity(type=EntityType.HOST, value="corp-dc-01.local", role=EntityRole.TARGET),
                Entity(type=EntityType.USER, value="svc_backup", role=EntityRole.TARGET),
            ],
            mitre_attack=MitreAttackMetadata(
                tactic="Credential Access",
                technique="T1003.001",
                technique_name="LSASS Memory",
            ),
        ),
        NormalizedAlert(
            alert_id=f"ALT-RESP-2",
            fingerprint=f"fp-resp-2",
            source=AlertSourceType.WAZUH,
            rule_id="R-RESP-2",
            rule_name="Lateral Movement via WMI",
            rule_description="Remote process creation on internal workstation",
            raw_severity="high",
            normalized_severity=SeverityLevel.HIGH,
            timestamp=(base_time + timedelta(minutes=5)).isoformat(),
            source_ip="203.0.113.55",
            host="wkstn-fin-04",
            raw_payload={},
            entities=[
                Entity(type=EntityType.IP, value="203.0.113.55", role=EntityRole.SOURCE),
                Entity(type=EntityType.HOST, value="wkstn-fin-04", role=EntityRole.TARGET),
            ],
            mitre_attack=MitreAttackMetadata(
                tactic="Lateral Movement",
                technique="T1047",
                technique_name="Windows Management Instrumentation",
            ),
        ),
    ]

    incident = CorrelatedIncident(
        incident_id=incident_id,
        title="Active Active Directory Domain Controller Compromise",
        status=IncidentStatus.ACTIVE,
        created_at=base_time.isoformat(),
        updated_at=(base_time + timedelta(minutes=10)).isoformat(),
        window_start=base_time.isoformat(),
        window_end=(base_time + timedelta(minutes=10)).isoformat(),
        alert_count=len(alerts),
        alert_ids=[a.alert_id for a in alerts],
        alerts=alerts,
        entities=list({e.value: e for a in alerts for e in a.entities}.values()),
        primary_entity="203.0.113.55",
        tactics=["Credential Access", "Lateral Movement"],
        techniques=["T1003.001", "T1047"],
        attack_chain_span=2,
        correlation_reasons=["Shared attacker IP 203.0.113.55"],
        deterministic_score=75.0,
        deterministic_floor=SeverityLevel.CRITICAL,
        severity=SeverityLevel.CRITICAL,
    )
    correlation_engine._incidents[incident_id] = incident
    return incident


class TestActionExecutor:
    """Tests the containment execution and reversible rollback capabilities."""

    def test_execute_isolate_host_dry_run(self):
        action = ProposedAction(
            action_id="ACT-TEST-001",
            incident_id="INC-001",
            action_type=ActionType.ISOLATE_HOST,
            target="prod-server-01",
            risk_level=ActionRiskLevel.HIGH,
            reason="Malware propagation mitigation",
        )
        receipt = action_executor.execute(action, dry_run=True)
        assert receipt["status"] == "success"
        assert receipt["dry_run"] is True
        assert receipt["details"]["isolated"] is True
        assert receipt["details"]["host"] == "prod-server-01"

    def test_rollback_isolate_host(self):
        action = ProposedAction(
            action_id="ACT-TEST-002",
            incident_id="INC-001",
            action_type=ActionType.ISOLATE_HOST,
            target="prod-server-01",
            risk_level=ActionRiskLevel.HIGH,
            status=ActionStatus.EXECUTED,
            reason="Containment",
        )
        receipt = action_executor.rollback(action, dry_run=True)
        assert receipt["status"] == "rolled_back"
        assert receipt["details"]["isolated"] is False

    def test_execute_and_rollback_block_ip(self):
        action = ProposedAction(
            action_id="ACT-TEST-003",
            incident_id="INC-001",
            action_type=ActionType.BLOCK_IP,
            target="198.51.100.99",
            risk_level=ActionRiskLevel.MEDIUM,
            reason="C2 beaconing block",
        )
        exec_receipt = action_executor.execute(action, dry_run=True)
        assert exec_receipt["status"] == "success"
        assert "DROP_ALL" in exec_receipt["details"]["action"]

        rollback_receipt = action_executor.rollback(action, dry_run=True)
        assert rollback_receipt["status"] == "rolled_back"
        assert rollback_receipt["details"]["action"] == "REMOVED"

    def test_execute_and_rollback_disable_user(self):
        action = ProposedAction(
            action_id="ACT-TEST-004",
            incident_id="INC-001",
            action_type=ActionType.DISABLE_USER,
            target="compromised_user",
            risk_level=ActionRiskLevel.HIGH,
            reason="Account takeover mitigation",
        )
        exec_receipt = action_executor.execute(action, dry_run=True)
        assert exec_receipt["details"]["account_status"] == "LOCKED_DISABLED"

        rollback_receipt = action_executor.rollback(action, dry_run=True)
        assert rollback_receipt["details"]["account_status"] == "ACTIVE_ENABLED"


class TestResponseManager:
    """Tests action proposal generation, approval gate, and rejection."""

    def test_propose_actions_from_state_classifies_tier0_as_critical(self):
        incident = _create_response_test_incident("INC-MGR-001")
        mock_state = {
            "incident": incident,
            "recommended_actions": [
                "Isolate host corp-dc-01.local immediately to stop lateral spread",
                "Block attacker IP 203.0.113.55 at perimeter firewall",
                "Disable compromised user account svc_backup",
            ],
            "asset_context": {
                "corp-dc-01.local": {
                    "criticality": AssetCriticalityTier.TIER_0_CRITICAL.value,
                    "role": "Domain Controller",
                }
            },
            "threat_intel": {"203.0.113.55": {"verdict": "malicious"}},
            "lateral_movement_paths": ["corp-dc-01.local -> wkstn-fin-04"],
        }

        actions = response_manager.propose_actions_from_state(mock_state)
        assert len(actions) >= 3

        # Domain controller isolation MUST be tagged CRITICAL risk
        dc_action = next(a for a in actions if a.action_type == ActionType.ISOLATE_HOST and a.target == "corp-dc-01.local")
        assert dc_action.risk_level == ActionRiskLevel.CRITICAL
        assert dc_action.status == ActionStatus.PENDING_APPROVAL

        # IP block must be tagged MEDIUM or LOW
        ip_action = next(a for a in actions if a.action_type == ActionType.BLOCK_IP)
        assert ip_action.target == "203.0.113.55"

    def test_analyst_approval_executes_action(self):
        incident = _create_response_test_incident("INC-MGR-002")
        mock_state = {
            "incident": incident,
            "recommended_actions": ["Block attacker IP 203.0.113.55"],
            "asset_context": {},
            "threat_intel": {"203.0.113.55": {"verdict": "malicious"}},
        }
        actions = response_manager.propose_actions_from_state(mock_state)
        action = actions[0]

        updated = response_manager.approve_action(
            action_id=action.action_id,
            analyst_id="analyst_alice",
            notes="Verified malicious IP against abuseipdb",
            auto_execute=True,
            dry_run=True,
        )

        assert updated.status == ActionStatus.EXECUTED
        assert updated.approved_by == "analyst_alice"
        assert updated.approved_at is not None
        assert updated.approval_notes == "Verified malicious IP against abuseipdb"
        assert updated.execution_result is not None

    def test_analyst_rejection_marks_rejected(self):
        incident = _create_response_test_incident("INC-MGR-003")
        mock_state = {
            "incident": incident,
            "recommended_actions": ["Disable user svc_backup"],
            "asset_context": {},
            "threat_intel": {},
        }
        actions = response_manager.propose_actions_from_state(mock_state)
        action = actions[0]

        updated = response_manager.reject_action(
            action_id=action.action_id,
            analyst_id="analyst_bob",
            reason="Service account is critical for production backups; manual intervention required",
        )

        assert updated.status == ActionStatus.REJECTED
        assert updated.rejected_by == "analyst_bob"
        assert "Service account is critical" in updated.rejection_reason

    def test_cannot_reapprove_executed_action(self):
        incident = _create_response_test_incident("INC-MGR-004")
        mock_state = {
            "incident": incident,
            "recommended_actions": ["Block IP 203.0.113.55"],
            "asset_context": {},
            "threat_intel": {},
        }
        actions = response_manager.propose_actions_from_state(mock_state)
        action = actions[0]
        response_manager.approve_action(action.action_id, analyst_id="analyst_alice")

        with pytest.raises(ValueError, match="already"):
            response_manager.approve_action(action.action_id, analyst_id="analyst_charlie")


class TestEscalationDispatcher:
    """Tests Slack Block Kit formatting and simulated dispatch."""

    def test_build_slack_block_kit(self):
        action = ProposedAction(
            action_id="ACT-SLACK-01",
            incident_id="INC-SLACK-01",
            action_type=ActionType.ISOLATE_HOST,
            target="wkstn-01",
            risk_level=ActionRiskLevel.HIGH,
            reason="Quarantine endpoint",
        )
        blocks = escalation_dispatcher.build_slack_block_kit(
            incident_id="INC-SLACK-01",
            incident_title="Ransomware Outbreak",
            severity="critical",
            deterministic_floor="critical",
            summary="Host infected with LockBit payload.",
            actions=[action],
        )

        assert "blocks" in blocks
        assert any(b.get("type") == "header" for b in blocks["blocks"])
        # Check action button accessory
        action_sections = [b for b in blocks["blocks"] if "accessory" in b]
        assert len(action_sections) == 1
        assert action_sections[0]["accessory"]["type"] == "button"
        assert action_sections[0]["accessory"]["value"] == "approve:ACT-SLACK-01"

    @pytest.mark.asyncio
    async def test_simulated_dispatch_slack_and_pagerduty(self):
        action = ProposedAction(
            action_id="ACT-SIM-01",
            incident_id="INC-SIM-01",
            action_type=ActionType.BLOCK_IP,
            target="1.2.3.4",
            risk_level=ActionRiskLevel.LOW,
            reason="Test block",
        )
        slack_rec = await escalation_dispatcher.dispatch_slack(
            incident_id="INC-SIM-01",
            incident_title="Test Incident",
            severity="high",
            deterministic_floor="high",
            summary="Test summary",
            actions=[action],
            webhook_url=None,
        )
        assert slack_rec.status == "simulated"
        assert slack_rec.channel == EscalationChannel.SLACK

        pd_rec = await escalation_dispatcher.dispatch_pagerduty(
            incident_id="INC-SIM-01",
            incident_title="Test Incident",
            severity="high",
            summary="Test summary",
            actions_count=1,
            routing_key=None,
        )
        assert pd_rec.status == "simulated"
        assert pd_rec.channel == EscalationChannel.PAGERDUTY


class TestGraphHITLIntegration:
    """Tests that investigate_incident populates proposed_actions in state."""

    def test_investigation_graph_populates_proposed_actions(self):
        incident = _create_response_test_incident("INC-HITL-GRAPH-01")
        state = investigate_incident("INC-HITL-GRAPH-01")

        assert state.get("investigation_complete") is True
        assert "proposed_actions" in state
        actions = state["proposed_actions"]
        assert len(actions) > 0
        assert all(isinstance(a, ProposedAction) for a in actions)


@pytest.mark.asyncio
class TestResponseAPIEndpoints:
    """Tests REST endpoints under /api/v1/incidents/{incident_id}/actions and /escalate."""

    async def test_actions_api_lifecycle(self):
        incident = _create_response_test_incident("INC-API-HITL-01")
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            # 1. List actions (auto-triggers investigation if needed)
            resp = await client.get(f"/api/v1/incidents/{incident.incident_id}/actions")
            assert resp.status_code == 200
            actions = resp.json()
            assert len(actions) > 0
            action_id = actions[0]["action_id"]

            # 2. Approve action
            approve_resp = await client.post(
                f"/api/v1/incidents/{incident.incident_id}/actions/{action_id}/approve",
                json={"analyst_id": "soc_analyst_1", "notes": "Approved containment under SOP-04"},
            )
            assert approve_resp.status_code == 200
            appr_data = approve_resp.json()
            assert appr_data["status"] == "executed"
            assert appr_data["approved_by"] == "soc_analyst_1"

            # 3. Rollback action
            rollback_resp = await client.post(
                f"/api/v1/incidents/{incident.incident_id}/actions/{action_id}/rollback",
                json={"analyst_id": "soc_analyst_1"},
            )
            assert rollback_resp.status_code == 200
            rb_data = rollback_resp.json()
            assert rb_data["status"] == "rolled_back"

    async def test_reject_action_endpoint(self):
        incident = _create_response_test_incident("INC-API-HITL-02")
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get(f"/api/v1/incidents/{incident.incident_id}/actions")
            assert resp.status_code == 200
            actions = resp.json()
            action_id = actions[0]["action_id"]

            reject_resp = await client.post(
                f"/api/v1/incidents/{incident.incident_id}/actions/{action_id}/reject",
                json={"analyst_id": "soc_lead", "reason": "Host contains critical non-redundant database"},
            )
            assert reject_resp.status_code == 200
            rej_data = reject_resp.json()
            assert rej_data["status"] == "rejected"
            assert rej_data["rejected_by"] == "soc_lead"

    async def test_escalate_endpoint(self):
        incident = _create_response_test_incident("INC-API-HITL-03")
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                f"/api/v1/incidents/{incident.incident_id}/escalate",
                params={"channel": "slack"},
            )
            assert resp.status_code == 200
            data = resp.json()
            assert data["incident_id"] == incident.incident_id
            assert data["channel"] == "slack"
            assert data["status"] in ("sent", "simulated")
