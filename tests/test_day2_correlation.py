"""
Day 2 Advanced Correlation Engine Test Suite.
Tests for graph-based entity clustering, temporal decay, kill-chain progression,
blast radius, incident merge/split, suppression engine, and telemetry.
"""
import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import patch

from backend.ingestion.models import (
    NormalizedAlert, Entity, EntityType, EntityRole,
    SeverityLevel, AlertSourceType, utc_now,
)
from backend.correlation.graph import EntityGraph
from backend.correlation.temporal import TemporalWindowTracker
from backend.correlation.killchain import KillChainValidator
from backend.correlation.explainer import IncidentExplainer
from backend.correlation.blast_radius import BlastRadiusAssessor, AssetTier
from backend.correlation.suppression import CorrelationSuppressionEngine, SuppressionRule
from backend.correlation.telemetry import CorrelationTelemetry
from backend.correlation.merge_split import IncidentClusterManager
from backend.correlation.models import CorrelatedIncident, IncidentStatus


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────────

def _make_entity(entity_type: EntityType, value: str, internal: bool = False) -> Entity:
    return Entity(type=entity_type, value=value, role=EntityRole.ACTOR)

def _make_alert(
    alert_id: str,
    rule_name: str,
    source_ip: str = "192.168.1.10",
    host: str = "web-01",
    user: str = "analyst",
    timestamp: str | None = None,
    tactics: list | None = None,
    severity: SeverityLevel = SeverityLevel.HIGH,
) -> NormalizedAlert:
    from backend.ingestion.models import NormalizedAlert, MitreAttackMetadata, Entity, EntityType, EntityRole
    ts = timestamp or utc_now()
    entities = [
        Entity(type=EntityType.IP, value=source_ip, role=EntityRole.ACTOR),
        Entity(type=EntityType.HOST, value=host, role=EntityRole.TARGET),
    ]
    if user:
        entities.append(Entity(type=EntityType.USER, value=user, role=EntityRole.RELATED))
    return NormalizedAlert(
        alert_id=alert_id,
        fingerprint=f"fp-{alert_id}",
        source=AlertSourceType.WAZUH,
        timestamp=ts,
        rule_id="9999",
        rule_name=rule_name,
        rule_description=rule_name,
        raw_severity="high",
        normalized_severity=severity,
        entities=entities,
        source_ip=source_ip,
        destination_ip="10.0.0.1",
        host=host,
        user=user,
        raw_payload={},
    )

def _make_incident(
    incident_id: str = "INC-2026-0001",
    severity: SeverityLevel = SeverityLevel.HIGH,
    tactics: list | None = None,
    alerts: list | None = None,
    entities: list | None = None,
) -> CorrelatedIncident:
    _alerts = alerts or [_make_alert("A1", "Brute Force")]
    _entities = entities or list(_alerts[0].entities)
    return CorrelatedIncident(
        incident_id=incident_id,
        title="Test Incident",
        status=IncidentStatus.NEW,
        window_start=utc_now(),
        window_end=utc_now(),
        alert_count=len(_alerts),
        alert_ids=[a.alert_id for a in _alerts],
        alerts=_alerts,
        entities=_entities,
        tactics=tactics or ["Credential Access"],
        techniques=["T1110"],
        attack_chain_span=len(tactics or ["Credential Access"]),
        correlation_reasons=["Initial alert"],
        deterministic_score=55,
        deterministic_floor=severity,
        severity=severity,
    )


# ─────────────────────────────────────────────────────────────────────────────
# EntityGraph tests
# ─────────────────────────────────────────────────────────────────────────────

class TestEntityGraph:

    def test_add_alert_creates_nodes(self):
        graph = EntityGraph()
        alert = _make_alert("A1", "Brute Force")
        graph.add_alert(alert)
        assert "A1" in graph.alerts
        assert len(graph.entities) >= 2  # IP and HOST

    def test_shared_entity_cluster(self):
        graph = EntityGraph()
        a1 = _make_alert("A1", "Brute Force", source_ip="10.1.1.1", host="srv-a")
        a2 = _make_alert("A2", "Port Scan", source_ip="10.1.1.1", host="srv-b")
        graph.add_alert(a1)
        graph.add_alert(a2)
        clusters = graph.find_connected_clusters()
        assert len(clusters) == 1
        assert len(clusters[0]["alert_ids"]) == 2

    def test_independent_alerts_produce_separate_clusters(self):
        graph = EntityGraph()
        a1 = _make_alert("A1", "Alert A", source_ip="192.168.1.1", host="host-alpha")
        a2 = _make_alert("A2", "Alert B", source_ip="10.200.200.1", host="host-beta")
        # Override entities so they share nothing
        from backend.ingestion.models import Entity, EntityType, EntityRole
        a1.entities = [Entity(type=EntityType.IP, value="192.168.1.1", role=EntityRole.ACTOR)]
        a2.entities = [Entity(type=EntityType.IP, value="10.200.200.1", role=EntityRole.ACTOR)]
        graph.add_alert(a1)
        graph.add_alert(a2)
        clusters = graph.find_connected_clusters()
        assert len(clusters) == 2

    def test_pivot_path_found(self):
        graph = EntityGraph()
        a1 = _make_alert("A1", "Brute Force", source_ip="5.5.5.5", host="srv-a")
        a2 = _make_alert("A2", "Lateral Move", source_ip="5.5.5.5", host="srv-b")
        graph.add_alert(a1)
        graph.add_alert(a2)
        path = graph.find_shortest_pivot_path("ip:5.5.5.5", "host:srv-b")
        assert path is not None
        assert "ip:5.5.5.5" in path
        assert "host:srv-b" in path

    def test_entity_centrality(self):
        graph = EntityGraph()
        graph.add_alert(_make_alert("B1", "Test1", source_ip="9.9.9.9"))
        graph.add_alert(_make_alert("B2", "Test2", source_ip="9.9.9.9"))
        assert graph.get_entity_centrality("ip:9.9.9.9") == 2

    def test_export_graph_json_schema(self):
        graph = EntityGraph()
        graph.add_alert(_make_alert("A1", "Brute Force"))
        data = graph.export_graph_json()
        assert "nodes" in data and "edges" in data and "stats" in data
        assert data["stats"]["total_alerts"] == 1

    def test_pivot_path_none_for_unknown_entity(self):
        graph = EntityGraph()
        graph.add_alert(_make_alert("A1", "Test"))
        path = graph.find_shortest_pivot_path("ip:99.99.99.99", "host:nonexistent")
        assert path is None


# ─────────────────────────────────────────────────────────────────────────────
# TemporalWindowTracker tests
# ─────────────────────────────────────────────────────────────────────────────

class TestTemporalWindowTracker:

    def test_decay_at_time_zero_is_one(self):
        tracker = TemporalWindowTracker()
        ts = utc_now()
        weight = tracker.calculate_decay_weight(ts, ts)
        assert weight == 1.0

    def test_decay_decreases_with_time(self):
        tracker = TemporalWindowTracker(decay_half_life_seconds=300.0)
        base = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        later = datetime(2026, 1, 1, 12, 5, 0, tzinfo=timezone.utc)  # 5 min later
        w1 = tracker.calculate_decay_weight(base.isoformat(), base.isoformat())
        w2 = tracker.calculate_decay_weight(base.isoformat(), later.isoformat())
        assert w2 < w1

    def test_velocity_burst_detection(self):
        tracker = TemporalWindowTracker(velocity_threshold_rpm=5.0)
        now = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        alerts = []
        for i in range(12):
            a = _make_alert(f"A{i}", f"Alert {i}", timestamp=(now + timedelta(seconds=i * 5)).isoformat())
            alerts.append(a)
        velocity = tracker.calculate_alert_velocity(alerts)
        assert velocity["is_burst"] is True
        assert velocity["rate_per_minute"] > 0

    def test_adaptive_window_contract_on_burst(self):
        tracker = TemporalWindowTracker(base_window_seconds=1800, velocity_threshold_rpm=5.0)
        now = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        alerts = [
            _make_alert(f"A{i}", f"Alert {i}", timestamp=(now + timedelta(seconds=i * 3)).isoformat())
            for i in range(20)
        ]
        w = tracker.compute_adaptive_window(alerts)
        assert w < 1800

    def test_adaptive_window_expands_on_multi_stage(self):
        tracker = TemporalWindowTracker(base_window_seconds=1800)
        now = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        alerts = []
        from backend.ingestion.models import MitreAttackMetadata
        tactics_sequence = ["Reconnaissance", "Initial Access", "Persistence"]
        for i, tactic in enumerate(tactics_sequence):
            a = _make_alert(f"A{i}", f"Alert {i}", timestamp=(now + timedelta(seconds=i * 500)).isoformat())
            a.mitre_attack = MitreAttackMetadata(tactics=[tactic], techniques=[], technique_names=[])
            alerts.append(a)
        w = tracker.compute_adaptive_window(alerts)
        assert w >= 1800


# ─────────────────────────────────────────────────────────────────────────────
# KillChainValidator tests
# ─────────────────────────────────────────────────────────────────────────────

class TestKillChainValidator:

    def test_multi_stage_progressive(self):
        validator = KillChainValidator()
        tactics = ["Initial Access", "Execution", "Persistence", "Lateral Movement"]
        result = validator.evaluate_progression(tactics)
        assert result["is_progressive"] is True
        assert result["forward_ratio"] >= 0.6

    def test_single_stage(self):
        validator = KillChainValidator()
        result = validator.evaluate_progression(["Credential Access"])
        assert result["unique_stages"] == 1
        assert result["is_progressive"] is False

    def test_critical_milestones_detected(self):
        validator = KillChainValidator()
        result = validator.evaluate_progression(["Discovery", "Lateral Movement", "Exfiltration"])
        assert "Lateral Movement" in result["critical_milestones"]
        assert "Exfiltration" in result["critical_milestones"]

    def test_should_escalate_severity(self):
        validator = KillChainValidator()
        evaluation = {
            "is_progressive": True,
            "critical_milestones": ["Lateral Movement"],
            "chain_span": 3,
            "progression_confidence": 0.9,
        }
        assert validator.should_escalate_severity(evaluation) is True

    def test_no_escalation_single_non_critical(self):
        validator = KillChainValidator()
        evaluation = {
            "is_progressive": False,
            "critical_milestones": [],
            "chain_span": 1,
            "progression_confidence": 0.2,
        }
        assert validator.should_escalate_severity(evaluation) is False


# ─────────────────────────────────────────────────────────────────────────────
# IncidentExplainer tests
# ─────────────────────────────────────────────────────────────────────────────

class TestIncidentExplainer:

    def test_single_tactic_title(self):
        title = IncidentExplainer.generate_incident_title(
            tactics=["Credential Access"],
            techniques=["T1110 - Brute Force"],
            primary_entity="192.168.1.50",
            target_host="db-prod-01",
            alert_count=3,
        )
        assert "Credential Access" in title
        assert "db-prod-01" in title

    def test_multi_stage_title(self):
        title = IncidentExplainer.generate_incident_title(
            tactics=["Initial Access", "Persistence"],
            techniques=[],
            primary_entity=None,
            target_host="web-01",
            alert_count=2,
        )
        assert "Multi-Stage" in title
        assert "Initial Access" in title

    def test_correlation_reasons_generated(self):
        reasons = IncidentExplainer.generate_correlation_reasons(
            shared_entities=["ip:10.0.0.1", "host:srv-a"],
            time_span_minutes=25.0,
            tactics=["Lateral Movement"],
            alert_count=5,
        )
        assert len(reasons) >= 2
        assert any("ip:10.0.0.1" in r for r in reasons)

    def test_root_cause_identifies_earliest_alert(self):
        now = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        alerts = [
            _make_alert("A1", "Brute Force", timestamp=(now + timedelta(minutes=10)).isoformat()),
            _make_alert("A2", "Port Scan", timestamp=now.isoformat()),
        ]
        root = IncidentExplainer.summarize_root_cause(alerts)
        assert root["trigger_alert_id"] == "A2"


# ─────────────────────────────────────────────────────────────────────────────
# BlastRadiusAssessor tests
# ─────────────────────────────────────────────────────────────────────────────

class TestBlastRadiusAssessor:

    def test_tier0_classified_correctly(self):
        assessor = BlastRadiusAssessor()
        tier = assessor.classify_asset("prod-dc-controller-01")
        assert tier == AssetTier.TIER_0

    def test_tier1_database(self):
        assessor = BlastRadiusAssessor()
        tier = assessor.classify_asset("postgres-primary")
        assert tier == AssetTier.TIER_1

    def test_crown_jewel_flag_set_for_dc(self):
        assessor = BlastRadiusAssessor()
        from backend.ingestion.models import Entity, EntityType, EntityRole
        entities = [Entity(type=EntityType.HOST, value="prod-dc-01", role=EntityRole.TARGET)]
        result = assessor.assess_incident(entities)
        assert result["is_crown_jewel_compromise"] is True

    def test_blast_score_increases_with_lateral_spread(self):
        assessor = BlastRadiusAssessor()
        from backend.ingestion.models import Entity, EntityType, EntityRole
        entities_small = [Entity(type=EntityType.HOST, value="web-01", role=EntityRole.TARGET)]
        entities_large = [
            Entity(type=EntityType.HOST, value=f"web-0{i}", role=EntityRole.TARGET)
            for i in range(6)
        ]
        result_small = assessor.assess_incident(entities_small)
        result_large = assessor.assess_incident(entities_large)
        assert result_large["blast_radius_score"] > result_small["blast_radius_score"]


# ─────────────────────────────────────────────────────────────────────────────
# CorrelationSuppressionEngine tests
# ─────────────────────────────────────────────────────────────────────────────

class TestCorrelationSuppressionEngine:

    def test_scanner_rule_suppresses_matching_alert(self):
        engine = CorrelationSuppressionEngine()
        alert = _make_alert("A1", "Port scan detected", source_ip="10.200.50.25")
        is_suppressed, rule_id, _ = engine.check_suppression(alert)
        assert is_suppressed is True
        assert rule_id == "vuln-scanner-qualys"

    def test_backup_service_account_suppressed(self):
        engine = CorrelationSuppressionEngine()
        alert = _make_alert("A2", "High disk read during cron", user="svc_backup", source_ip="192.168.0.5")
        is_suppressed, rule_id, _ = engine.check_suppression(alert)
        assert is_suppressed is True
        assert rule_id == "backup-svc-account"

    def test_legitimate_threat_not_suppressed(self):
        engine = CorrelationSuppressionEngine()
        alert = _make_alert("A3", "Ransomware detected", source_ip="1.2.3.4", user="attacker")
        is_suppressed, _, _ = engine.check_suppression(alert)
        assert is_suppressed is False

    def test_add_and_remove_rule(self):
        engine = CorrelationSuppressionEngine()
        rule = SuppressionRule(rule_id="custom-test", description="Test rule", match_users=["testuser"])
        engine.add_rule(rule)
        alert = _make_alert("A4", "Test alert", user="testuser", source_ip="10.0.0.5")
        is_suppressed, rule_id, _ = engine.check_suppression(alert)
        assert is_suppressed is True
        engine.remove_rule("custom-test")
        is_suppressed, _, _ = engine.check_suppression(alert)
        assert is_suppressed is False


# ─────────────────────────────────────────────────────────────────────────────
# CorrelationTelemetry tests
# ─────────────────────────────────────────────────────────────────────────────

class TestCorrelationTelemetry:

    def test_latency_percentile_calculation(self):
        telemetry = CorrelationTelemetry()
        latencies = [10.0, 20.0, 30.0, 50.0, 100.0]
        for lat in latencies:
            telemetry.record_correlation_latency(lat)
        percentiles = telemetry.get_latency_percentiles()
        assert percentiles["p50"] > 0
        assert percentiles["p99"] >= percentiles["p50"]
        assert percentiles["avg"] > 0

    def test_summary_noise_reduction_calculation(self):
        telemetry = CorrelationTelemetry()
        telemetry.total_alerts_suppressed = 5
        alerts = [_make_alert(f"X{j}", f"Alert {j}") for j in range(6)]
        incidents = [_make_incident(f"INC-{i}", alerts=[alerts[i*2], alerts[i*2+1]]) for i in range(3)]
        summary = telemetry.compute_summary(incidents)
        assert summary["total_incidents"] == 3
        assert summary["noise_reduction_percentage"] >= 0

    def test_buffer_bounded_to_1000(self):
        telemetry = CorrelationTelemetry()
        for i in range(2001):
            telemetry.record_correlation_latency(float(i % 100 + 1))
        assert len(telemetry.correlation_latencies_ms) <= 1000


# ─────────────────────────────────────────────────────────────────────────────
# IncidentClusterManager merge/split tests
# ─────────────────────────────────────────────────────────────────────────────

class TestIncidentClusterManager:

    def _shared_entity(self):
        from backend.ingestion.models import Entity, EntityType, EntityRole
        return Entity(type=EntityType.IP, value="5.5.5.5", role=EntityRole.ACTOR)

    def test_merge_incidents_combines_alerts(self):
        a1 = _make_alert("A1", "Brute Force")
        a2 = _make_alert("A2", "Credential Dump")
        inc1 = _make_incident("INC-001", alerts=[a1], entities=list(a1.entities))
        inc2 = _make_incident("INC-002", alerts=[a2], entities=list(a2.entities))
        merged = IncidentClusterManager.merge_incidents(inc1, inc2)
        assert len(merged.alerts) == 2
        assert "A2" in merged.alert_ids

    def test_merge_secondary_marked_resolved(self):
        a1 = _make_alert("A1", "Brute Force")
        a2 = _make_alert("A2", "Port Scan")
        inc1 = _make_incident("INC-001", alerts=[a1])
        inc2 = _make_incident("INC-002", alerts=[a2])
        IncidentClusterManager.merge_incidents(inc1, inc2)
        assert inc2.status == IncidentStatus.RESOLVED

    def test_split_incident_creates_child(self):
        a1 = _make_alert("A1", "Brute Force")
        a2 = _make_alert("A2", "Lateral Movement")
        a3 = _make_alert("A3", "Data Exfiltration")
        inc = _make_incident("INC-001", alerts=[a1, a2, a3])
        parent, child = IncidentClusterManager.split_incident(inc, ["A3"], "INC-002")
        assert child.incident_id == "INC-002"
        assert len(parent.alerts) == 2
        assert len(child.alerts) == 1
        assert child.alerts[0].alert_id == "A3"

    def test_split_raises_on_all_alerts_extracted(self):
        a1 = _make_alert("A1", "Brute Force")
        inc = _make_incident("INC-001", alerts=[a1])
        with pytest.raises(ValueError, match="at least one alert"):
            IncidentClusterManager.split_incident(inc, ["A1"], "INC-002")

    def test_detect_mergeable_incidents_returns_pairs(self):
        from backend.ingestion.models import Entity, EntityType, EntityRole
        shared_ent = Entity(type=EntityType.HOST, value="shared-host", role=EntityRole.TARGET)
        a1 = _make_alert("A1", "Alert 1")
        a2 = _make_alert("A2", "Alert 2")
        a1.entities = [shared_ent]
        a2.entities = [shared_ent]
        inc1 = _make_incident("INC-001", alerts=[a1], entities=[shared_ent])
        inc2 = _make_incident("INC-002", alerts=[a2], entities=[shared_ent])
        candidates = IncidentClusterManager.detect_mergeable_incidents([inc1, inc2])
        assert len(candidates) >= 1
        pair = candidates[0]
        assert pair[0] == "INC-001"
        assert pair[1] == "INC-002"
