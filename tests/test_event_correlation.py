"""
Phase 2: Event Correlation Tests.
Validates sliding-window grouping, MITRE chain mapping,
deterministic severity floor, and Ingestion-Correlation integration.
"""
import pytest
from datetime import datetime, timezone, timedelta
from backend.correlation.engine import CorrelationEngine
from backend.correlation.models import CorrelatedIncident, IncidentStatus
from backend.correlation.mitre import sort_tactics_by_killchain, infer_mitre_from_rule
from backend.ingestion.models import (
    NormalizedAlert, Entity, EntityType, EntityRole,
    SeverityLevel, AlertSourceType, MitreAttackMetadata,
)
from backend.ingestion.engine import IngestionEngine


def _make_alert(
    alert_id="a-001",
    rule_name="SSH Brute Force",
    source_ip="10.0.0.1",
    host="server-01",
    severity="high",
    timestamp=None,
    mitre_tactics=None,
    mitre_techniques=None,
):
    ts = timestamp or datetime.now(timezone.utc).isoformat()
    entities = [
        Entity(type=EntityType.IP, value=source_ip, role=EntityRole.SOURCE),
        Entity(type=EntityType.HOST, value=host, role=EntityRole.TARGET),
    ]
    mitre = None
    if mitre_tactics:
        mitre = MitreAttackMetadata(tactics=mitre_tactics, techniques=mitre_techniques or [])
    sev_map = {s.value: s for s in SeverityLevel}
    return NormalizedAlert(
        alert_id=alert_id,
        fingerprint=f"fp-{alert_id}",
        source=AlertSourceType.WAZUH,
        rule_id=f"R-{alert_id}",
        rule_name=rule_name,
        rule_description=f"Test: {rule_name}",
        raw_severity=severity,
        normalized_severity=sev_map.get(severity, SeverityLevel.MEDIUM),
        timestamp=ts,
        source_ip=source_ip,
        host=host,
        entities=entities,
        mitre_attack=mitre,
        raw_payload={"raw": True},
    )


@pytest.fixture()
def engine():
    e = CorrelationEngine(window_seconds=1800)
    e.clear()
    return e


class TestMitreHelpers:
    def test_sort_tactics_ordered(self):
        result = sort_tactics_by_killchain(["Impact", "Initial Access", "Credential Access", "Execution"])
        order = {t: i for i, t in enumerate(result)}
        assert order["Initial Access"] < order["Execution"]
        assert order["Execution"] < order["Credential Access"]
        assert order["Credential Access"] < order["Impact"]

    def test_sort_tactics_deduplicates(self):
        result = sort_tactics_by_killchain(["Execution", "Execution", "Initial Access"])
        assert len(result) == 2

    def test_infer_brute_force(self):
        r = infer_mitre_from_rule("SSH brute force attempt", "R001")
        assert r and "Credential Access" in r["tactics"]

    def test_infer_privilege_escalation(self):
        r = infer_mitre_from_rule("sudo privilege escalation", "R002")
        assert r and "Privilege Escalation" in r["tactics"]

    def test_infer_unknown_returns_none(self):
        assert infer_mitre_from_rule("generic heartbeat", "R999") is None

    def test_infer_port_scan(self):
        r = infer_mitre_from_rule("nmap port scan detected", "R003")
        assert r and "Discovery" in r["tactics"]

    def test_infer_ransomware(self):
        r = infer_mitre_from_rule("ransomware file encryption", "R004")
        assert r and "Impact" in r["tactics"]


class TestNewIncidentCreation:
    def test_first_alert_creates_incident(self, engine):
        inc = engine.correlate(_make_alert("a-001", source_ip="192.168.1.10"))
        assert inc.incident_id.startswith("INC-")
        assert inc.alert_count == 1
        assert inc.status == IncidentStatus.NEW

    def test_title_is_non_empty(self, engine):
        inc = engine.correlate(_make_alert("a-002", rule_name="Brute Force Login", source_ip="10.1.1.1"))
        assert inc.title and len(inc.title) > 5

    def test_severity_equals_floor(self, engine):
        inc = engine.correlate(_make_alert("a-003", severity="critical"))
        assert inc.severity == inc.deterministic_floor

    def test_score_in_range(self, engine):
        inc = engine.correlate(_make_alert("a-004"))
        assert 0 <= inc.deterministic_score <= 100


class TestSlidingWindowGrouping:
    def test_same_ip_within_window_merged(self, engine):
        ts1 = datetime.now(timezone.utc).isoformat()
        ts2 = (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat()
        i1 = engine.correlate(_make_alert("b-001", source_ip="10.5.5.5", timestamp=ts1))
        i2 = engine.correlate(_make_alert("b-002", source_ip="10.5.5.5", timestamp=ts2, rule_name="Port Scan"))
        assert i1.incident_id == i2.incident_id
        assert i2.alert_count == 2

    def test_same_host_within_window_merged(self, engine):
        ts1 = datetime.now(timezone.utc).isoformat()
        ts2 = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()
        i1 = engine.correlate(_make_alert("c-001", host="dc-01", source_ip="10.0.0.1", timestamp=ts1))
        i2 = engine.correlate(_make_alert("c-002", host="dc-01", source_ip="10.0.0.99", timestamp=ts2))
        assert i1.incident_id == i2.incident_id

    def test_different_entities_separate_incidents(self, engine):
        i1 = engine.correlate(_make_alert("e-001", source_ip="1.2.3.4", host="alpha"))
        i2 = engine.correlate(_make_alert("e-002", source_ip="9.9.9.9", host="beta"))
        assert i1.incident_id != i2.incident_id

    def test_merged_incident_has_all_alerts(self, engine):
        ip = "192.168.100.1"
        inc = None
        for i in range(5):
            inc = engine.correlate(_make_alert("f-{:03d}".format(i), source_ip=ip))
        assert inc.alert_count == 5

    def test_correlation_reasons_populated(self, engine):
        ip = "10.10.10.10"
        engine.correlate(_make_alert("g-001", source_ip=ip))
        inc = engine.correlate(_make_alert("g-002", source_ip=ip, rule_name="Lateral Movement"))
        assert any("Correlated" in r for r in inc.correlation_reasons)


class TestAttackChainEnrichment:
    def test_multi_tactic_sorted_by_killchain(self, engine):
        engine.correlate(_make_alert("h-001", source_ip="10.0.1.1", mitre_tactics=["Credential Access"]))
        inc = engine.correlate(_make_alert("h-002", source_ip="10.0.1.1", mitre_tactics=["Initial Access"]))
        ia_idx = inc.tactics.index("Initial Access")
        ca_idx = inc.tactics.index("Credential Access")
        assert ia_idx < ca_idx

    def test_attack_chain_span_grows(self, engine):
        ip = "10.0.2.2"
        engine.correlate(_make_alert("i-001", source_ip=ip, mitre_tactics=["Execution"]))
        inc = engine.correlate(_make_alert("i-002", source_ip=ip, mitre_tactics=["Persistence"]))
        assert inc.attack_chain_span >= 2

    def test_heuristic_inference_when_no_mitre_metadata(self, engine):
        inc = engine.correlate(_make_alert("j-001", rule_name="SSH Brute Force Detected", source_ip="10.3.3.3"))
        assert "Credential Access" in inc.tactics

    def test_techniques_deduplicated(self, engine):
        ip = "10.4.4.4"
        for i in range(3):
            engine.correlate(_make_alert(
                "k-{:03d}".format(i), source_ip=ip,
                mitre_tactics=["Execution"], mitre_techniques=["T1059 - Command Interpreter"],
            ))
        inc = engine.list_incidents()[0]
        assert inc.techniques.count("T1059 - Command Interpreter") == 1


class TestSeverityFloorDeterminism:
    def test_severity_equals_floor_for_all_levels(self, engine):
        for i, sev in enumerate(["low", "medium", "high", "critical"]):
            inc = engine.correlate(_make_alert("n-{:03d}".format(i), severity=sev, source_ip="10.0.{}.1".format(i)))
            assert inc.severity == inc.deterministic_floor, "floor mismatch for {}".format(sev)

    def test_score_nondecreasing_on_merge(self, engine):
        ip = "10.9.9.9"
        i1 = engine.correlate(_make_alert("o-001", source_ip=ip, severity="high"))
        score1 = i1.deterministic_score
        i2 = engine.correlate(_make_alert("o-002", source_ip=ip, severity="low"))
        assert i2.deterministic_score >= score1


class TestQueryAPI:
    def test_list_incidents(self, engine):
        for i in range(5):
            engine.correlate(_make_alert("p-{:03d}".format(i), source_ip="10.1.{}.1".format(i), host="server-{:03d}".format(i)))
        assert len(engine.list_incidents()) == 5

    def test_get_incident_by_id(self, engine):
        inc = engine.correlate(_make_alert("q-001", source_ip="10.2.0.1"))
        found = engine.get_incident(inc.incident_id)
        assert found and found.incident_id == inc.incident_id

    def test_get_missing_incident_returns_none(self, engine):
        assert engine.get_incident("INC-9999-9999") is None

    def test_filter_by_tactic(self, engine):
        engine.correlate(_make_alert("r-001", source_ip="10.3.0.1", mitre_tactics=["Impact"]))
        engine.correlate(_make_alert("r-002", source_ip="10.3.0.2", mitre_tactics=["Discovery"]))
        results = engine.list_incidents(tactic="Impact")
        assert all("Impact" in inc.tactics for inc in results)

    def test_clear_resets_state(self, engine):
        engine.correlate(_make_alert("s-001"))
        engine.clear()
        assert len(engine.list_incidents()) == 0


class TestIngestionCorrelationIntegration:
    def _fresh_pair(self):
        from backend.correlation.engine import CorrelationEngine as CE
        correlator = CE()
        correlator.clear()
        ingest = IngestionEngine()
        ingest.clear()
        ingest._correlation_engine = correlator
        return ingest, correlator

    def test_ingest_returns_incident_id(self):
        ingest, _ = self._fresh_pair()
        payload = {
            "id": "5000",
            "rule": {"id": "5710", "description": "SSH Auth Failure", "level": 10},
            "agent": {"id": "001", "name": "web-server-01"},
            "data": {"srcip": "203.0.113.100", "dstip": "10.0.0.50"},
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        result = ingest.ingest(payload, explicit_source="wazuh")
        assert result.status == "ingested"
        assert result.incident_id and result.incident_id.startswith("INC-")

    def test_duplicate_does_not_create_new_incident(self):
        ingest, correlator = self._fresh_pair()
        payload = {
            "id": "6000",
            "rule": {"id": "1001", "description": "Port Scan", "level": 8},
            "agent": {"id": "002", "name": "db-server-02"},
            "data": {"srcip": "10.9.8.7"},
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        r1 = ingest.ingest(payload, explicit_source="wazuh")
        r2 = ingest.ingest(payload, explicit_source="wazuh")
        assert r1.status == "ingested" and r2.status == "deduplicated"
        assert r2.incident_id is None
        assert len(correlator.list_incidents()) == 1

    def test_related_alerts_into_one_incident(self):
        ingest, correlator = self._fresh_pair()
        rules = [
            {"id": "5710", "description": "SSH Auth Failure", "level": 10},
            {"id": "5715", "description": "Sudo Command Execution", "level": 11},
            {"id": "5720", "description": "Shadow File Read", "level": 12},
        ]
        for i, rule in enumerate(rules):
            payload = {
                "id": str(9000 + i),
                "rule": rule,
                "agent": {"id": "001", "name": "host-A"},
                "data": {"srcip": "192.0.2.50"},
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            ingest.ingest(payload, explicit_source="wazuh")
        incidents = correlator.list_incidents()
        assert len(incidents) == 1
        assert incidents[0].alert_count == 3
