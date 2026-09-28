"""
Phase 1 Pytest Suite: Multi-Source Alert Ingestion, Normalization & Deduplication.
Covers Wazuh and Syslog adapters, OCSF/ECS entity extraction, deterministic SHA-256 deduplication,
and REST API webhook endpoints with raw forensic payload retention.
"""
import pytest
from httpx import AsyncClient, ASGITransport
from backend.app.main import app
from backend.ingestion import (
    WazuhAdapter,
    SyslogAdapter,
    SeverityLevel,
    AlertSourceType,
    EntityType,
    EntityRole,
    ingestion_engine,
)

SAMPLE_WAZUH_SSH_ALERT = {
    "id": "1695900000.12345",
    "timestamp": "2026-09-28T13:20:10.000+0000",
    "rule": {
        "id": "5710",
        "level": 10,
        "description": "sshd: Multiple failed login attempts.",
        "mitre": {
            "id": ["T1110.001"],
            "tactic": ["Initial Access"],
            "technique": ["Password Guessing"],
        },
        "groups": ["syslog", "sshd", "authentication_failures"],
    },
    "agent": {
        "id": "001",
        "name": "prod-db-primary-01",
        "ip": "10.0.1.50",
    },
    "data": {
        "srcip": "198.51.100.42",
        "dstuser": "root",
        "srcuser": "svc_deployer",
        "dstport": "22",
        "srcport": "49201",
    },
    "location": "/var/log/auth.log",
}

SAMPLE_WAZUH_SYSCHECK_ALERT = {
    "id": "1695900000.67890",
    "timestamp": "2026-09-28T13:25:00.000+0000",
    "rule": {
        "id": "550",
        "level": 14,
        "description": "Integrity checksum changed for /etc/shadow",
        "mitre": {
            "id": ["T1548"],
            "tactic": ["Privilege Escalation"],
        },
    },
    "agent": {
        "id": "002",
        "name": "prod-api-gw-01",
        "ip": "10.0.1.10",
    },
    "syscheck": {
        "path": "/etc/shadow",
        "md5_after": "d41d8cd98f00b204e9800998ecf8427e",
        "sha256_after": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    },
}

SAMPLE_SYSLOG_ALERT = {
    "source": "syslog",
    "severity": 3,
    "facility": 4,
    "app_name": "sudo",
    "hostname": "wkstn-fin-109",
    "timestamp": "2026-09-28T13:30:00Z",
    "message": "COMMAND=/bin/bash user admin_sec for user root from 10.0.4.15",
}

class TestWazuhAdapter:
    def test_wazuh_can_handle(self):
        adapter = WazuhAdapter()
        assert adapter.can_handle(SAMPLE_WAZUH_SSH_ALERT) is True
        assert adapter.can_handle({"source": "wazuh"}) is True
        assert adapter.can_handle({"random": "payload"}) is False
        assert adapter.can_handle([]) is False

    def test_wazuh_severity_mapping(self):
        adapter = WazuhAdapter()
        assert adapter.map_wazuh_level_to_severity(16) == SeverityLevel.CRITICAL
        assert adapter.map_wazuh_level_to_severity(15) == SeverityLevel.CRITICAL
        assert adapter.map_wazuh_level_to_severity(12) == SeverityLevel.HIGH
        assert adapter.map_wazuh_level_to_severity(10) == SeverityLevel.MEDIUM
        assert adapter.map_wazuh_level_to_severity(8) == SeverityLevel.MEDIUM
        assert adapter.map_wazuh_level_to_severity(5) == SeverityLevel.LOW
        assert adapter.map_wazuh_level_to_severity(2) == SeverityLevel.INFORMATIONAL

    def test_wazuh_normalization_ssh_brute_force(self):
        adapter = WazuhAdapter()
        alert = adapter.normalize(SAMPLE_WAZUH_SSH_ALERT)

        assert alert.alert_id == "1695900000.12345"
        assert alert.source == AlertSourceType.WAZUH
        assert alert.rule_id == "5710"
        assert alert.rule_name == "sshd: Multiple failed login attempts."
        assert alert.normalized_severity == SeverityLevel.MEDIUM
        assert alert.source_ip == "198.51.100.42"
        assert alert.destination_ip == "10.0.1.50"
        assert alert.source_port == 49201
        assert alert.destination_port == 22
        assert alert.host == "prod-db-primary-01"
        assert alert.user == "root"

        # Check entity collection
        entity_types = {e.type: e.value for e in alert.entities}
        assert entity_types[EntityType.IP] in ["198.51.100.42", "10.0.1.50"]
        assert entity_types[EntityType.HOST] == "prod-db-primary-01"
        assert entity_types[EntityType.USER] == "root"

        # Check MITRE ATT&CK
        assert alert.mitre_attack is not None
        assert "Initial Access" in alert.mitre_attack.tactics
        assert "T1110.001" in alert.mitre_attack.techniques

        # Check raw payload retention
        assert alert.raw_payload == SAMPLE_WAZUH_SSH_ALERT

    def test_wazuh_normalization_syscheck_file_integrity(self):
        adapter = WazuhAdapter()
        alert = adapter.normalize(SAMPLE_WAZUH_SYSCHECK_ALERT)

        assert alert.normalized_severity == SeverityLevel.HIGH
        assert alert.file_hash == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assert alert.host == "prod-api-gw-01"
        assert alert.mitre_attack.tactics == ["Privilege Escalation"]

        # Check hash entity
        hash_entities = [e for e in alert.entities if e.type == EntityType.FILE_HASH]
        assert len(hash_entities) == 1
        assert hash_entities[0].details.get("path") == "/etc/shadow"


class TestSyslogAdapter:
    def test_syslog_normalization(self):
        adapter = SyslogAdapter()
        assert adapter.can_handle(SAMPLE_SYSLOG_ALERT) is True

        alert = adapter.normalize(SAMPLE_SYSLOG_ALERT)
        assert alert.source == AlertSourceType.SYSLOG
        assert alert.normalized_severity == SeverityLevel.HIGH
        assert alert.host == "wkstn-fin-109"
        assert alert.source_ip == "10.0.4.15"
        assert alert.process_name == "sudo"
        assert alert.raw_payload == SAMPLE_SYSLOG_ALERT


class TestIngestionEngineDeduplication:
    def setup_method(self):
        ingestion_engine.clear()

    def test_alert_deduplication(self):
        # Ingest first alert
        res1 = ingestion_engine.ingest(SAMPLE_WAZUH_SSH_ALERT)
        assert res1.status == "ingested"
        assert res1.was_duplicate is False
        assert res1.duplicate_count == 1

        # Ingest same alert 4 more times
        for _ in range(4):
            res = ingestion_engine.ingest(SAMPLE_WAZUH_SSH_ALERT)
            assert res.status == "deduplicated"
            assert res.was_duplicate is True

        # Check alert state
        stored_alert = ingestion_engine.get_alert(res1.alert_id)
        assert stored_alert is not None
        assert stored_alert.duplicate_count == 5

        # Check stats
        stats = ingestion_engine.get_stats()
        assert stats["total_unique_alerts"] == 1
        assert stats["total_raw_events"] == 5
        assert stats["deduplication_ratio"] == 0.8

    def test_distinct_alerts_kept_separate(self):
        res1 = ingestion_engine.ingest(SAMPLE_WAZUH_SSH_ALERT)
        res2 = ingestion_engine.ingest(SAMPLE_WAZUH_SYSCHECK_ALERT)

        assert res1.fingerprint != res2.fingerprint
        assert res1.alert_id != res2.alert_id

        alerts = ingestion_engine.list_alerts()
        assert len(alerts) == 2


class TestAlertsApi:
    def setup_method(self):
        ingestion_engine.clear()

    @pytest.mark.asyncio
    async def test_webhook_ingest_wazuh(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            res = await client.post(
                "/api/v1/alerts/webhook/wazuh",
                json=SAMPLE_WAZUH_SSH_ALERT,
            )
            assert res.status_code == 201
            data = res.json()
            assert data["status"] == "ingested"
            assert data["source"] == "wazuh"
            assert data["was_duplicate"] is False
            assert data["duplicate_count"] == 1

            # Ingest duplicate
            res_dup = await client.post(
                "/api/v1/alerts/webhook/wazuh",
                json=SAMPLE_WAZUH_SSH_ALERT,
            )
            assert res_dup.status_code == 201
            data_dup = res_dup.json()
            assert data_dup["status"] == "deduplicated"
            assert data_dup["was_duplicate"] is True
            assert data_dup["duplicate_count"] == 2

    @pytest.mark.asyncio
    async def test_list_alerts_and_filtering(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            await client.post("/api/v1/alerts/webhook/wazuh", json=SAMPLE_WAZUH_SSH_ALERT)
            await client.post("/api/v1/alerts/webhook/wazuh", json=SAMPLE_WAZUH_SYSCHECK_ALERT)

            # List all
            res_all = await client.get("/api/v1/alerts/")
            assert res_all.status_code == 200
            assert res_all.json()["count"] == 2

            # Filter by severity
            res_high = await client.get("/api/v1/alerts/?severity=high")
            assert res_high.status_code == 200
            assert res_high.json()["count"] == 1
            assert res_high.json()["alerts"][0]["rule_id"] == "550"

            # Filter by host
            res_host = await client.get("/api/v1/alerts/?host=prod-db-primary-01")
            assert res_host.status_code == 200
            assert res_host.json()["count"] == 1
            assert res_host.json()["alerts"][0]["host"] == "prod-db-primary-01"

    @pytest.mark.asyncio
    async def test_get_alert_by_id_and_forensics(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            res_post = await client.post("/api/v1/alerts/webhook/wazuh", json=SAMPLE_WAZUH_SSH_ALERT)
            alert_id = res_post.json()["alert_id"]

            res_get = await client.get(f"/api/v1/alerts/{alert_id}")
            assert res_get.status_code == 200
            alert_data = res_get.json()
            assert alert_data["alert_id"] == alert_id
            assert "raw_payload" in alert_data
            assert alert_data["raw_payload"]["location"] == "/var/log/auth.log"

    @pytest.mark.asyncio
    async def test_get_alert_not_found(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            res = await client.get("/api/v1/alerts/nonexistent-id")
            assert res.status_code == 404

    @pytest.mark.asyncio
    async def test_alert_stats(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            await client.post("/api/v1/alerts/webhook/wazuh", json=SAMPLE_WAZUH_SSH_ALERT)
            await client.post("/api/v1/alerts/webhook/wazuh", json=SAMPLE_WAZUH_SSH_ALERT)

            res_stats = await client.get("/api/v1/alerts/stats")
            assert res_stats.status_code == 200
            stats = res_stats.json()
            assert stats["total_unique_alerts"] == 1
            assert stats["total_raw_events"] == 2
            assert stats["deduplication_ratio"] == 0.5
