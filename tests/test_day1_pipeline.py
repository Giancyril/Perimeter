"""
Day 1 Advanced Ingestion Pipeline Integration Test Suite.
Validates all 10 core Day 1 capabilities.
"""
import pytest
import time
from httpx import AsyncClient, ASGITransport
from backend.app.main import app
from backend.ingestion.security import WebhookSecurityManager
from backend.ingestion.ocsf import OcsfValidator, OcsfClass
from backend.ingestion.network import NetworkClassifier, IpScope
from backend.ingestion.rate_limiter import IngestionRateLimiter
from backend.ingestion.dlq import DeadLetterQueue, DlqFailureReason
from backend.ingestion.storm import AlertStormSuppressor
from backend.ingestion.adapters.splunk import SplunkAdapter
from backend.ingestion.adapters.elastic import ElasticAdapter
from backend.ingestion.telemetry import IngestionTelemetry
from backend.ingestion.models import AlertSourceType, SeverityLevel


class TestDay1HMACSecurity:
    def test_hmac_signing_and_verification(self):
        manager = WebhookSecurityManager(primary_secret="test_secret_123")
        payload = b'{"alert": "test", "severity": "high"}'
        sig_header, ts = manager.sign_payload(payload)

        valid, msg = manager.verify_signature(payload, sig_header)
        assert valid is True

        tampered = b'{"alert": "tampered", "severity": "high"}'
        valid_tampered, _ = manager.verify_signature(tampered, sig_header)
        assert valid_tampered is False

    def test_secret_rotation_fallback(self):
        primary_secret = "new_active_secret"
        retired_secret = "retired_secret_key"
        manager = WebhookSecurityManager(
            primary_secret=primary_secret,
            fallback_secrets=[retired_secret],
        )
        old_signer = WebhookSecurityManager(primary_secret=retired_secret)
        payload = b'{"data": "test"}'
        old_sig, _ = old_signer.sign_payload(payload)

        valid, _ = manager.verify_signature(payload, old_sig)
        assert valid is True


class TestDay1OCSFValidation:
    def test_ocsf_classification_mapping(self):
        cls_uid = OcsfValidator.infer_class_uid({"rule_name": "SSH brute force authentication failed"})
        assert cls_uid == OcsfClass.AUTHENTICATION

    def test_ocsf_schema_conformance(self):
        valid_ocsf = {
            "activity_id": 1,
            "category_uid": 2,
            "class_uid": 2001,
            "severity_id": 4,
            "time": int(time.time()),
            "rule_name": "SSH brute force attempt detected",
        }
        res = OcsfValidator.validate_and_conform(valid_ocsf)
        assert res.is_valid is True
        assert res.class_uid == 2001


class TestDay1NetworkClassification:
    def test_rfc1918_private_ip(self):
        assert NetworkClassifier.classify_ip("10.0.0.1").scope == IpScope.PRIVATE
        assert NetworkClassifier.classify_ip("192.168.1.100").scope == IpScope.PRIVATE
        assert NetworkClassifier.classify_ip("172.16.50.2").scope == IpScope.PRIVATE

    def test_public_and_loopback(self):
        assert NetworkClassifier.classify_ip("127.0.0.1").scope == IpScope.LOOPBACK
        assert NetworkClassifier.classify_ip("8.8.8.8").scope == IpScope.PUBLIC


class TestDay1RateLimiting:
    def test_token_bucket_exhaustion(self):
        limiter = IngestionRateLimiter(default_capacity=2.0, default_refill_rate=0.01)
        source = "test-sensor-01"

        st1 = limiter.check_rate_limit(source)
        assert st1.allowed is True
        st2 = limiter.check_rate_limit(source)
        assert st2.allowed is True

        st3 = limiter.check_rate_limit(source)
        assert st3.allowed is False
        assert st3.retry_after_seconds > 0


class TestDay1DeadLetterQueue:
    def test_dlq_capture_and_replay(self):
        dlq = DeadLetterQueue(max_size=10)
        entry = dlq.enqueue(
            payload={"corrupted": True},
            source_key="splunk",
            failure_reason=DlqFailureReason.NORMALIZATION_ERROR,
            failure_detail="Missing timestamp",
        )
        assert entry.source_key == "splunk"
        stats = dlq.get_stats()
        assert stats["total_entries"] == 1

        replayed = dlq.replay(entry.entry_id)
        assert replayed == {"corrupted": True}


class TestDay1StormSuppressor:
    def test_storm_suppression_and_cooldown(self):
        suppressor = AlertStormSuppressor(threshold=3, window_seconds=10, cooldown_seconds=2)
        rule_id = "brute_force"
        source_key = "host01"

        assert suppressor.check_and_record(rule_id, source_key).suppressed is False
        assert suppressor.check_and_record(rule_id, source_key).suppressed is False
        assert suppressor.check_and_record(rule_id, source_key).suppressed is False

        decision = suppressor.check_and_record(rule_id, source_key)
        assert decision.suppressed is True


class TestDay1SiemAdapters:
    def test_splunk_hec_adapter(self):
        adapter = SplunkAdapter()
        payload = {
            "event": {
                "search_name": "Suspicious PowerShell Execution",
                "urgency": "high",
                "src_ip": "192.168.1.50",
                "dest_ip": "10.0.0.5",
                "user": "admin",
                "host": "fin-srv-01",
            },
            "source": "splunk-hec",
            "sourcetype": "stash",
        }
        assert adapter.can_handle(payload) is True
        alert = adapter.normalize(payload)
        assert alert.source == AlertSourceType.SPLUNK
        assert alert.normalized_severity == SeverityLevel.HIGH
        assert alert.source_ip == "192.168.1.50"
        assert alert.host == "fin-srv-01"

    def test_elastic_ecs_adapter(self):
        adapter = ElasticAdapter()
        payload = {
            "@timestamp": "2026-10-01T10:00:00Z",
            "rule": {
                "id": "elastic-rule-101",
                "name": "Persistence via Scheduled Task",
                "severity": "critical",
                "threat": [{
                    "tactic": {"id": "TA0003"},
                    "technique": [{"id": "T1053"}],
                }],
            },
            "source": {"ip": "172.16.0.4"},
            "host": {"hostname": "dc-master"},
            "user": {"name": "svc_backup"},
        }
        assert adapter.can_handle(payload) is True
        alert = adapter.normalize(payload)
        assert alert.source == AlertSourceType.ELASTIC
        assert alert.normalized_severity == SeverityLevel.CRITICAL
        assert alert.source_ip == "172.16.0.4"
        assert "T1053" in alert.mitre_attack.techniques


class TestDay1Telemetry:
    def test_telemetry_metrics_tracking(self):
        tel = IngestionTelemetry()
        tel.record_received("splunk")
        tel.record_normalized("high", latency_ms=1.5)
        tel.record_rate_limited()
        tel.record_storm_suppressed()

        snap = tel.get_snapshot()
        assert snap["counters"]["total_received"] == 1
        assert snap["counters"]["total_normalized"] == 1
        assert snap["counters"]["total_rate_limited"] == 1
        assert snap["counters"]["total_storm_suppressed"] == 1
        assert snap["by_source"]["splunk"] == 1


class TestDay1ApiEndpoints:
    @pytest.mark.asyncio
    async def test_telemetry_endpoint(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            resp = await ac.get("/api/v1/alerts/telemetry")
            assert resp.status_code == 200
            data = resp.json()
            assert "counters" in data
            assert "throughput_events_per_sec" in data

    @pytest.mark.asyncio
    async def test_dlq_endpoint(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            resp = await ac.get("/api/v1/alerts/dlq")
            assert resp.status_code == 200
            data = resp.json()
            assert "dlq_size" in data
            assert "entries" in data
