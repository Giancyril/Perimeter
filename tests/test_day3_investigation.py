"""
Day 3 Advanced Investigation Agent Test Suite.

Comprehensive tests covering all Day 3 investigation modules:
- Multi-modal IOC Extractor
- Attack Hypothesis Engine
- Threat Actor Attribution Profiler
- Dynamic Playbook Router & Approval Gating
- Cryptographic Chain-of-Custody Evidence Tracker
- Contextual Evidence Confidence Scorer
- Multi-Dimensional Alert Deduplicator
- Formal Investigation State Machine
"""
import pytest
from datetime import datetime, timezone, timedelta

from backend.ingestion.models import (
    NormalizedAlert, Entity, EntityType, EntityRole,
    SeverityLevel, AlertSourceType, MitreAttackMetadata, utc_now,
)
from backend.agent.ioc_extractor import IOCExtractor, IOCType, IOCConfidence
from backend.agent.hypothesis import (
    HypothesisEngine, HypothesisCategory, HypothesisStatus, HypothesisConfidence,
)
from backend.agent.attribution import (
    AttributionProfiler, ActorMotivation,
)
from backend.agent.playbook import (
    PlaybookRouter, PlaybookType, StepActionType, StepStatus,
)
from backend.agent.evidence_chain import (
    EvidenceChain, EvidenceType,
)
from backend.agent.context_scorer import (
    ContextScorer, AssetTier, ConfidenceTier,
)
from backend.agent.deduplication import (
    AdvancedDeduplicator, DeduplicationStrategy,
)
from backend.agent.investigation_state import (
    InvestigationStateMachine, InvestigationPhase,
)


def _make_alert(
    alert_id: str,
    rule_name: str,
    description: str = "",
    command_line: str = "",
    techniques: list[str] = None,
    tactics: list[str] = None,
    entities: list[Entity] = None,
    file_hash: str = None,
    source_ip: str = None,
) -> NormalizedAlert:
    techs = techniques or ["T1059"]
    return NormalizedAlert(
        alert_id=alert_id,
        fingerprint=f"fp-{alert_id}",
        source=AlertSourceType.WAZUH,
        rule_id="RULE-101",
        rule_name=rule_name,
        rule_description=description or rule_name,
        raw_severity="high",
        normalized_severity=SeverityLevel.HIGH,
        severity=SeverityLevel.HIGH,
        timestamp=utc_now(),
        file_hash=file_hash,
        source_ip=source_ip,
        raw_payload={"details": description or rule_name, "cmd": command_line},
        mitre_attack=MitreAttackMetadata(
            tactics=tactics or ["execution"],
            techniques=techs,
            technique_names=[f"Tech {t}" for t in techs],
        ),
        entities=entities or [
            Entity(type=EntityType.IP, value="198.51.100.22", role=EntityRole.ACTOR),
            Entity(type=EntityType.HOST, value="FINANCE-SRV01", role=EntityRole.TARGET),
        ],
    )


# ============================================================================
# 1. IOC Extractor Tests
# ============================================================================

class TestIOCExtractor:
    def test_extract_ips_and_domains(self):
        extractor = IOCExtractor()
        alert = _make_alert(
            alert_id="ALT-001",
            rule_name="Outbound C2 Beacon",
            description="Outbound connection to evil-c2-node.com and 198.51.100.55",
            source_ip="198.51.100.55",
        )
        iocs = extractor.extract(alert)
        types = {i["type"] for i in iocs}
        values = {i["value"] for i in iocs}

        assert IOCType.IP_ADDRESS.value in types
        assert "198.51.100.55" in values
        assert IOCType.DOMAIN.value in types
        assert "evil-c2-node.com" in values

    def test_filters_private_and_loopback_ips(self):
        extractor = IOCExtractor()
        alert = _make_alert(
            alert_id="ALT-002",
            rule_name="Local Traffic",
            description="Loopback traffic observed",
            entities=[
                Entity(type=EntityType.IP, value="127.0.0.1", role=EntityRole.ACTOR),
                Entity(type=EntityType.IP, value="0.0.0.0", role=EntityRole.ACTOR),
                Entity(type=EntityType.IP, value="203.0.113.195", role=EntityRole.ACTOR),
            ],
        )
        iocs = extractor.extract(alert)
        values = {i["value"] for i in iocs}

        assert "203.0.113.195" in values
        assert "127.0.0.1" not in values
        assert "0.0.0.0" not in values

    def test_extract_hashes_and_cves(self):
        extractor = IOCExtractor()
        alert = _make_alert(
            alert_id="ALT-003",
            rule_name="CVE-2023-34362 MOVEit Transfer Exploit",
            description="Exploit matched payload e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            file_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        )
        iocs = extractor.extract(alert)
        types = {i["type"] for i in iocs}

        assert IOCType.FILE_HASH_SHA256.value in types
        assert IOCType.CVE.value in types

    def test_batch_extraction(self):
        extractor = IOCExtractor()
        alerts = [
            _make_alert(f"ALT-B{i}", f"Rule {i}", description=f"Host beacon to node{i}.bad.org")
            for i in range(3)
        ]
        batch_results = extractor.extract_batch(alerts)
        assert len(batch_results) == 3
        for res in batch_results.values():
            assert any(ioc["type"] == IOCType.DOMAIN.value for ioc in res)


# ============================================================================
# 2. Hypothesis Engine Tests
# ============================================================================

class TestHypothesisEngine:
    def test_generates_ransomware_hypothesis(self):
        engine = HypothesisEngine()
        alerts = [
            _make_alert(
                alert_id="ALT-R1",
                rule_name="Volume Shadow Copy Deletion",
                command_line="vssadmin delete shadows /all /quiet",
                techniques=["T1490"],
            ),
            _make_alert(
                alert_id="ALT-R2",
                rule_name="Mass File Encryption Detected",
                description="High velocity bitlocker / ransom activity",
                techniques=["T1486"],
            ),
        ]
        hyps = engine.generate(alerts)
        assert len(hyps) > 0
        top = hyps[0]
        assert top.category == HypothesisCategory.RANSOMWARE_DEPLOYMENT
        assert top.confidence >= 0.85
        assert top.confidence_level in (HypothesisConfidence.HIGH, HypothesisConfidence.VERY_HIGH)

    def test_generates_credential_theft_hypothesis(self):
        engine = HypothesisEngine()
        alerts = [
            _make_alert(
                alert_id="ALT-C1",
                rule_name="LSASS Memory Dumping",
                command_line="procdump.exe -ma lsass.exe lsass.dmp",
                techniques=["T1003.001"],
            )
        ]
        hyps = engine.generate(alerts)
        assert any(h.category == HypothesisCategory.CREDENTIAL_THEFT for h in hyps)

    def test_evaluate_evidence_supporting_and_refuting(self):
        engine = HypothesisEngine()
        alerts = [_make_alert("ALT-1", "Suspicious Process", command_line="mimikatz")]
        hyp = engine.generate(alerts)[0]
        initial_score = hyp.confidence

        # Add supporting evidence
        engine.evaluate_evidence(hyp, "Sysmon Event 10 confirmed memory handle access", supports=True)
        assert hyp.confidence > initial_score
        assert len(hyp.supporting_evidence) >= 2

        # Add refuting evidence
        engine.evaluate_evidence(hyp, "Hash confirmed to match approved sysadmin diagnostic utility", supports=False)
        assert hyp.confidence < initial_score + 0.10
        assert len(hyp.refuting_evidence) == 1


# ============================================================================
# 3. Attribution Profiler Tests
# ============================================================================

class TestAttributionProfiler:
    def test_attributes_apt28_from_ttps_and_tools(self):
        profiler = AttributionProfiler()
        matches = profiler.profile(
            techniques=["T1566.001", "T1059.001", "T1003", "T1071.001"],
            tools=["Mimikatz", "X-Agent"],
        )
        assert len(matches) > 0
        top = matches[0]
        assert top.actor_name == "APT28"
        assert top.motivation == ActorMotivation.ESPIONAGE.value
        assert top.similarity_score >= 0.60

    def test_attributes_lockbit_ransomware(self):
        profiler = AttributionProfiler()
        matches = profiler.profile(
            techniques=["T1486", "T1490", "T1003"],
            tools=["StealBit", "LockBit Black Builder"],
        )
        assert len(matches) > 0
        assert any(m.actor_name == "LockBit" for m in matches)

    def test_lookup_actor_by_alias(self):
        profiler = AttributionProfiler()
        actor = profiler.get_actor("Fancy Bear")
        assert actor is not None
        assert actor.name == "APT28"

        actor2 = profiler.get_actor("Cozy Bear")
        assert actor2 is not None
        assert actor2.name == "APT29"


# ============================================================================
# 4. Playbook Router Tests
# ============================================================================

class TestPlaybookRouter:
    def test_routes_ransomware_playbook(self):
        router = PlaybookRouter()
        alerts = [_make_alert("A1", "Ransomware encryption activity", description="vssadmin delete shadows")]
        pb = router.route(alerts, hypothesis_category="RANSOMWARE_DEPLOYMENT")

        assert pb.playbook_type == PlaybookType.RANSOMWARE_CONTAINMENT
        assert pb.priority == "P1_CRITICAL"
        assert len(pb.steps) >= 4

    def test_requires_human_approval_for_host_isolation(self):
        router = PlaybookRouter()
        alerts = [_make_alert("A1", "Ransomware detected")]
        pb = router.route(alerts, hypothesis_category="RANSOMWARE_DEPLOYMENT")

        # Step 2: Endpoint Isolation requires approval
        step2 = pb.steps[1]
        assert step2.action_type == StepActionType.ENDPOINT_ISOLATION
        assert step2.requires_human_approval is True

        # Attempting advance without approval halts at AWAITING_APPROVAL
        router.advance_step(pb, step_number=2, output="Isolation initiated", approved=False)
        assert step2.status == StepStatus.AWAITING_APPROVAL

        # With approval, step completes
        router.advance_step(pb, step_number=2, output="Host successfully disconnected from LAN", approved=True)
        assert step2.status == StepStatus.COMPLETED


# ============================================================================
# 5. Evidence Chain Tests
# ============================================================================

class TestEvidenceChain:
    def test_records_evidence_with_cryptographic_hashes(self):
        chain = EvidenceChain(incident_id="INC-999")
        item1 = chain.record(
            evidence_type=EvidenceType.RAW_ALERT,
            source="wazuh",
            description="Ingested initial detection",
            raw_data={"alert_id": "ALT-1", "severity": "HIGH"},
        )
        assert chain.total_evidence_count == 1
        assert item1.prev_hash == EvidenceChain.GENESIS_HASH
        assert len(item1.sha256_hash) == 64

        item2 = chain.record(
            evidence_type=EvidenceType.THREAT_INTEL_REPORT,
            source="abuseipdb",
            description="Abuse score 100% confirmed",
            raw_data={"ip": "198.51.100.5", "confidence": 100},
        )
        assert chain.total_evidence_count == 2
        assert item2.prev_hash == item1.sha256_hash
        assert chain.verify_integrity() is True

    def test_tamper_detection(self):
        chain = EvidenceChain(incident_id="INC-1000")
        chain.record(EvidenceType.RAW_ALERT, "wazuh", "Legitimate log", {"data": "authentic"})
        chain.record(EvidenceType.ENDPOINT_LOG, "sysmon", "Process exec", {"cmd": "whoami"})

        assert chain.verify_integrity() is True

        # Tamper with an item
        chain._items[0].raw_data = {"data": "TAMPERED_BY_ADVERSARY"}
        assert chain.verify_integrity() is False

    def test_export_manifest(self):
        chain = EvidenceChain(incident_id="INC-1001")
        chain.record(EvidenceType.RAW_ALERT, "wazuh", "Alert 1", {"k": "v"})
        manifest = chain.export_audit_manifest()

        assert manifest["incident_id"] == "INC-1001"
        assert manifest["total_items"] == 1
        assert manifest["chain_valid"] is True


# ============================================================================
# 6. Context Scorer Tests
# ============================================================================

class TestContextScorer:
    def test_crown_jewel_and_admin_scores_high(self):
        scorer = ContextScorer()
        scored = scorer.score(
            evidence_id="EV-1",
            asset_tier=AssetTier.TIER_0_CROWN_JEWEL,
            privilege_level="DOMAIN ADMIN",
            abuse_confidence_score=95,
            vt_positives=45,
            corroborating_source_count=3,
        )
        assert scored.context_score >= 80.0
        assert scored.tier == ConfidenceTier.CRITICAL

    def test_sandbox_and_standard_user_scores_low(self):
        scorer = ContextScorer()
        scored = scorer.score(
            evidence_id="EV-2",
            asset_tier=AssetTier.TIER_3_SANDBOX,
            privilege_level="USER",
            abuse_confidence_score=10,
            corroborating_source_count=1,
            age_in_hours=72.0,
        )
        assert scored.context_score < 45.0
        assert scored.tier in (ConfidenceTier.LOW, ConfidenceTier.INFORMATIONAL)


# ============================================================================
# 7. Deduplication Tests
# ============================================================================

class TestAdvancedDeduplicator:
    def test_aggregates_identical_semantic_alerts(self):
        dedup = AdvancedDeduplicator(time_window_seconds=300)
        t0 = datetime.now(timezone.utc)
        alerts = [
            _make_alert(f"ALT-{i}", "Port Scan Observed")
            for i in range(5)
        ]
        for i, a in enumerate(alerts):
            a.timestamp = (t0 + timedelta(seconds=i * 10)).isoformat()

        clusters = dedup.batch_process(alerts)
        assert len(clusters) == 1
        cluster = clusters[0]
        assert cluster.total_occurrences == 5
        assert cluster.compression_ratio == 0.8
        assert len(cluster.source_alert_ids) == 5

        telemetry = dedup.get_telemetry()
        assert telemetry["total_ingested"] == 5
        assert telemetry["unique_clusters"] == 1
        assert telemetry["suppressed_duplicates"] == 4


# ============================================================================
# 8. Investigation State Machine Tests
# ============================================================================

class TestInvestigationStateMachine:
    def test_lifecycle_transitions(self):
        sm = InvestigationStateMachine(investigation_id="INV-001")
        assert sm.current_phase == InvestigationPhase.INITIALIZED
        assert not sm.is_terminal

        sm.transition(InvestigationPhase.TRIAGING, "Alert ingested from Wazuh")
        assert sm.current_phase == InvestigationPhase.TRIAGING

        sm.transition(InvestigationPhase.HYPOTHESIZING, "Correlated entities detected")
        assert sm.current_phase == InvestigationPhase.HYPOTHESIZING

        sm.transition(InvestigationPhase.ENRICHING_INTEL, "Querying AbuseIPDB & VT")
        sm.transition(InvestigationPhase.VERIFYING_EVIDENCE, "Corroborating process ancestry")
        sm.transition(InvestigationPhase.SYNTHESIZING_REPORT, "Evidence corroborated")
        sm.transition(InvestigationPhase.COMPLETED, "Final report dispatched to SOC")

        assert sm.current_phase == InvestigationPhase.COMPLETED
        assert sm.is_terminal
        assert len(sm.history) == 6

    def test_blocks_illegal_transitions(self):
        sm = InvestigationStateMachine(investigation_id="INV-002")
        with pytest.raises(ValueError):
            sm.transition(InvestigationPhase.COMPLETED, "Premature closure")

    def test_serialization_and_deserialization(self):
        sm = InvestigationStateMachine(investigation_id="INV-003")
        sm.transition(InvestigationPhase.TRIAGING, "Initial review")
        sm.transition(InvestigationPhase.HYPOTHESIZING, "Forming hypothesis")

        serialized = sm.to_dict()
        restored = InvestigationStateMachine.from_dict(serialized)

        assert restored.investigation_id == sm.investigation_id
        assert restored.current_phase == InvestigationPhase.HYPOTHESIZING
        assert len(restored.history) == 2
