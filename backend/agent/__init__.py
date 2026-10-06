"""
Investigation Agent package.

Integrates LangGraph-based dynamic investigation, multi-modal IOC extraction,
attack hypothesis formulation, threat actor attribution, automated playbooks,
cryptographic chain-of-custody tracking, contextual evidence confidence scoring,
multi-dimensional alert deduplication, and formal lifecycle state transitions.
"""

from backend.agent.graph import (
    investigate_incident,
    build_investigation_graph,
    InvestigationState,
)
from backend.agent.ioc_extractor import (
    IOCExtractor,
    IOCType,
    IOCConfidence,
    ExtractedIOC,
)
from backend.agent.hypothesis import (
    HypothesisEngine,
    AttackHypothesis,
    HypothesisCategory,
    HypothesisStatus,
    HypothesisConfidence,
)
from backend.agent.attribution import (
    AttributionProfiler,
    ThreatActorProfile,
    AttributionMatch,
    ActorMotivation,
)
from backend.agent.playbook import (
    PlaybookRouter,
    InvestigationPlaybook,
    PlaybookStep,
    PlaybookType,
    StepActionType,
    StepStatus,
)
from backend.agent.evidence_chain import (
    EvidenceChain,
    EvidenceItem,
    EvidenceType,
)
from backend.agent.context_scorer import (
    ContextScorer,
    ScoredEvidence,
    AssetTier,
    ConfidenceTier,
)
from backend.agent.deduplication import (
    AdvancedDeduplicator,
    DeduplicatedAlertCluster,
    DeduplicationStrategy,
)
from backend.agent.investigation_state import (
    InvestigationStateMachine,
    InvestigationPhase,
    StateTransitionRecord,
)

__all__ = [
    # Graph & State
    "investigate_incident",
    "build_investigation_graph",
    "InvestigationState",
    # Day 3 Modules
    "IOCExtractor",
    "IOCType",
    "IOCConfidence",
    "ExtractedIOC",
    "HypothesisEngine",
    "AttackHypothesis",
    "HypothesisCategory",
    "HypothesisStatus",
    "HypothesisConfidence",
    "AttributionProfiler",
    "ThreatActorProfile",
    "AttributionMatch",
    "ActorMotivation",
    "PlaybookRouter",
    "InvestigationPlaybook",
    "PlaybookStep",
    "PlaybookType",
    "StepActionType",
    "StepStatus",
    "EvidenceChain",
    "EvidenceItem",
    "EvidenceType",
    "ContextScorer",
    "ScoredEvidence",
    "AssetTier",
    "ConfidenceTier",
    "AdvancedDeduplicator",
    "DeduplicatedAlertCluster",
    "DeduplicationStrategy",
    "InvestigationStateMachine",
    "InvestigationPhase",
    "StateTransitionRecord",
]
