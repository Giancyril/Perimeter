"""
Pydantic Data Models for Evaluation, Adversarial Testing, and Failure Modes.
"""
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
from backend.ingestion.models import SeverityLevel
from backend.response.models import ActionType


class BenchmarkScenario(BaseModel):
    """Defines an end-to-end benchmark attack or benign operational scenario."""
    scenario_id: str
    name: str
    description: str
    is_malicious: bool
    alerts: List[Dict[str, Any]]
    expected_min_severity: SeverityLevel
    expected_tactics: List[str] = Field(default_factory=list)
    expected_techniques: List[str] = Field(default_factory=list)
    expected_action_type: Optional[ActionType] = None
    expected_containment_target: Optional[str] = None
    is_adversarial: bool = False
    adversarial_vector: Optional[str] = None


class ScenarioResult(BaseModel):
    """Result of running a benchmark scenario through the full SOC agent pipeline."""
    scenario_id: str
    scenario_name: str
    passed: bool
    is_malicious: bool
    detected_severity: SeverityLevel
    expected_min_severity: SeverityLevel
    severity_floor_preserved: bool
    detected_tactics: List[str]
    matched_expected_tactics: bool
    proposed_action: Optional[str] = None
    action_matched: bool
    latency_ms: float
    details: str = ""


class AdversarialTestResult(BaseModel):
    """Result of evaluating a prompt injection attack against SIEM log inputs."""
    vector_id: str
    vector_name: str
    injection_payload: str
    target_field: str
    injection_detected: bool
    injection_neutralized: bool
    severity_downgrade_prevented: bool
    final_severity: SeverityLevel
    deterministic_floor: SeverityLevel
    passed: bool
    notes: str = ""


class FailureModeResult(BaseModel):
    """Result of evaluating agent behavior under infrastructure/API outage conditions."""
    mode_name: str
    component: str
    simulated_failure: str
    graceful_degradation: bool
    deterministic_fallback_worked: bool
    no_unhandled_crash: bool
    passed: bool
    audit_message: str = ""


class EvaluationMetrics(BaseModel):
    """Overall benchmark evaluation metrics."""
    total_scenarios: int
    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int
    precision: float
    recall: float
    f1_score: float
    invariant_preservation_rate: float
    prompt_injection_defense_rate: float
    failure_resilience_rate: float
    avg_triage_latency_ms: float
