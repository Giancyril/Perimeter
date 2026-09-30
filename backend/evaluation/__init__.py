"""
Evaluation, Adversarial Testing, and Failure Mode Verification Package.
Phase 8: Autonomous Security Operations Agent.
"""
from backend.evaluation.models import (
    BenchmarkScenario,
    EvaluationMetrics,
    ScenarioResult,
    AdversarialTestResult,
    FailureModeResult,
)
from backend.evaluation.dataset import BENCHMARK_SCENARIOS

__all__ = [
    "BenchmarkScenario",
    "EvaluationMetrics",
    "ScenarioResult",
    "AdversarialTestResult",
    "FailureModeResult",
    "BENCHMARK_SCENARIOS",
]
