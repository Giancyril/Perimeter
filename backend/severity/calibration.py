"""
Historical Score Calibration & Analyst Feedback Optimization Engine for Severity Engine.

Maintains online score calibration from SOC analyst triage verdicts (True Positive,
False Positive, Overestimated). Computes empirical calibration offsets and
tunes decision thresholds to minimize alert fatigue while maintaining high recall.
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from backend.ingestion.models import SeverityLevel


class AnalystVerdict(str, Enum):
    TRUE_POSITIVE_CONFIRMED = "TRUE_POSITIVE_CONFIRMED"
    FALSE_POSITIVE_NOISE = "FALSE_POSITIVE_NOISE"
    BENIGN_TRUE_POSITIVE = "BENIGN_TRUE_POSITIVE"
    SEVERITY_OVERESTIMATED = "SEVERITY_OVERESTIMATED"
    SEVERITY_UNDERESTIMATED = "SEVERITY_UNDERESTIMATED"


@dataclass
class FeedbackEntry:
    incident_id: str
    model_score: float
    model_severity: SeverityLevel
    verdict: AnalystVerdict
    analyst_id: str
    adjusted_severity: Optional[SeverityLevel] = None
    notes: Optional[str] = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "model_score": round(self.model_score, 2),
            "model_severity": self.model_severity.value,
            "verdict": self.verdict.value,
            "analyst_id": self.analyst_id,
            "adjusted_severity": self.adjusted_severity.value if self.adjusted_severity else None,
            "notes": self.notes,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class CalibrationTelemetry:
    total_feedback: int
    true_positive_rate: float
    false_positive_rate: float
    bias_offset: float
    recommended_critical_threshold: float
    recommended_high_threshold: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_feedback": self.total_feedback,
            "true_positive_rate": round(self.true_positive_rate, 3),
            "false_positive_rate": round(self.false_positive_rate, 3),
            "bias_offset": round(self.bias_offset, 2),
            "recommended_critical_threshold": round(self.recommended_critical_threshold, 1),
            "recommended_high_threshold": round(self.recommended_high_threshold, 1),
        }


class HistoricalScoreCalibrator:
    """Applies empirical feedback offsets to raw severity scores."""

    DEFAULT_CRITICAL_THRESHOLD = 80.0
    DEFAULT_HIGH_THRESHOLD = 60.0

    def __init__(self) -> None:
        self._feedback_log: List[FeedbackEntry] = []

    def record_feedback(
        self,
        incident_id: str,
        model_score: float,
        model_severity: SeverityLevel,
        verdict: AnalystVerdict,
        analyst_id: str,
        adjusted_severity: Optional[SeverityLevel] = None,
        notes: Optional[str] = None,
    ) -> FeedbackEntry:
        """Records ground-truth analyst feedback to inform model calibration."""
        entry = FeedbackEntry(
            incident_id=incident_id,
            model_score=model_score,
            model_severity=model_severity,
            verdict=verdict,
            analyst_id=analyst_id,
            adjusted_severity=adjusted_severity,
            notes=notes,
        )
        self._feedback_log.append(entry)
        return entry

    def calculate_bias_offset(self) -> float:
        """
        Computes score shift based on historical tendency to overestimate or underestimate.
        Negative offset means model overestimates severity (downward correction needed).
        Positive offset means model underestimates severity (upward correction needed).
        """
        if not self._feedback_log:
            return 0.0

        overestimated = sum(
            1 for e in self._feedback_log
            if e.verdict in (AnalystVerdict.SEVERITY_OVERESTIMATED, AnalystVerdict.FALSE_POSITIVE_NOISE)
        )
        underestimated = sum(
            1 for e in self._feedback_log
            if e.verdict == AnalystVerdict.SEVERITY_UNDERESTIMATED
        )
        n = len(self._feedback_log)

        # Net bias (-1.0 to +1.0 scaled to max +/- 12 points)
        net_ratio = (underestimated - overestimated) / n
        return max(-12.0, min(12.0, net_ratio * 15.0))

    def calibrate(self, raw_score: float) -> float:
        """Applies empirical calibration offset to a new raw score."""
        offset = self.calculate_bias_offset()
        calibrated = raw_score + offset
        return min(100.0, max(0.0, calibrated))

    def get_telemetry(self) -> CalibrationTelemetry:
        """Generates statistical overview of analyst triage accuracy and threshold tuning."""
        if not self._feedback_log:
            return CalibrationTelemetry(
                total_feedback=0,
                true_positive_rate=1.0,
                false_positive_rate=0.0,
                bias_offset=0.0,
                recommended_critical_threshold=self.DEFAULT_CRITICAL_THRESHOLD,
                recommended_high_threshold=self.DEFAULT_HIGH_THRESHOLD,
            )

        n = len(self._feedback_log)
        tp_count = sum(
            1 for e in self._feedback_log
            if e.verdict in (AnalystVerdict.TRUE_POSITIVE_CONFIRMED, AnalystVerdict.BENIGN_TRUE_POSITIVE)
        )
        fp_count = sum(
            1 for e in self._feedback_log
            if e.verdict == AnalystVerdict.FALSE_POSITIVE_NOISE
        )

        bias = self.calculate_bias_offset()
        crit_thresh = max(70.0, min(90.0, self.DEFAULT_CRITICAL_THRESHOLD - bias))
        high_thresh = max(50.0, min(75.0, self.DEFAULT_HIGH_THRESHOLD - bias))

        return CalibrationTelemetry(
            total_feedback=n,
            true_positive_rate=tp_count / n,
            false_positive_rate=fp_count / n,
            bias_offset=bias,
            recommended_critical_threshold=crit_thresh,
            recommended_high_threshold=high_thresh,
        )
