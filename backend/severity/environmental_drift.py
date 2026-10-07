"""
Environmental Drift & Temporal Sensitivity Compensator for Severity Engine.

Calculates temporal risk multipliers and environmental sensitivity adjustments:
- Off-hours / weekend / holiday threat activity multiplier (+15% to +35%)
- Change-freeze period multiplier (+25%)
- Scheduled maintenance window dampening (-30%)
- Endpoint configuration drift tracking.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, time, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


class TimeContext(str, Enum):
    BUSINESS_HOURS = "BUSINESS_HOURS"
    AFTER_HOURS = "AFTER_HOURS"
    WEEKEND = "WEEKEND"
    COMPANY_HOLIDAY = "COMPANY_HOLIDAY"
    MAINTENANCE_WINDOW = "MAINTENANCE_WINDOW"


@dataclass
class DriftAdjustmentResult:
    original_score: float
    adjusted_score: float
    drift_multiplier: float
    time_context: TimeContext
    is_change_freeze: bool = False
    adjustment_reasons: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "original_score": round(self.original_score, 2),
            "adjusted_score": round(self.adjusted_score, 2),
            "drift_multiplier": round(self.drift_multiplier, 3),
            "time_context": self.time_context.value,
            "is_change_freeze": self.is_change_freeze,
            "adjustment_reasons": self.adjustment_reasons,
        }


class EnvironmentalDriftCompensator:
    """Adjusts incident scores according to temporal environment and operational status."""

    BUSINESS_START = time(8, 0)   # 08:00
    BUSINESS_END = time(18, 0)    # 18:00

    def __init__(self, holidays: Optional[List[str]] = None) -> None:
        # Holidays in 'YYYY-MM-DD' format
        self.holidays = set(holidays or [])

    def _determine_time_context(
        self,
        dt: datetime,
        in_maintenance: bool = False,
    ) -> TimeContext:
        if in_maintenance:
            return TimeContext.MAINTENANCE_WINDOW

        date_str = dt.strftime("%Y-%m-%d")
        if date_str in self.holidays:
            return TimeContext.COMPANY_HOLIDAY

        # 5 = Saturday, 6 = Sunday
        if dt.weekday() >= 5:
            return TimeContext.WEEKEND

        t = dt.time()
        if self.BUSINESS_START <= t <= self.BUSINESS_END:
            return TimeContext.BUSINESS_HOURS
        return TimeContext.AFTER_HOURS

    def evaluate(
        self,
        base_score: float,
        timestamp: Optional[datetime] = None,
        in_maintenance: bool = False,
        change_freeze_active: bool = False,
        config_drift_score: float = 0.0,  # 0.0 to 1.0 (drift from golden image)
    ) -> DriftAdjustmentResult:
        """Computes environmental sensitivity multipliers and explains rationale."""
        dt = timestamp or datetime.now(timezone.utc)
        context = self._determine_time_context(dt, in_maintenance)

        multiplier = 1.0
        reasons: List[str] = []

        if context == TimeContext.MAINTENANCE_WINDOW:
            multiplier *= 0.70  # Expected operational volatility
            reasons.append("Active scheduled maintenance window dampens severity by 30%")
        elif context == TimeContext.COMPANY_HOLIDAY:
            multiplier *= 1.35  # Reduced SOC staffing, high adversary preference
            reasons.append("Activity on observed holiday increases risk by +35%")
        elif context == TimeContext.WEEKEND:
            multiplier *= 1.25  # Reduced off-hours engineering presence
            reasons.append("Weekend off-hours activity increases risk by +25%")
        elif context == TimeContext.AFTER_HOURS:
            multiplier *= 1.15  # Outside normal working hours
            reasons.append("After-hours activity increases risk by +15%")

        if change_freeze_active:
            multiplier *= 1.25
            reasons.append("Active change-freeze policy violation increases risk by +25%")

        if config_drift_score > 0.5:
            drift_bonus = 1.0 + (config_drift_score * 0.15)
            multiplier *= drift_bonus
            reasons.append(f"Significant host configuration drift ({round(config_drift_score, 2)}) applies +{round((drift_bonus-1.0)*100)}% penalty")

        # Clamp multiplier between 0.5x and 2.0x
        final_multiplier = min(2.0, max(0.5, multiplier))
        adjusted = min(100.0, max(0.0, base_score * final_multiplier))

        return DriftAdjustmentResult(
            original_score=base_score,
            adjusted_score=adjusted,
            drift_multiplier=final_multiplier,
            time_context=context,
            is_change_freeze=change_freeze_active,
            adjustment_reasons=reasons,
        )
