"""
Dynamic Temporal Sliding Window & Alert Velocity Tracker.
Calculates time-decay correlation weights, alert acceleration velocity,
and dynamically adjusts window sizes for burst vs low-and-slow attack campaigns.
"""
from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime, timezone
import math
from backend.ingestion.models import NormalizedAlert

class TemporalWindowTracker:
    """Tracks time windows, decay factors, and alert velocity for correlated incident clusters."""

    def __init__(
        self,
        base_window_seconds: int = 1800,
        decay_half_life_seconds: float = 600.0,
        velocity_threshold_rpm: float = 10.0,
    ):
        self.base_window_seconds = base_window_seconds
        self.decay_half_life = decay_half_life_seconds
        self.decay_lambda = math.log(2) / decay_half_life_seconds if decay_half_life_seconds > 0 else 0.001
        self.velocity_threshold_rpm = velocity_threshold_rpm

    def _parse_ts(self, ts: str) -> datetime:
        try:
            return datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except Exception:
            return datetime.now(timezone.utc)

    def calculate_decay_weight(self, alert_time: str, reference_time: Optional[str] = None) -> float:
        """
        Calculates exponential time-decay weight (0.0 to 1.0) for an alert relative to reference_time.
        Weight = exp(-lambda * delta_seconds).
        """
        t_alert = self._parse_ts(alert_time)
        t_ref = self._parse_ts(reference_time) if reference_time else datetime.now(timezone.utc)
        delta_sec = max(0.0, (t_ref - t_alert).total_seconds())
        return round(math.exp(-self.decay_lambda * delta_sec), 4)

    def calculate_weighted_score(self, alerts: List[NormalizedAlert], reference_time: Optional[str] = None) -> float:
        """Calculates total weighted alert score accounting for temporal decay."""
        if not alerts:
            return 0.0
        weights = [self.calculate_decay_weight(a.timestamp, reference_time) for a in alerts]
        return round(sum(weights), 3)

    def calculate_alert_velocity(self, alerts: List[NormalizedAlert]) -> Dict[str, Any]:
        """
        Calculates alert velocity (rate per minute) and acceleration over the span of the alerts.
        """
        if len(alerts) < 2:
            return {
                "rate_per_minute": 0.0,
                "is_burst": False,
                "duration_seconds": 0.0,
                "acceleration": 0.0,
            }

        sorted_alerts = sorted(alerts, key=lambda a: self._parse_ts(a.timestamp))
        t_start = self._parse_ts(sorted_alerts[0].timestamp)
        t_end = self._parse_ts(sorted_alerts[-1].timestamp)
        duration_sec = max(1.0, (t_end - t_start).total_seconds())
        duration_min = duration_sec / 60.0

        rate_rpm = round(len(alerts) / duration_min, 2)
        is_burst = rate_rpm >= self.velocity_threshold_rpm

        # Acceleration: velocity in 2nd half minus velocity in 1st half
        mid_idx = len(sorted_alerts) // 2
        first_half = sorted_alerts[:mid_idx]
        second_half = sorted_alerts[mid_idx:]

        t_mid = self._parse_ts(sorted_alerts[mid_idx].timestamp)
        dur_1 = max(1.0, (t_mid - t_start).total_seconds()) / 60.0
        dur_2 = max(1.0, (t_end - t_mid).total_seconds()) / 60.0

        v1 = len(first_half) / dur_1
        v2 = len(second_half) / dur_2
        acceleration = round(v2 - v1, 2)

        return {
            "rate_per_minute": rate_rpm,
            "is_burst": is_burst,
            "duration_seconds": round(duration_sec, 1),
            "acceleration": acceleration,
        }

    def compute_adaptive_window(self, alerts: List[NormalizedAlert]) -> int:
        """
        Dynamically adjusts correlation window:
        - If high burst / storm detected, shortens window to prevent over-clustering.
        - If slow-and-low tactic progression detected (e.g. reconnaissance over hours),
          expands window up to 2x base window.
        """
        if not alerts:
            return self.base_window_seconds

        velocity = self.calculate_alert_velocity(alerts)
        if velocity["is_burst"]:
            # High velocity: contract window to focus on the immediate incident storm
            return max(300, int(self.base_window_seconds * 0.5))

        # Check unique tactics span: if multiple tactics are present over long duration, expand
        tactics = {t for a in alerts for t in (a.mitre_attack.tactics if a.mitre_attack else [])}
        if len(tactics) >= 3 and velocity["duration_seconds"] > 900:
            # Multi-stage attack unfolding slowly: expand window up to 2x
            return int(self.base_window_seconds * 2.0)

        return self.base_window_seconds
