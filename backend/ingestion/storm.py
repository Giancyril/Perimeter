"""
Alert Storm Suppressor.
Detects and suppresses high-frequency duplicate or near-duplicate alert floods
caused by noisy SIEM rules, thereby reducing analyst fatigue and correlation noise:
- Sliding time-window alert burst counter per rule_id.
- Configurable suppression threshold and cooldown window.
- Suppressed alert tracking with suppression reason and reinstatement logic.
- Storm status reporting per source/rule.
"""
import time
import threading
from typing import Dict, Any, Optional, Tuple
from pydantic import BaseModel, Field


class StormEntry(BaseModel):
    rule_id: str
    source_key: str
    window_start: float
    alert_count: int = 0
    suppressed_count: int = 0
    is_suppressing: bool = False
    suppression_started_at: Optional[float] = None
    last_seen_at: float = Field(default_factory=time.time)


class SuppressionDecision(BaseModel):
    suppressed: bool
    rule_id: str
    source_key: str
    reason: str
    alert_count_in_window: int
    suppressed_count: int


class AlertStormSuppressor:
    """
    Detects rule-level alert storms within a sliding window and activates suppression.
    """

    def __init__(
        self,
        threshold: int = 20,
        window_seconds: int = 60,
        cooldown_seconds: int = 300,
    ):
        self.threshold = threshold
        self.window_seconds = window_seconds
        self.cooldown_seconds = cooldown_seconds
        self._entries: Dict[str, StormEntry] = {}
        self._lock = threading.Lock()

    def _make_key(self, rule_id: str, source_key: str) -> str:
        return f"{source_key}::{rule_id}"

    def check_and_record(
        self,
        rule_id: str,
        source_key: str = "default",
        current_time: Optional[float] = None,
    ) -> SuppressionDecision:
        """
        Records an alert arrival and returns a SuppressionDecision.
        If the alert count in the current window exceeds the threshold, suppression is activated.
        """
        now = current_time if current_time is not None else time.time()
        key = self._make_key(rule_id, source_key)

        with self._lock:
            entry = self._entries.get(key)

            if entry is None or (now - entry.window_start) > self.window_seconds:
                # Start a fresh window
                entry = StormEntry(
                    rule_id=rule_id,
                    source_key=source_key,
                    window_start=now,
                    is_suppressing=False,
                )
                self._entries[key] = entry

            # Check if cooldown has expired
            if (
                entry.is_suppressing
                and entry.suppression_started_at is not None
                and (now - entry.suppression_started_at) > self.cooldown_seconds
            ):
                entry.is_suppressing = False
                entry.suppression_started_at = None
                entry.alert_count = 0
                entry.suppressed_count = 0
                entry.window_start = now

            entry.alert_count += 1
            entry.last_seen_at = now

            if entry.is_suppressing:
                entry.suppressed_count += 1
                return SuppressionDecision(
                    suppressed=True,
                    rule_id=rule_id,
                    source_key=source_key,
                    reason=f"Storm active: {entry.suppressed_count} suppressed in cooldown window",
                    alert_count_in_window=entry.alert_count,
                    suppressed_count=entry.suppressed_count,
                )

            if entry.alert_count > self.threshold:
                entry.is_suppressing = True
                entry.suppression_started_at = now
                entry.suppressed_count += 1
                return SuppressionDecision(
                    suppressed=True,
                    rule_id=rule_id,
                    source_key=source_key,
                    reason=f"Storm threshold exceeded: {entry.alert_count} alerts in {self.window_seconds}s window",
                    alert_count_in_window=entry.alert_count,
                    suppressed_count=entry.suppressed_count,
                )

        return SuppressionDecision(
            suppressed=False,
            rule_id=rule_id,
            source_key=source_key,
            reason="Within normal rate",
            alert_count_in_window=entry.alert_count,
            suppressed_count=entry.suppressed_count,
        )

    def get_active_storms(self) -> Dict[str, Any]:
        with self._lock:
            return {
                k: {
                    "rule_id": v.rule_id,
                    "source_key": v.source_key,
                    "alert_count": v.alert_count,
                    "suppressed_count": v.suppressed_count,
                    "is_suppressing": v.is_suppressing,
                }
                for k, v in self._entries.items()
                if v.is_suppressing
            }

    def reset_rule(self, rule_id: str, source_key: str = "default") -> bool:
        key = self._make_key(rule_id, source_key)
        with self._lock:
            if key in self._entries:
                del self._entries[key]
                return True
        return False


alert_storm_suppressor = AlertStormSuppressor()
