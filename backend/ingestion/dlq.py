"""
Dead-Letter Queue (DLQ) with Replay Support.
Captures alerts that fail ingestion normalization, deduplication, or schema validation,
preserving them for forensic review and deterministic replay:
- Thread-safe bounded ring-buffer storage with configurable max size.
- Per-entry failure reason, original payload, retry attempt count.
- Replay capability: re-ingest failed entries into the live ingestion pipeline.
- Expiry: entries older than max_age_seconds are pruned automatically.
"""
import time
import threading
import uuid
from typing import Dict, Any, List, Optional
from enum import Enum
from pydantic import BaseModel, Field


class DlqFailureReason(str, Enum):
    NORMALIZATION_ERROR = "normalization_error"
    SCHEMA_VALIDATION_FAILED = "schema_validation_failed"
    SIGNATURE_INVALID = "signature_invalid"
    RATE_LIMITED = "rate_limited"
    DEDUPLICATION_COLLISION = "deduplication_collision"
    UNKNOWN = "unknown"


class DlqEntry(BaseModel):
    entry_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    original_payload: Dict[str, Any]
    source_key: str
    failure_reason: DlqFailureReason
    failure_detail: str = ""
    enqueued_at: float = Field(default_factory=time.time)
    retry_count: int = 0
    last_retry_at: Optional[float] = None
    resolved: bool = False


class DeadLetterQueue:
    """
    Bounded, thread-safe Dead-Letter Queue for failed alert ingestion entries.
    """

    def __init__(self, max_size: int = 5000, max_age_seconds: int = 86400):
        self.max_size = max_size
        self.max_age_seconds = max_age_seconds
        self._entries: Dict[str, DlqEntry] = {}
        self._lock = threading.Lock()

    def enqueue(
        self,
        payload: Dict[str, Any],
        source_key: str,
        failure_reason: DlqFailureReason,
        failure_detail: str = "",
    ) -> DlqEntry:
        with self._lock:
            self._prune_expired()
            if len(self._entries) >= self.max_size:
                oldest_id = min(self._entries, key=lambda k: self._entries[k].enqueued_at)
                del self._entries[oldest_id]

            entry = DlqEntry(
                original_payload=payload,
                source_key=source_key,
                failure_reason=failure_reason,
                failure_detail=failure_detail,
            )
            self._entries[entry.entry_id] = entry
            return entry

    def replay(self, entry_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            entry = self._entries.get(entry_id)
            if not entry or entry.resolved:
                return None
            entry.retry_count += 1
            entry.last_retry_at = time.time()
            return dict(entry.original_payload)

    def resolve(self, entry_id: str) -> bool:
        with self._lock:
            entry = self._entries.get(entry_id)
            if entry:
                entry.resolved = True
                return True
            return False

    def list_entries(
        self,
        unresolved_only: bool = True,
        source_key: Optional[str] = None,
        limit: int = 100,
    ) -> List[DlqEntry]:
        with self._lock:
            self._prune_expired()
            entries = list(self._entries.values())

        if unresolved_only:
            entries = [e for e in entries if not e.resolved]
        if source_key:
            entries = [e for e in entries if e.source_key == source_key]
        entries.sort(key=lambda e: e.enqueued_at, reverse=True)
        return entries[:limit]

    def get_stats(self) -> Dict[str, Any]:
        with self._lock:
            total = len(self._entries)
            unresolved = sum(1 for e in self._entries.values() if not e.resolved)
            by_reason: Dict[str, int] = {}
            for e in self._entries.values():
                key = e.failure_reason.value
                by_reason[key] = by_reason.get(key, 0) + 1

        return {
            "total_entries": total,
            "unresolved_entries": unresolved,
            "resolved_entries": total - unresolved,
            "by_failure_reason": by_reason,
            "max_size": self.max_size,
        }

    def _prune_expired(self) -> None:
        cutoff = time.time() - self.max_age_seconds
        expired = [eid for eid, e in self._entries.items() if e.enqueued_at < cutoff]
        for eid in expired:
            del self._entries[eid]


dead_letter_queue = DeadLetterQueue()
