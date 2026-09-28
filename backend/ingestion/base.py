"""
Base Alert Source Adapter Interface.
All SIEM adapters (Wazuh, Splunk, Elastic, Sentinel, Syslog) inherit from this interface.
"""
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
import hashlib
import json
from backend.ingestion.models import NormalizedAlert, AlertSourceType

class AlertSourceAdapter(ABC):
    """Abstract base class for normalizing alerts from different SIEM formats into standard OCSF/ECS."""

    @property
    @abstractmethod
    def source_type(self) -> AlertSourceType:
        """The source type identifier."""
        pass

    @abstractmethod
    def can_handle(self, payload: Dict[str, Any]) -> bool:
        """Determines if this adapter can parse the given raw payload."""
        pass

    @abstractmethod
    def normalize(self, payload: Dict[str, Any]) -> NormalizedAlert:
        """Parses and converts the raw SIEM payload into a standard NormalizedAlert."""
        pass

    @staticmethod
    def compute_fingerprint(
        source: str,
        rule_id: str,
        source_ip: Optional[str] = None,
        destination_ip: Optional[str] = None,
        user: Optional[str] = None,
        host: Optional[str] = None,
        process_name: Optional[str] = None,
        file_hash: Optional[str] = None,
    ) -> str:
        """
        Computes a deterministic SHA-256 fingerprint for alert correlation & deduplication.
        Alerts matching the same entity signature within a time window are deduplicated.
        """
        canonical_components = [
            str(source or "").strip().lower(),
            str(rule_id or "").strip(),
            str(source_ip or "").strip(),
            str(destination_ip or "").strip(),
            str(user or "").strip().lower(),
            str(host or "").strip().lower(),
            str(process_name or "").strip().lower(),
            str(file_hash or "").strip().lower(),
        ]
        seed = "|".join(canonical_components)
        return hashlib.sha256(seed.encode("utf-8")).hexdigest()
