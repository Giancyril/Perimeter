"""
SIEM Adapter Registry.
Dispatches incoming alert payloads to the appropriate adapter based on source or payload signature.
"""
from typing import Dict, Any, List, Optional
from backend.ingestion.base import AlertSourceAdapter
from backend.ingestion.adapters.wazuh import WazuhAdapter
from backend.ingestion.adapters.syslog import SyslogAdapter
from backend.ingestion.adapters.generic import GenericAdapter
from backend.ingestion.adapters.splunk import SplunkAdapter
from backend.ingestion.adapters.elastic import ElasticAdapter

class AdapterRegistry:
    """Registry maintaining all supported SIEM alert source adapters."""

    def __init__(self):
        self._adapters: List[AlertSourceAdapter] = [
            SplunkAdapter(),
            ElasticAdapter(),
            WazuhAdapter(),
            SyslogAdapter(),
            GenericAdapter(),  # Fallback must be last
        ]

    def register(self, adapter: AlertSourceAdapter):
        """Register a new custom adapter (e.g. Splunk, Elastic, Sentinel)."""
        self._adapters.insert(0, adapter)

    def get_adapter_by_source(self, source_name: str) -> Optional[AlertSourceAdapter]:
        src = str(source_name).lower().strip()
        for adapter in self._adapters:
            if adapter.source_type.value == src:
                return adapter
        return self._adapters[-1]  # Generic fallback

    def resolve_adapter(self, payload: Dict[str, Any], explicit_source: Optional[str] = None) -> AlertSourceAdapter:
        if explicit_source:
            adapter = self.get_adapter_by_source(explicit_source)
            if adapter:
                return adapter

        for adapter in self._adapters:
            if adapter.can_handle(payload):
                return adapter

        return self._adapters[-1]

adapter_registry = AdapterRegistry()
