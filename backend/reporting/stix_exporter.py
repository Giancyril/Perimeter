"""
STIX 2.1 Cyber Threat Intelligence Exporter (Day 5 - Commit 2).

Converts autonomous SOC incident reports, evidence chains, IOCs, and MITRE ATT&CK
mappings into OASIS STIX 2.1 compliant JSON bundles for automated threat-intelligence
sharing across SIEM/SOAR platforms, MISP, and OpenCTI.
"""
from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from backend.reporting.models import IncidentReport


def _stix_id(type_name: str) -> str:
    """Generate canonical STIX 2.1 ID format: <type>--<uuidv4>."""
    return f"{type_name}--{uuid.uuid4()}"


def _format_stix_timestamp(dt: datetime) -> str:
    """STIX 2.1 requires RFC 3339 with UTC timezone ('Z')."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")[:-4] + "Z"


class STIX21Exporter:
    """
    Transforms structured IncidentReport objects into OASIS STIX 2.1 JSON bundles.
    """

    def __init__(self, identity_name: str = "Autonomous SecOps Agent SOC") -> None:
        self.identity_name = identity_name
        self.identity_id = f"identity--{uuid.uuid5(uuid.NAMESPACE_DNS, 'secops.autonomous.soc')}"

    def _create_identity(self) -> Dict[str, Any]:
        now_str = _format_stix_timestamp(datetime.now(timezone.utc))
        return {
            "type": "identity",
            "spec_version": "2.1",
            "id": self.identity_id,
            "created": now_str,
            "modified": now_str,
            "name": self.identity_name,
            "identity_class": "system",
            "sectors": ["technology", "cybersecurity"],
        }

    def _create_incident(self, report: IncidentReport, now_str: str) -> Dict[str, Any]:
        inc_id = _stix_id("incident")
        return {
            "type": "incident",
            "spec_version": "2.1",
            "id": inc_id,
            "created": now_str,
            "modified": now_str,
            "name": f"[{report.final_severity.value.upper()}] {report.incident_title}",
            "description": report.executive_summary or f"Correlated incident {report.incident_id}",
            "created_by_ref": self.identity_id,
            "labels": [
                f"severity:{report.final_severity.value.lower()}",
                f"status:{report.status.lower()}",
                "automated-triage",
            ],
            "external_references": [
                {
                    "source_name": "Autonomous SOC Incident ID",
                    "external_id": report.incident_id,
                }
            ],
        }

    def _create_attack_patterns(self, report: IncidentReport, now_str: str) -> List[Dict[str, Any]]:
        patterns = []
        for tech in report.mitre_techniques:
            # Extract technique ID e.g. T1059 or T1059.001
            m = re.search(r"T\d{4}(?:\.\d{3})?", tech)
            tech_id = m.group(0) if m else tech
            ap_id = _stix_id("attack-pattern")
            patterns.append({
                "type": "attack-pattern",
                "spec_version": "2.1",
                "id": ap_id,
                "created": now_str,
                "modified": now_str,
                "name": tech,
                "created_by_ref": self.identity_id,
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": tech_id,
                        "url": f"https://attack.mitre.org/techniques/{tech_id.replace('.', '/')}/",
                    }
                ],
            })
        return patterns

    def _create_indicators(self, report: IncidentReport, now_str: str) -> List[Dict[str, Any]]:
        indicators = []
        ip_regex = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
        sha256_regex = re.compile(r"^[a-fA-F0-9]{64}$")
        domain_regex = re.compile(r"^[a-zA-Z0-9][-a-zA-Z0-9]*(\.[a-zA-Z0-9][-a-zA-Z0-9]*)+$")

        for ent in report.entities:
            val = ent.entity_value
            stix_pattern = None
            indicator_types = ["malicious-activity"]

            if ent.entity_type == "ip" or ip_regex.match(val):
                stix_pattern = f"[ipv4-addr:value = '{val}']"
            elif ent.entity_type == "hash" or sha256_regex.match(val):
                stix_pattern = f"[file:hashes.'SHA-256' = '{val}']"
            elif ent.entity_type == "domain" or (domain_regex.match(val) and not ip_regex.match(val)):
                stix_pattern = f"[domain-name:value = '{val}']"

            if stix_pattern:
                ind_id = _stix_id("indicator")
                indicators.append({
                    "type": "indicator",
                    "spec_version": "2.1",
                    "id": ind_id,
                    "created": now_str,
                    "modified": now_str,
                    "name": f"IOC: {val}",
                    "pattern": stix_pattern,
                    "pattern_type": "stix",
                    "valid_from": now_str,
                    "indicator_types": indicator_types,
                    "created_by_ref": self.identity_id,
                    "labels": [f"criticality:{ent.criticality or 'medium'}"],
                })
        return indicators

    def _create_relationships(
        self,
        incident_obj: Dict[str, Any],
        attack_patterns: List[Dict[str, Any]],
        indicators: List[Dict[str, Any]],
        now_str: str,
    ) -> List[Dict[str, Any]]:
        relationships = []

        # Incident uses attack-patterns
        for ap in attack_patterns:
            rel_id = _stix_id("relationship")
            relationships.append({
                "type": "relationship",
                "spec_version": "2.1",
                "id": rel_id,
                "created": now_str,
                "modified": now_str,
                "relationship_type": "uses",
                "source_ref": incident_obj["id"],
                "target_ref": ap["id"],
                "created_by_ref": self.identity_id,
            })

        # Indicators indicate incident
        for ind in indicators:
            rel_id = _stix_id("relationship")
            relationships.append({
                "type": "relationship",
                "spec_version": "2.1",
                "id": rel_id,
                "created": now_str,
                "modified": now_str,
                "relationship_type": "indicates",
                "source_ref": ind["id"],
                "target_ref": incident_obj["id"],
                "created_by_ref": self.identity_id,
            })

        return relationships

    def to_bundle(self, report: IncidentReport) -> Dict[str, Any]:
        """Convert IncidentReport to a complete STIX 2.1 Bundle dictionary."""
        now_str = _format_stix_timestamp(datetime.now(timezone.utc))

        identity = self._create_identity()
        incident = self._create_incident(report, now_str)
        attack_patterns = self._create_attack_patterns(report, now_str)
        indicators = self._create_indicators(report, now_str)
        relationships = self._create_relationships(incident, attack_patterns, indicators, now_str)

        all_objects = [identity, incident] + attack_patterns + indicators + relationships

        return {
            "type": "bundle",
            "id": _stix_id("bundle"),
            "spec_version": "2.1",
            "objects": all_objects,
        }

    def to_json(self, report: IncidentReport, indent: int = 2) -> str:
        """Render STIX 2.1 Bundle as serialized JSON string."""
        bundle_dict = self.to_bundle(report)
        return json.dumps(bundle_dict, indent=indent, default=str)

    def export_to_file(self, report: IncidentReport, output_path: Path) -> Path:
        """Serialize bundle directly to a .json file."""
        output_path.parent.mkdir(parents=True, exist_ok=True)
        content = self.to_json(report)
        output_path.write_text(content, encoding="utf-8")
        return output_path
