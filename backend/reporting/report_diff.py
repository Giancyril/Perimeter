"""
Historical Report Diff & Incident Evolution Tracker (Day 5 - Commit 8).

Compares multiple revisions of an IncidentReport over time to track:
1. Newly discovered IOCs and lateral movement paths.
2. Severity upgrades or floor adjustments.
3. Newly surfaced MITRE techniques.
4. Newly identified adversarial prompt injection attempts.
5. Generates human-readable audit changelog for analysts and compliance.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

from backend.ingestion.models import SeverityLevel
from backend.reporting.models import IncidentReport


@dataclass
class ReportDiffResult:
    """Detailed structural delta between two versions of an incident report."""
    diff_id: str
    incident_id: str
    prior_report_id: str
    current_report_id: str
    diff_timestamp: datetime

    # Severity deltas
    prior_severity: SeverityLevel
    current_severity: SeverityLevel
    severity_upgraded: bool
    severity_downgraded: bool
    floor_changed: bool

    # Entity deltas
    added_entities: List[str]
    removed_entities: List[str]

    # Timeline deltas
    new_timeline_events_count: int
    added_event_titles: List[str]

    # MITRE deltas
    new_tactics: List[str]
    new_techniques: List[str]

    # Lateral movement & Injection deltas
    new_lateral_movement_paths: List[str]
    newly_detected_adversarial_injection: bool

    # Executive narrative of changes
    change_summary: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "diff_id": self.diff_id,
            "incident_id": self.incident_id,
            "prior_report_id": self.prior_report_id,
            "current_report_id": self.current_report_id,
            "diff_timestamp": self.diff_timestamp.isoformat(),
            "prior_severity": self.prior_severity.value,
            "current_severity": self.current_severity.value,
            "severity_upgraded": self.severity_upgraded,
            "severity_downgraded": self.severity_downgraded,
            "floor_changed": self.floor_changed,
            "added_entities": self.added_entities,
            "removed_entities": self.removed_entities,
            "new_timeline_events_count": self.new_timeline_events_count,
            "added_event_titles": self.added_event_titles,
            "new_tactics": self.new_tactics,
            "new_techniques": self.new_techniques,
            "new_lateral_movement_paths": self.new_lateral_movement_paths,
            "newly_detected_adversarial_injection": self.newly_detected_adversarial_injection,
            "change_summary": self.change_summary,
        }

    def to_markdown(self) -> str:
        """Render markdown changelog of incident evolution."""
        sev_change = (
            f"**{self.prior_severity.value.upper()}** ➔ **{self.current_severity.value.upper()}**"
            if self.prior_severity != self.current_severity
            else f"Unchanged (`{self.current_severity.value.upper()}`)"
        )

        lines = [
            f"# 🔄 INCIDENT REVISION AUDIT // DIFF REPORT",
            f"**Incident ID:** `{self.incident_id}` | **Diff ID:** `{self.diff_id}`  ",
            f"**Prior Version:** `{self.prior_report_id}` ➔ **Current Version:** `{self.current_report_id}`  ",
            f"**Generated:** {self.diff_timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}  ",
            "",
            "---",
            "",
            "## 📊 High-Level Evolution Summary",
            f"> {self.change_summary}",
            "",
            "| Metric | Delta Status |",
            "| :--- | :--- |",
            f"| **Severity Evolution** | {sev_change} |",
            f"| **New Timeline Events** | **+{self.new_timeline_events_count}** |",
            f"| **Newly Identified Entities** | **+{len(self.added_entities)}** |",
            f"| **New MITRE Techniques** | **+{len(self.new_techniques)}** |",
            f"| **Adversarial Injection Detected** | {'🚨 YES (NEWLY FLAGGED)' if self.newly_detected_adversarial_injection else 'No change'} |",
            "",
            "---",
        ]

        if self.added_entities:
            lines.extend([
                "## 🧬 Newly Discovered Entities (Blast Radius Expansion)",
                "\n".join(f"- `{e}`" for e in self.added_entities),
                "",
            ])

        if self.new_techniques:
            lines.extend([
                "## 🎯 Newly Identified MITRE ATT&CK Techniques",
                "\n".join(f"- `{t}`" for t in self.new_techniques),
                "",
            ])

        if self.new_lateral_movement_paths:
            lines.extend([
                "## 🌐 New Lateral Movement Paths",
                "\n".join(f"- `{p}`" for p in self.new_lateral_movement_paths),
                "",
            ])

        lines.extend([
            "---",
            "*Autonomous SOC Version Control & Investigation Provenance*",
        ])
        return "\n".join(lines)


SEVERITY_ORDER = [
    SeverityLevel.INFORMATIONAL,
    SeverityLevel.LOW,
    SeverityLevel.MEDIUM,
    SeverityLevel.HIGH,
    SeverityLevel.CRITICAL,
]


class ReportDiffEngine:
    """
    Computes precise delta sets between two iterations of an IncidentReport.
    """

    def diff(self, prior: IncidentReport, current: IncidentReport) -> ReportDiffResult:
        prior_rank = SEVERITY_ORDER.index(prior.final_severity)
        curr_rank = SEVERITY_ORDER.index(current.final_severity)

        upgraded = curr_rank > prior_rank
        downgraded = curr_rank < prior_rank
        floor_changed = prior.deterministic_floor != current.deterministic_floor

        # Entity diffs
        prior_ents = set(e.entity_value for e in prior.entities)
        curr_ents = set(e.entity_value for e in current.entities)
        added_ents = sorted(list(curr_ents - prior_ents))
        removed_ents = sorted(list(prior_ents - curr_ents))

        # Timeline diffs
        prior_event_titles = set(e.title for e in prior.timeline)
        added_events = [e for e in current.timeline if e.title not in prior_event_titles]
        new_event_titles = [e.title for e in added_events]
        new_events_count = len(current.timeline) - len(prior.timeline)
        if new_events_count < 0:
            new_events_count = len(added_events)

        # MITRE diffs
        prior_tactics = set(prior.mitre_tactics)
        curr_tactics = set(current.mitre_tactics)
        new_tactics = sorted(list(curr_tactics - prior_tactics))

        prior_techs = set(prior.mitre_techniques)
        curr_techs = set(current.mitre_techniques)
        new_techs = sorted(list(curr_techs - prior_techs))

        # Lateral movement diffs
        prior_paths = set(prior.lateral_movement_paths)
        curr_paths = set(current.lateral_movement_paths)
        new_paths = sorted(list(curr_paths - prior_paths))

        # Injection diff
        new_injection = current.adversarial_injection_detected and not prior.adversarial_injection_detected

        # Synthesize change narrative
        changes = []
        if upgraded:
            changes.append(f"Severity escalated from {prior.final_severity.value.upper()} to {current.final_severity.value.upper()}.")
        if added_ents:
            changes.append(f"Blast radius expanded with {len(added_ents)} new entities.")
        if new_paths:
            changes.append(f"Confirmed {len(new_paths)} additional lateral movement trajectories.")
        if new_injection:
            changes.append("ATTENTION: Adversarial prompt injection detected in newly acquired log streams.")
        if not changes:
            changes.append("Minor telemetry refinement with no change to overall threat classification.")

        summary = " ".join(changes)

        return ReportDiffResult(
            diff_id=f"diff-{uuid.uuid4().hex[:8]}",
            incident_id=current.incident_id,
            prior_report_id=prior.report_id,
            current_report_id=current.report_id,
            diff_timestamp=datetime.now(timezone.utc),
            prior_severity=prior.final_severity,
            current_severity=current.final_severity,
            severity_upgraded=upgraded,
            severity_downgraded=downgraded,
            floor_changed=floor_changed,
            added_entities=added_ents,
            removed_entities=removed_ents,
            new_timeline_events_count=max(0, new_events_count),
            added_event_titles=new_event_titles,
            new_tactics=new_tactics,
            new_techniques=new_techs,
            new_lateral_movement_paths=new_paths,
            newly_detected_adversarial_injection=new_injection,
            change_summary=summary,
        )
