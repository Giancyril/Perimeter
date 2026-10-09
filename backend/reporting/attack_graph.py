"""
MITRE ATT&CK Attack Graph & Kill-Chain Visualizer (Day 5 - Commit 3).

Renders structural attack progression graphs from incident evidence,
generating:
1. Mermaid.js Flowchart (host-to-host lateral movement and technique flow)
2. Mermaid.js Sequence Diagram (chronological message passing)
3. Graphviz DOT notation
4. High-contrast ASCII Kill-Chain representation for terminal / markdown embedding.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from backend.reporting.models import IncidentReport, TimelineEvent


MITRE_KILL_CHAIN_ORDER = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]


@dataclass
class AttackPathSummary:
    """Summary of the primary attack progression vector."""
    initial_compromise_vector: str
    entry_node: str
    pivot_nodes: List[str]
    target_nodes: List[str]
    total_stages: int
    attack_span_minutes: float


class AttackGraphVisualizer:
    """
    Constructs multi-format visual attack graphs and kill-chain models from IncidentReport.
    """

    def __init__(self, sanitize_node_names: bool = True) -> None:
        self.sanitize_node_names = sanitize_node_names

    def _clean_id(self, text: str) -> str:
        """Sanitize strings into safe identifiers for Mermaid / DOT."""
        cleaned = re.sub(r"[^a-zA-Z0-9_]", "_", text)
        return cleaned.strip("_") or "node"

    def analyze_path(self, report: IncidentReport) -> AttackPathSummary:
        """Trace chronological attack flow from timeline events."""
        events = sorted(report.timeline, key=lambda e: e.timestamp)
        if not events:
            return AttackPathSummary(
                initial_compromise_vector="Unknown",
                entry_node="External",
                pivot_nodes=[],
                target_nodes=[],
                total_stages=0,
                attack_span_minutes=0.0,
            )

        start_time = events[0].timestamp
        end_time = events[-1].timestamp
        span_min = max(0.0, (end_time - start_time).total_seconds() / 60.0)

        entry_node = "External"
        if events[0].related_entities:
            entry_node = events[0].related_entities[0]

        all_entities = []
        for ev in events:
            for ent in ev.related_entities:
                if ent not in all_entities and ent != entry_node:
                    all_entities.append(ent)

        pivots = all_entities[:-1] if len(all_entities) > 1 else []
        targets = [all_entities[-1]] if all_entities else [entry_node]

        vector = events[0].title if events else "Suspicious Event Sequence"

        return AttackPathSummary(
            initial_compromise_vector=vector,
            entry_node=entry_node,
            pivot_nodes=pivots,
            target_nodes=targets,
            total_stages=len(events),
            attack_span_minutes=round(span_min, 1),
        )

    def to_mermaid_flowchart(self, report: IncidentReport) -> str:
        """
        Generate a modern, themed Mermaid flowchart of entity interactions and techniques.
        """
        lines = [
            "```mermaid",
            "flowchart LR",
            "    %% Theme and styling",
            "    classDef external fill:#b91c1c,stroke:#f87171,stroke-width:2px,color:#fff;",
            "    classDef host fill:#1e293b,stroke:#64748b,stroke-width:2px,color:#f8fafc;",
            "    classDef crownJewel fill:#dc2626,stroke:#fca5a5,stroke-width:3px,color:#fff;",
            "    classDef action fill:#0f172a,stroke:#38bdf8,stroke-width:1px,color:#38bdf8;",
        ]

        events = sorted(report.timeline, key=lambda e: e.timestamp)
        node_ids: Dict[str, str] = {}

        def get_nid(entity_name: str) -> str:
            if entity_name not in node_ids:
                node_ids[entity_name] = f"N_{self._clean_id(entity_name)}_{len(node_ids)}"
            return node_ids[entity_name]

        # Register entity nodes with styles
        for ent in report.entities:
            nid = get_nid(ent.entity_value)
            label = f'"{ent.entity_value}<br/><small>({ent.entity_type})</small>"'
            lines.append(f"    {nid}[{label}]")
            if ent.criticality in ("critical", "tier_0"):
                lines.append(f"    class {nid} crownJewel;")
            elif ent.threat_verdict == "malicious" or ent.entity_type in ("ip", "external"):
                lines.append(f"    class {nid} external;")
            else:
                lines.append(f"    class {nid} host;")

        # Draw transitions between sequential entities in timeline
        edges_drawn = set()
        for idx in range(len(events) - 1):
            curr_ev = events[idx]
            next_ev = events[idx + 1]

            src_ents = curr_ev.related_entities or ["External_Threat"]
            dst_ents = next_ev.related_entities or ["Internal_Network"]

            src_nid = get_nid(src_ents[0])
            dst_nid = get_nid(dst_ents[0])

            edge_key = (src_nid, dst_nid)
            if edge_key not in edges_drawn and src_nid != dst_nid:
                tech_label = curr_ev.title[:28]
                lines.append(f'    {src_nid} -->|"{tech_label}"| {dst_nid}')
                edges_drawn.add(edge_key)

        # Fallback if no timeline edges drawn
        if not edges_drawn:
            lines.append("    Attacker[External Threat Actor] -->|Initial Compromise| Target[Victim Asset]")

        lines.append("```")
        return "\n".join(lines)

    def to_mermaid_sequence(self, report: IncidentReport) -> str:
        """Generate chronological Mermaid sequence diagram."""
        lines = [
            "```mermaid",
            "sequenceDiagram",
            "    autonumber",
        ]
        events = sorted(report.timeline, key=lambda e: e.timestamp)
        if len(events) < 2:
            lines.extend([
                "    participant Attacker as External Threat",
                "    participant Victim as Internal Host",
                "    Attacker->>Victim: Alert Activity Detected",
            ])
        else:
            participants = set()
            for ev in events:
                for ent in (ev.related_entities or ["Unknown_Entity"])[:2]:
                    participants.add(self._clean_id(ent))

            for p in sorted(participants):
                lines.append(f"    participant {p}")

            for ev in events[:12]:  # cap at 12 steps for readable diagram
                ents = [self._clean_id(e) for e in (ev.related_entities or [])]
                if len(ents) >= 2:
                    lines.append(f"    {ents[0]}->>+{ents[1]}: {ev.title[:30]}")
                elif len(ents) == 1:
                    lines.append(f"    Note over {ents[0]}: {ev.title[:30]}")
        lines.append("```")
        return "\n".join(lines)

    def to_ascii_kill_chain(self, report: IncidentReport) -> str:
        """
        Produce a formatted ASCII kill-chain table highlighting active tactics.
        """
        active_tactics = set(t.lower() for t in report.mitre_tactics)
        lines = [
            "+----------------------+---------+----------------------------------------+",
            "| MITRE ATT&CK Phase   | Active? | Observed Tactics / Techniques          |",
            "+----------------------+---------+----------------------------------------+",
        ]

        for phase in MITRE_KILL_CHAIN_ORDER:
            is_active = phase.lower() in active_tactics or any(phase.lower() in t for t in active_tactics)
            status_symbol = "[X] YES" if is_active else "[ ]  -- "

            matched_techs = [
                tech for tech in report.mitre_techniques
                if phase.lower() in tech.lower()
            ]
            detail = matched_techs[0][:38] if matched_techs else ("Active Phase Detected" if is_active else "")
            lines.append(f"| {phase:<20} | {status_symbol:<7} | {detail:<38} |")

        lines.append("+----------------------+---------+----------------------------------------+")
        return "\n".join(lines)

    def to_dot(self, report: IncidentReport) -> str:
        """Export Graphviz DOT language graph."""
        lines = [
            'digraph AttackGraph {',
            '    rankdir=LR;',
            '    node [shape=box, style="rounded,filled", fontname="Helvetica"];',
        ]
        events = sorted(report.timeline, key=lambda e: e.timestamp)
        for ent in report.entities:
            nid = self._clean_id(ent.entity_value)
            fill = "#ffcccc" if ent.criticality in ("critical", "tier_0") else "#e2e8f0"
            lines.append(f'    "{nid}" [label="{ent.entity_value}\n({ent.entity_type})", fillcolor="{fill}"];')

        for i in range(len(events) - 1):
            e1 = events[i]
            e2 = events[i + 1]
            if e1.related_entities and e2.related_entities:
                s = self._clean_id(e1.related_entities[0])
                d = self._clean_id(e2.related_entities[0])
                if s != d:
                    lbl = e1.title[:20].replace('"', '')
                    lines.append(f'    "{s}" -> "{d}" [label="{lbl}"];')
        lines.append('}')
        return "\n".join(lines)
