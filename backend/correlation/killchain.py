"""
Multi-Stage MITRE ATT&CK Kill-Chain Progression & Transition Matrix Validator.
Evaluates the chronological transition of attack stages to score progression confidence,
detect forward adversary movement, and identify critical kill-chain milestone crossings.
"""
from typing import Dict, List, Set, Tuple, Optional, Any
from backend.correlation.mitre import MITRE_TACTIC_ORDER, get_tactic_weight

# Natural forward transitions in cyber attack kill-chains (from_tactic -> allowed/likely to_tactics)
FORWARD_TRANSITIONS: Dict[str, Set[str]] = {
    "Reconnaissance": {"Resource Development", "Initial Access", "Discovery"},
    "Resource Development": {"Initial Access", "Execution"},
    "Initial Access": {"Execution", "Persistence", "Privilege Escalation", "Discovery", "Credential Access"},
    "Execution": {"Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access", "Discovery"},
    "Persistence": {"Privilege Escalation", "Defense Evasion", "Credential Access", "Lateral Movement"},
    "Privilege Escalation": {"Defense Evasion", "Credential Access", "Discovery", "Lateral Movement", "Collection"},
    "Defense Evasion": {"Credential Access", "Discovery", "Lateral Movement", "Collection", "Command and Control"},
    "Credential Access": {"Discovery", "Lateral Movement", "Collection", "Command and Control", "Exfiltration"},
    "Discovery": {"Lateral Movement", "Collection", "Command and Control", "Exfiltration", "Impact"},
    "Lateral Movement": {"Execution", "Persistence", "Privilege Escalation", "Credential Access", "Collection"},
    "Collection": {"Command and Control", "Exfiltration", "Impact"},
    "Command and Control": {"Exfiltration", "Impact", "Lateral Movement"},
    "Exfiltration": {"Impact"},
    "Impact": set(),
}

CRITICAL_MILESTONES = {
    "Credential Access",
    "Lateral Movement",
    "Exfiltration",
    "Impact",
}

class KillChainValidator:
    """Validates chronological progression of MITRE ATT&CK tactics in an incident."""

    def __init__(self):
        self.tactic_order = MITRE_TACTIC_ORDER

    def evaluate_progression(self, ordered_tactics: List[str]) -> Dict[str, Any]:
        """
        Analyzes a sequence of tactics ordered chronologically by alert timestamp.
        Returns progression metrics, forward transition ratio, and critical milestone flags.
        """
        if not ordered_tactics:
            return {
                "unique_stages": 0,
                "is_progressive": False,
                "forward_ratio": 0.0,
                "critical_milestones": [],
                "progression_confidence": 0.0,
                "chain_span": 0,
            }

        # Deduplicate consecutive duplicates
        cleaned: List[str] = []
        for t in ordered_tactics:
            if not cleaned or cleaned[-1].lower() != t.lower():
                # Match canonical name
                canonical = next((c for c in self.tactic_order if c.lower() == t.lower()), t)
                cleaned.append(canonical)

        if len(cleaned) <= 1:
            unique = list(set(cleaned))
            milestones = [t for t in unique if t in CRITICAL_MILESTONES]
            return {
                "unique_stages": len(unique),
                "is_progressive": False,
                "forward_ratio": 1.0,
                "critical_milestones": milestones,
                "progression_confidence": 0.3 if milestones else 0.1,
                "chain_span": 1,
            }

        valid_forward_steps = 0
        total_transitions = len(cleaned) - 1

        for i in range(total_transitions):
            t_curr = cleaned[i]
            t_next = cleaned[i + 1]

            allowed_next = FORWARD_TRANSITIONS.get(t_curr, set())
            idx_curr = get_tactic_weight(t_curr)
            idx_next = get_tactic_weight(t_next)

            # Either an explicit transition or monotonic forward progress in kill-chain order
            if t_next in allowed_next or idx_next >= idx_curr:
                valid_forward_steps += 1

        forward_ratio = round(valid_forward_steps / total_transitions, 2)
        unique_stages = list(dict.fromkeys(cleaned))
        milestones = [t for t in unique_stages if t in CRITICAL_MILESTONES]

        # Calculate chain span: difference between earliest and latest kill-chain index + 1
        weights = [get_tactic_weight(t) for t in unique_stages if get_tactic_weight(t) < 99]
        chain_span = (max(weights) - min(weights) + 1) if weights else len(unique_stages)

        # Progression confidence: combines forward ratio, unique stages count, and milestones
        confidence = (forward_ratio * 0.5) + (min(len(unique_stages), 5) / 5.0 * 0.3) + (0.2 if milestones else 0.0)
        confidence = round(min(1.0, confidence), 2)

        return {
            "unique_stages": len(unique_stages),
            "is_progressive": forward_ratio >= 0.6 and len(unique_stages) >= 2,
            "forward_ratio": forward_ratio,
            "critical_milestones": milestones,
            "progression_confidence": confidence,
            "chain_span": chain_span,
            "ordered_sequence": unique_stages,
        }

    def should_escalate_severity(self, evaluation: Dict[str, Any]) -> bool:
        """Determines if the kill-chain progression warrants an automatic severity promotion."""
        if evaluation["is_progressive"] and len(evaluation["critical_milestones"]) >= 1:
            return True
        if evaluation["chain_span"] >= 4 and evaluation["progression_confidence"] >= 0.7:
            return True
        return False
