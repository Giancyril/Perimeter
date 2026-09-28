"""
MITRE ATT&CK Enterprise Matrix & Attack Chain Knowledge Base.
Provides canonical sequence ordering, tactic mappings, and attack chain progression scoring.
"""
from typing import Dict, List, Optional, Set

# Canonical MITRE ATT&CK Enterprise tactics ordered chronologically by cyber kill-chain phase
MITRE_TACTIC_ORDER: List[str] = [
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

# Map technique IDs to standard descriptions
TECHNIQUE_CATALOG: Dict[str, Dict[str, str]] = {
    "T1110": {"name": "Brute Force", "tactic": "Credential Access"},
    "T1110.001": {"name": "Password Guessing", "tactic": "Credential Access"},
    "T1110.003": {"name": "Password Spraying", "tactic": "Credential Access"},
    "T1190": {"name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    "T1078": {"name": "Valid Accounts", "tactic": "Initial Access"},
    "T1059": {"name": "Command and Scripting Interpreter", "tactic": "Execution"},
    "T1059.001": {"name": "PowerShell", "tactic": "Execution"},
    "T1059.004": {"name": "Unix Shell", "tactic": "Execution"},
    "T1053": {"name": "Scheduled Task/Job", "tactic": "Persistence"},
    "T1053.003": {"name": "Cron", "tactic": "Persistence"},
    "T1548": {"name": "Abuse Elevation Control Mechanism", "tactic": "Privilege Escalation"},
    "T1548.003": {"name": "Sudo and Sudo Caching", "tactic": "Privilege Escalation"},
    "T1036": {"name": "Masquerading", "tactic": "Defense Evasion"},
    "T1070": {"name": "Indicator Removal on Host", "tactic": "Defense Evasion"},
    "T1003": {"name": "OS Credential Dumping", "tactic": "Credential Access"},
    "T1558": {"name": "Steal or Forge Kerberos Tickets", "tactic": "Credential Access"},
    "T1046": {"name": "Network Service Discovery", "tactic": "Discovery"},
    "T1082": {"name": "System Information Discovery", "tactic": "Discovery"},
    "T1021": {"name": "Remote Services", "tactic": "Lateral Movement"},
    "T1021.004": {"name": "SSH", "tactic": "Lateral Movement"},
    "T1105": {"name": "Ingress Tool Transfer", "tactic": "Command and Control"},
    "T1071": {"name": "Application Layer Protocol", "tactic": "Command and Control"},
    "T1048": {"name": "Exfiltration Over Alternative Protocol", "tactic": "Exfiltration"},
    "T1486": {"name": "Data Encrypted for Impact", "tactic": "Impact"},
    "T1489": {"name": "Service Stop", "tactic": "Impact"},
}

def get_tactic_weight(tactic_name: str) -> int:
    """Returns order index for sorting tactics chronologically."""
    for idx, t in enumerate(MITRE_TACTIC_ORDER):
        if t.lower() == tactic_name.lower():
            return idx
    return 99

def sort_tactics_by_killchain(tactics: List[str]) -> List[str]:
    """Sorts unique tactics in kill-chain sequence."""
    unique_tactics = list(set(tactics))
    return sorted(unique_tactics, key=get_tactic_weight)

def infer_mitre_from_rule(rule_name: str, rule_id: str) -> Optional[Dict[str, List[str]]]:
    """Fallback heuristics to infer ATT&CK tactic/technique when SIEM rule lacks metadata."""
    rn = rule_name.lower()
    tactics: Set[str] = set()
    techniques: Set[str] = set()

    if "brute force" in rn or "failed login" in rn or "authentication failure" in rn:
        tactics.add("Credential Access")
        techniques.add("T1110 - Brute Force")
    elif "sudo" in rn or "privilege" in rn or "elevation" in rn:
        tactics.add("Privilege Escalation")
        techniques.add("T1548 - Abuse Elevation")
    elif "powershell" in rn or "bash" in rn or "exec" in rn:
        tactics.add("Execution")
        techniques.add("T1059 - Command Interpreter")
    elif "cron" in rn or "scheduled" in rn:
        tactics.add("Persistence")
        techniques.add("T1053 - Cron / Task")
    elif "port scan" in rn or "sweep" in rn or "nmap" in rn:
        tactics.add("Discovery")
        techniques.add("T1046 - Network Discovery")
    elif "ransomware" in rn or "encrypt" in rn:
        tactics.add("Impact")
        techniques.add("T1486 - Data Encrypted")
    elif "exfiltrat" in rn or "upload" in rn:
        tactics.add("Exfiltration")
        techniques.add("T1048 - Exfiltration")

    if tactics:
        return {
            "tactics": sort_tactics_by_killchain(list(tactics)),
            "techniques": list(techniques),
        }
    return None
