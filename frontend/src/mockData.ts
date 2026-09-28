import type { SecurityIncident, DashboardStats } from "./types";

export const MOCK_INCIDENTS: SecurityIncident[] = [
  {
    id: "INC-2026-0891",
    title: "Brute Force Authentication followed by Privilege Escalation",
    severity: "critical",
    deterministic_score: 88,
    deterministic_floor: "high",
    llm_reasoning: "Correlation detected 142 failed SSH attempts followed by successful root session and sudo execution within 90 seconds. Asset is a Tier-1 production database server (prod-db-primary-01). Historical actor pattern matches APT29 lateral movement TTPs.",
    status: "pending_approval",
    owner: "SecOps Agent (Auto)",
    created_at: "2026-09-28T13:20:10Z",
    updated_at: "2026-09-28T13:22:45Z",
    tactics: ["Initial Access", "Privilege Escalation", "Lateral Movement"],
    techniques: ["T1110 - Brute Force", "T1548 - Abuse Elevation", "T1021 - Remote Services"],
    alert_count: 5,
    entities: [
      { id: "e1", type: "ip", value: "198.51.100.42", reputation: "malicious", details: { Geo: "RU", ASN: "AS12345", AbuseScore: "94%", Reports: "312 in last 24h" } },
      { id: "e2", type: "host", value: "prod-db-primary-01", reputation: "internal", details: { OS: "Ubuntu 22.04 LTS", Tier: "Tier-1 High-Value", VPC: "vpc-prod-core", IP: "10.0.12.44" } },
      { id: "e3", type: "user", value: "svc_deployer", reputation: "suspicious", details: { Role: "Service Account", Privileges: "sudo, docker", Status: "Anomalous Sudo Spike" } },
      { id: "e4", type: "process", value: "/usr/bin/python3 -c import pty...", reputation: "malicious", details: { PID: "41289", Parent: "sshd: svc_deployer", Hash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" } }
    ],
    alerts: [
      {
        id: "ALT-90412",
        rule_id: "WAZUH-SSH-0089",
        title: "Excessive Failed SSH Authentications from External IP",
        source: "wazuh",
        timestamp: "2026-09-28T13:20:10Z",
        raw_severity: "high",
        tactic: "Initial Access",
        technique: "T1110.001 - Password Guessing",
        entities: [
          { id: "e1", type: "ip", value: "198.51.100.42" },
          { id: "e2", type: "host", value: "prod-db-primary-01" }
        ]
      },
      {
        id: "ALT-90415",
        rule_id: "WAZUH-AUTH-0012",
        title: "Successful Login After Multiple Authentication Failures",
        source: "wazuh",
        timestamp: "2026-09-28T13:21:05Z",
        raw_severity: "critical",
        tactic: "Initial Access",
        technique: "T1078 - Valid Accounts",
        entities: [
          { id: "e1", type: "ip", value: "198.51.100.42" },
          { id: "e3", type: "user", value: "svc_deployer" }
        ]
      },
      {
        id: "ALT-90420",
        rule_id: "SPLUNK-SUDO-0044",
        title: "Sudo Shell Spawned by Non-Interactive Service Account",
        source: "splunk",
        timestamp: "2026-09-28T13:21:40Z",
        raw_severity: "critical",
        tactic: "Privilege Escalation",
        technique: "T1548.003 - Sudo and Sudo Caching",
        entities: [
          { id: "e2", type: "host", value: "prod-db-primary-01" },
          { id: "e3", type: "user", value: "svc_deployer" }
        ]
      }
    ],
    timeline: [
      {
        id: "tl-1",
        timestamp: "13:20:10",
        type: "alert",
        title: "Inbound SSH Brute-force Ingested",
        summary: "Wazuh agent reported 142 failed SSH attempts originating from 198.51.100.42 over a 45s window.",
        evidence_id: "EVD-001"
      },
      {
        id: "tl-2",
        timestamp: "13:20:25",
        type: "tool_call",
        title: "Threat Intel Query: AbuseIPDB & VirusTotal",
        summary: "Tool ip_enrichment returned reputation: malicious. Confidence score: 94%. Associated with known scanner network in AS12345.",
        evidence_id: "EVD-002"
      },
      {
        id: "tl-3",
        timestamp: "13:21:05",
        type: "alert",
        title: "Account Compromise Flagged",
        summary: "Successful authentication for account svc_deployer from external IP 198.51.100.42.",
        evidence_id: "EVD-003"
      },
      {
        id: "tl-4",
        timestamp: "13:21:40",
        type: "tool_call",
        title: "SIEM Deep Query: User Command History",
        summary: "Executed query 'index=linux_audit host=prod-db-primary-01 user=svc_deployer'. Found spawned interactive bash and sudo su command.",
        evidence_id: "EVD-004"
      },
      {
        id: "tl-5",
        timestamp: "13:22:00",
        type: "reasoning",
        title: "Deterministic Severity Floor Enforced",
        summary: "Deterministic score calculated: 88 (Critical). Rule floor applied: Compromise of Tier-1 database host enforces minimum HIGH floor.",
        evidence_id: "EVD-005"
      },
      {
        id: "tl-6",
        timestamp: "13:22:45",
        type: "escalation",
        title: "Proposed Containment Action: Host Isolation",
        summary: "Autonomous agent generated human-in-the-loop containment request. High impact action requires human approval before AWS/Wazuh network isolation executes.",
        evidence_id: "EVD-006"
      }
    ],
    proposed_action: {
      action_id: "ACT-2026-0891-1",
      action_type: "isolate_host",
      target: "prod-db-primary-01",
      rationale: "Active interactive root shell compromised via external IP 198.51.100.42. Immediate network isolation required to prevent database dump and lateral spread.",
      requires_approval: true,
      status: "proposed",
      rollback_available: true
    },
    scoring_breakdown: {
      base_score: 55,
      multipliers: {
        "Tier-1 Database Asset criticality": 1.4,
        "Successful auth following brute-force": 1.25,
        "Active root shell privilege escalation": 1.3
      },
      final_deterministic: 88,
      deterministic_floor: "high",
      llm_override: 88,
      llm_reasoning: "Agent agrees with deterministic calculation. Attacker obtained interactive terminal access on critical tier-1 asset. Floor constraint satisfied.",
      final_severity: "critical"
    },
    report: {
      report_id: "RPT-2026-0891",
      incident_id: "INC-2026-0891",
      generated_at: "2026-09-28T13:23:00Z",
      executive_summary: "A coordinated brute-force attack originating from IP 198.51.100.42 succeeded in compromising the service account svc_deployer on the production database server prod-db-primary-01. The adversary immediately escalated privileges to root using unauthorized sudo invocation. The Autonomous SecOps Agent correlated 3 discrete alerts, validated threat intelligence indicators, halted automated containment pending human authorization, and prepared an isolated sandbox environment.",
      technical_narrative: "Initial ingress occurred via SSH (port 22) against prod-db-primary-01 (10.0.12.44) from source IP 198.51.100.42. Over a 45-second duration, 142 failed login attempts were logged by Wazuh. At 13:21:05Z, a password spray variant correctly matched credentials for svc_deployer. Within 35 seconds of login, the session executed sudo -i, spawning an interactive root shell (PID 41289) and establishing an outbound beacon connection to known C2 infrastructure 45.141.84.12.",
      mitre_coverage: [
        { tactic: "Initial Access", technique: "Brute Force: Password Spraying", technique_id: "T1110.003" },
        { tactic: "Initial Access", technique: "Valid Accounts: Local Accounts", technique_id: "T1078.003" },
        { tactic: "Privilege Escalation", technique: "Abuse Elevation Control Mechanism: Sudo", technique_id: "T1548.003" },
        { tactic: "Lateral Movement", technique: "Remote Services: SSH", technique_id: "T1021.004" },
        { tactic: "Command and Control", technique: "Application Layer Protocol: Web Protocols", technique_id: "T1071.001" }
      ],
      recommended_actions: [
        "Authorize immediate network isolation of prod-db-primary-01 via AWS Security Group quarantine",
        "Rotate and invalidate all credentials, SSH authorized_keys, and tokens for svc_deployer",
        "Add external IP 198.51.100.42 and subnet to perimeter firewall edge drop list",
        "Trigger volatile memory capture and snapshot disk volume for digital forensics investigation",
        "Audit database audit logs for any unencrypted export or table SELECT anomalies"
      ],
      iocs: [
        { type: "IPv4", value: "198.51.100.42", context: "Attacker Ingress Node (AbuseIPDB score 94%)" },
        { type: "IPv4", value: "45.141.84.12", context: "Outbound C2 Beacon IP" },
        { type: "Username", value: "svc_deployer", context: "Compromised Service Account" },
        { type: "SHA256", value: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", context: "Suspicious Reverse Shell Binary" }
      ]
    }
  },
  {
    id: "INC-2026-0892",
    title: "Cobalt Strike C2 Beaconing via Injected Process",
    severity: "critical",
    deterministic_score: 92,
    deterministic_floor: "critical",
    llm_reasoning: "Memory injection detected into spoolsv.exe with periodic sleep mask jitter matching Cobalt Strike malleable C2 profile. Destination IP in foreign autonomous system.",
    status: "pending_approval",
    owner: "SecOps Agent (Auto)",
    created_at: "2026-09-28T13:45:00Z",
    updated_at: "2026-09-28T13:48:12Z",
    tactics: ["Defense Evasion", "Command and Control"],
    techniques: ["T1055 - Process Injection", "T1071 - Application Layer Protocol"],
    alert_count: 4,
    entities: [
      { id: "e5", type: "ip", value: "45.141.84.12", reputation: "malicious", details: { ASN: "AS48221", Country: "NL", VT_Detections: "18/72" } },
      { id: "e6", type: "host", value: "ws-fin-109", reputation: "internal", details: { OS: "Windows 11 Enterprise", Dept: "Finance", User: "clara.adams" } },
      { id: "e7", type: "process", value: "spoolsv.exe (Injected)", reputation: "malicious", details: { PID: "3844", HollowedSection: "0x7ffb3000" } }
    ],
    alerts: [
      {
        id: "ALT-90430",
        rule_id: "ELASTIC-MEM-0012",
        title: "Process Injection via CreateRemoteThread into spoolsv.exe",
        source: "elastic",
        timestamp: "2026-09-28T13:45:00Z",
        raw_severity: "critical",
        tactic: "Defense Evasion",
        technique: "T1055.001 - Dynamic-link Library Injection",
        entities: [
          { id: "e6", type: "host", value: "ws-fin-109" },
          { id: "e7", type: "process", value: "spoolsv.exe" }
        ]
      }
    ],
    timeline: [
      {
        id: "tl-21",
        timestamp: "13:45:00",
        type: "alert",
        title: "Process Injection Detected in spoolsv.exe",
        summary: "Elastic Defend detected unauthorized RWX memory allocation in spoolsv.exe.",
        evidence_id: "EVD-010"
      },
      {
        id: "tl-22",
        timestamp: "13:46:10",
        type: "tool_call",
        title: "Network Egress Inspection",
        summary: "Found recurring 60s HTTP POST beacons to 45.141.84.12:443 with randomized user-agents.",
        evidence_id: "EVD-011"
      },
      {
        id: "tl-23",
        timestamp: "13:48:12",
        type: "escalation",
        title: "Containment Action Proposed: Perimeter IP Block",
        summary: "Gate triggered: block external IP 45.141.84.12 across Palo Alto edge firewalls.",
        evidence_id: "EVD-012"
      }
    ],
    proposed_action: {
      action_id: "ACT-2026-0892-1",
      action_type: "block_ip",
      target: "45.141.84.12",
      rationale: "Confirmed C2 listener IP receiving continuous encrypted telemetry beacons from ws-fin-109.",
      requires_approval: true,
      status: "proposed",
      rollback_available: true
    },
    scoring_breakdown: {
      base_score: 70,
      multipliers: {
        "Active C2 Beaconing": 1.3,
        "Finance Department Asset": 1.15
      },
      final_deterministic: 92,
      deterministic_floor: "critical",
      llm_override: 92,
      llm_reasoning: "Unambiguous Cobalt Strike profile with memory manipulation and regular beacon intervals.",
      final_severity: "critical"
    }
  },
  {
    id: "INC-2026-0893",
    title: "Active Directory Kerberoasting & Ticket Extraction",
    severity: "high",
    deterministic_score: 76,
    deterministic_floor: "medium",
    llm_reasoning: "Spike in TGS requests for service principal names (SPNs) with RC4 encryption downgrade request. Originates from workstation in dev pool.",
    status: "investigating",
    owner: "SecOps Agent (Auto)",
    created_at: "2026-09-28T12:10:00Z",
    updated_at: "2026-09-28T12:15:30Z",
    tactics: ["Credential Access"],
    techniques: ["T1558 - Steal or Forge Kerberos Tickets"],
    alert_count: 3,
    entities: [
      { id: "e8", type: "user", value: "svc_backup_admin", reputation: "suspicious", details: { SPN: "MSSQLSvc/db.corp.local", Encryption: "RC4_HMAC" } },
      { id: "e9", type: "host", value: "dev-box-044", reputation: "internal", details: { Subnet: "172.16.50.0/24", Owner: "dev-team-b" } }
    ],
    alerts: [
      {
        id: "ALT-90401",
        rule_id: "SENTINEL-KRB-002",
        title: "Anomalous Kerberos TGS-REQ Request Storm",
        source: "sentinel",
        timestamp: "2026-09-28T12:10:00Z",
        raw_severity: "high",
        tactic: "Credential Access",
        technique: "T1558.003 - Kerberoasting",
        entities: [
          { id: "e8", type: "user", value: "svc_backup_admin" },
          { id: "e9", type: "host", value: "dev-box-044" }
        ]
      }
    ],
    timeline: [
      {
        id: "tl-31",
        timestamp: "12:10:00",
        type: "alert",
        title: "Kerberos TGS Surge Detected",
        summary: "Sentinel flagged 38 SPN ticket requests within 12 seconds from dev-box-044.",
        evidence_id: "EVD-020"
      },
      {
        id: "tl-32",
        timestamp: "12:12:15",
        type: "tool_call",
        title: "AD Audit Log Enrichment",
        summary: "Target service accounts include domain-admin tier accounts with weak password history.",
        evidence_id: "EVD-021"
      }
    ],
    proposed_action: {
      action_id: "ACT-2026-0893-1",
      action_type: "disable_user",
      target: "svc_backup_admin",
      rationale: "High risk of offline password cracking. Account credential must be invalidated until SPN rotation.",
      requires_approval: true,
      status: "proposed",
      rollback_available: true
    }
  },
  {
    id: "INC-2026-0894",
    title: "Potential Data Exfiltration via DNS Tunneling",
    severity: "medium",
    deterministic_score: 58,
    deterministic_floor: "medium",
    llm_reasoning: "High-entropy subdomain queries to dynamic domain ns1.datasync-cloud.biz observed from build runner.",
    status: "active",
    owner: "SecOps Agent (Auto)",
    created_at: "2026-09-28T11:05:00Z",
    updated_at: "2026-09-28T11:08:20Z",
    tactics: ["Exfiltration"],
    techniques: ["T1048 - Exfiltration Over Alternative Protocol"],
    alert_count: 2,
    entities: [
      { id: "e10", type: "host", value: "ci-runner-linux-08", reputation: "internal", details: { Role: "GitLab Runner", Zone: "Build VPC" } },
      { id: "e11", type: "ip", value: "192.0.2.199", reputation: "suspicious", details: { Domain: "ns1.datasync-cloud.biz", Entropy: "4.88" } }
    ],
    alerts: [],
    timeline: [
      {
        id: "tl-41",
        timestamp: "11:05:00",
        type: "alert",
        title: "High Volume TXT Query Anomaly",
        summary: "DNS resolver noted 1,200 unique subdomains queried to datasync-cloud.biz in 5 minutes.",
        evidence_id: "EVD-030"
      }
    ]
  },
  {
    id: "INC-2026-0895",
    title: "SQL Injection Attack Blocked by WAF",
    severity: "low",
    deterministic_score: 32,
    deterministic_floor: "low",
    llm_reasoning: "Automated vulnerability scanner payloads (sqlmap signatures) detected and blocked at Cloudflare edge. No backend database impact.",
    status: "resolved",
    owner: "SecOps Agent (Auto)",
    created_at: "2026-09-28T09:15:00Z",
    updated_at: "2026-09-28T09:18:00Z",
    tactics: ["Initial Access"],
    techniques: ["T1190 - Exploit Public-Facing Application"],
    alert_count: 1,
    entities: [
      { id: "e12", type: "ip", value: "203.0.113.88", reputation: "malicious", details: { Tool: "sqlmap/1.7.2#stable", Status: "Blocked 403" } }
    ],
    alerts: [],
    timeline: [
      {
        id: "tl-51",
        timestamp: "09:15:00",
        type: "alert",
        title: "WAF Signature Triggered: SQLi UNION SELECT",
        summary: "Pattern blocked before reaching ingress gateway. Attack neutralized.",
        evidence_id: "EVD-040"
      }
    ]
  }
];

export const MOCK_STATS: DashboardStats = {
  total: 5,
  critical: 2,
  pending_approval: 2,
  mttr_minutes: 4.2
};
