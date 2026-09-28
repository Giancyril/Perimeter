export type SeverityLevel = "critical" | "high" | "medium" | "low" | "informational";

export type IncidentStatus = "new" | "active" | "investigating" | "pending_approval" | "resolved" | "closed";

export type EntityType = "ip" | "user" | "host" | "process" | "file_hash";

export interface SecurityEntity {
  id: string;
  type: EntityType;
  value: string;
  reputation?: "malicious" | "suspicious" | "neutral" | "clean" | "internal";
  details?: Record<string, string>;
}

export interface SecurityAlert {
  id: string;
  rule_id: string;
  title: string;
  source: "wazuh" | "splunk" | "elastic" | "sentinel" | "syslog";
  timestamp: string;
  raw_severity: SeverityLevel;
  tactic?: string;
  technique?: string;
  entities: SecurityEntity[];
}

export interface TimelineEvent {
  id: string;
  timestamp: string;
  type: "alert" | "tool_call" | "reasoning" | "escalation";
  title: string;
  summary: string;
  evidence_id?: string;
  raw_data?: Record<string, unknown>;
}

export interface SecurityIncident {
  id: string;
  title: string;
  severity: SeverityLevel;
  deterministic_score: number;
  deterministic_floor: SeverityLevel;
  llm_reasoning: string;
  status: IncidentStatus;
  owner: string;
  created_at: string;
  updated_at: string;
  tactics: string[];
  techniques: string[];
  alert_count: number;
  entities: SecurityEntity[];
  alerts: SecurityAlert[];
  timeline: TimelineEvent[];
  proposed_action?: {
    action_id: string;
    action_type: "isolate_host" | "block_ip" | "disable_user" | "kill_process";
    target: string;
    rationale: string;
    requires_approval: boolean;
    status: "proposed" | "approved" | "rejected" | "executed";
  };
}
