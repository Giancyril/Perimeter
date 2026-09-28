export type SeverityLevel = "critical" | "high" | "medium" | "low" | "informational";

export type IncidentStatus =
  | "new"
  | "active"
  | "investigating"
  | "pending_approval"
  | "resolved"
  | "closed";

export type EntityType = "ip" | "user" | "host" | "process" | "file_hash";

export type ActionType = "isolate_host" | "block_ip" | "disable_user" | "kill_process" | "quarantine_file";

export type ActionStatus = "proposed" | "approved" | "rejected" | "executed" | "rolled_back";

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
  type: "alert" | "tool_call" | "reasoning" | "escalation" | "action";
  title: string;
  summary: string;
  evidence_id?: string;
  raw_data?: Record<string, unknown>;
}

export interface ProposedAction {
  action_id: string;
  action_type: ActionType;
  target: string;
  rationale: string;
  requires_approval: boolean;
  status: ActionStatus;
  executed_at?: string;
  executed_by?: string;
  rollback_available?: boolean;
}

export interface IncidentReport {
  report_id: string;
  incident_id: string;
  generated_at: string;
  executive_summary: string;
  technical_narrative: string;
  mitre_coverage: { tactic: string; technique: string; technique_id: string }[];
  recommended_actions: string[];
  iocs: { type: string; value: string; context: string }[];
}

export interface ScoringBreakdown {
  base_score: number;
  multipliers: Record<string, number>;
  final_deterministic: number;
  deterministic_floor: SeverityLevel;
  llm_override?: number;
  llm_reasoning: string;
  final_severity: SeverityLevel;
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
  proposed_action?: ProposedAction;
  scoring_breakdown?: ScoringBreakdown;
  report?: IncidentReport;
}

export interface DashboardStats {
  total: number;
  critical: number;
  pending_approval: number;
  mttr_minutes: number;
}