import { useState } from "react";
import {
  ShieldAlert,
  AlertTriangle,
  Terminal,
  Activity,
  User,
  Server,
  Globe,
  CheckCircle,
  XCircle,
  Lock,
} from "lucide-react";
import type { SecurityIncident, SeverityLevel } from "./types";

const MOCK_INCIDENTS: SecurityIncident[] = [
  {
    id: "INC-2026-0891",
    title: "Brute Force Authentication followed by Privilege Escalation",
    severity: "critical",
    deterministic_score: 88,
    deterministic_floor: "high",
    llm_reasoning:
      "Correlation detected 142 failed SSH attempts followed by successful root session and sudo execution within 90 seconds. Asset is a Tier-1 production database server.",
    status: "pending_approval",
    owner: "SecOps Agent (Auto)",
    created_at: "2026-09-28T13:20:10Z",
    updated_at: "2026-09-28T13:22:45Z",
    tactics: ["Initial Access", "Privilege Escalation"],
    techniques: ["T1110 - Brute Force", "T1548 - Abuse Elevation"],
    alert_count: 5,
    entities: [
      { id: "e1", type: "ip", value: "198.51.100.42", reputation: "malicious", details: { Geo: "RU", ASN: "AS12345", AbuseScore: "94%" } },
      { id: "e2", type: "host", value: "prod-db-primary-01", reputation: "internal", details: { Role: "PostgreSQL Database", Criticality: "Tier-1" } },
      { id: "e3", type: "user", value: "svc_deployer", reputation: "suspicious", details: { Department: "DevOps", Privileged: "Yes" } },
    ],
    alerts: [
      {
        id: "ALT-101",
        rule_id: "wazuh-5710",
        title: "sshd: Multiple failed login attempts",
        source: "wazuh",
        timestamp: "2026-09-28T13:20:10Z",
        raw_severity: "medium",
        tactic: "Initial Access",
        entities: [],
      },
      {
        id: "ALT-102",
        rule_id: "wazuh-5715",
        title: "sshd: Successful login after multiple failures",
        source: "wazuh",
        timestamp: "2026-09-28T13:21:04Z",
        raw_severity: "high",
        tactic: "Initial Access",
        entities: [],
      },
    ],
    timeline: [
      {
        id: "tm-1",
        timestamp: "13:20:10",
        type: "alert",
        title: "Ingested Wazuh Alert [Rule 5710]",
        summary: "142 failed SSH authentication attempts from 198.51.100.42 targeting svc_deployer.",
        evidence_id: "ALT-101",
      },
      {
        id: "tm-2",
        timestamp: "13:20:14",
        type: "tool_call",
        title: "Threat Intel Enrichment (AbuseIPDB)",
        summary: "Queried IP 198.51.100.42: Reported 312 times in last 24h. Malicious confidence score 94%.",
        evidence_id: "TI-0891",
      },
      {
        id: "tm-3",
        timestamp: "13:21:04",
        type: "alert",
        title: "Ingested Wazuh Alert [Rule 5715]",
        summary: "Successful authentication detected for svc_deployer on prod-db-primary-01.",
        evidence_id: "ALT-102",
      },
      {
        id: "tm-4",
        timestamp: "13:21:12",
        type: "reasoning",
        title: "Deterministic Floor & LLM Scoring",
        summary: "Deterministic floor computed: HIGH. LLM upgraded severity to CRITICAL due to production database impact.",
      },
    ],
    proposed_action: {
      action_id: "ACT-001",
      action_type: "isolate_host",
      target: "prod-db-primary-01",
      rationale: "Quarantine host at perimeter firewall to prevent lateral movement while preserving memory state for forensics.",
      requires_approval: true,
      status: "proposed",
    },
  },
  {
    id: "INC-2026-0890",
    title: "Suspicious PowerShell Download Cradle via Word Document",
    severity: "high",
    deterministic_score: 72,
    deterministic_floor: "high",
    llm_reasoning: "Encrypted payload retrieved via Invoke-WebRequest from known phishing domain.",
    status: "active",
    owner: "Analyst Jane D.",
    created_at: "2026-09-28T12:45:00Z",
    updated_at: "2026-09-28T13:00:22Z",
    tactics: ["Execution"],
    techniques: ["T1059.001 - PowerShell"],
    alert_count: 3,
    entities: [
      { id: "e4", type: "user", value: "finance_clerk_02", reputation: "internal" },
      { id: "e5", type: "host", value: "wkstn-fin-109", reputation: "internal" },
    ],
    alerts: [],
    timeline: [],
  },
];

export function App() {
  const [selectedIncident, setSelectedIncident] = useState<SecurityIncident>(MOCK_INCIDENTS[0]);
  const [activeTab, setActiveTab] = useState<"timeline" | "raw">("timeline");
  const [actionStatus, setActionStatus] = useState<string>("proposed");

  const getSeverityBadgeClass = (sev: SeverityLevel) => {
    switch (sev) {
      case "critical":
        return "badge-sev sev-critical";
      case "high":
        return "badge-sev sev-high";
      case "medium":
        return "badge-sev sev-medium";
      case "low":
        return "badge-sev sev-low";
      case "informational":
        return "badge-sev sev-informational";
    }
  };

  return (
    <div style={{ minHeight: "100vh", display: "flex", flexDirection: "column" }}>
      {/* Top Navbar */}
      <header className="soc-header">
        <div className="soc-brand">
          <ShieldAlert size={20} color="#f43f5e" />
          <span className="brand-title">Security Operations Agent</span>
          <span className="brand-tag">Autonomous SOC</span>
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: "14px" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "6px", fontSize: "12px", color: "var(--text-muted)" }}>
            <Activity size={14} color="#10b981" />
            <span>SIEM Pipeline: Ingestion Active (Wazuh/Syslog)</span>
          </div>
          <button className="btn btn-outline" style={{ padding: "4px 8px" }}>
            <Terminal size={14} />
            <span>Agent CLI</span>
          </button>
        </div>
      </header>

      {/* Main Split Layout */}
      <div style={{ display: "flex", flex: 1, overflow: "hidden" }}>
        {/* Left: Incident Queue */}
        <aside style={{ width: "420px", borderRight: "1px solid var(--border)", background: "var(--bg-surface)", display: "flex", flexDirection: "column" }}>
          <div style={{ padding: "12px", borderBottom: "1px solid var(--border)", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <div>
              <span style={{ fontWeight: 700, fontSize: "13px" }}>Incidents Queue</span>
              <span style={{ marginLeft: "8px", fontSize: "11px", color: "var(--text-dim)" }}>({MOCK_INCIDENTS.length} active)</span>
            </div>
            <div style={{ display: "flex", gap: "4px" }}>
              <span className="badge-sev sev-critical">1 Critical</span>
              <span className="badge-sev sev-high">1 High</span>
            </div>
          </div>

          <div style={{ overflowY: "auto", flex: 1 }}>
            <table className="soc-table">
              <thead>
                <tr>
                  <th>Sev</th>
                  <th>Incident</th>
                  <th>Age</th>
                </tr>
              </thead>
              <tbody>
                {MOCK_INCIDENTS.map((inc) => (
                  <tr
                    key={inc.id}
                    className={`clickable ${selectedIncident.id === inc.id ? "selected" : ""}`}
                    onClick={() => {
                      setSelectedIncident(inc);
                      setActionStatus(inc.proposed_action?.status || "proposed");
                    }}
                  >
                    <td>
                      <span className={getSeverityBadgeClass(inc.severity)}>{inc.severity.slice(0, 4)}</span>
                    </td>
                    <td>
                      <div style={{ fontWeight: 600, color: "var(--text-main)", fontSize: "12px", marginBottom: "3px" }}>
                        {inc.title}
                      </div>
                      <div style={{ display: "flex", gap: "6px", alignItems: "center", fontSize: "11px", color: "var(--text-dim)" }}>
                        <span className="mono">{inc.id}</span>
                        <span>•</span>
                        <span>{inc.tactics.join(", ")}</span>
                      </div>
                    </td>
                    <td style={{ fontSize: "11px", color: "var(--text-muted)", whiteSpace: "nowrap" }}>12m ago</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </aside>

        {/* Right: Incident Detail */}
        <main style={{ flex: 1, display: "flex", flexDirection: "column", background: "var(--bg-dark)", overflowY: "auto" }}>
          {/* Incident Detail Header */}
          <div style={{ padding: "16px 20px", borderBottom: "1px solid var(--border)", background: "var(--bg-surface)" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "10px" }}>
              <div>
                <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "4px" }}>
                  <span className="mono" style={{ fontSize: "12px", color: "var(--text-dim)" }}>{selectedIncident.id}</span>
                  <span className={getSeverityBadgeClass(selectedIncident.severity)}>{selectedIncident.severity}</span>
                  <span style={{ fontSize: "11px", background: "var(--bg-card)", border: "1px solid var(--border)", padding: "2px 6px", borderRadius: "3px" }}>
                    Status: <strong>{selectedIncident.status}</strong>
                  </span>
                  <span style={{ fontSize: "11px", color: "var(--text-dim)" }}>Owner: {selectedIncident.owner}</span>
                </div>
                <h2 style={{ fontSize: "16px", fontWeight: 700 }}>{selectedIncident.title}</h2>
              </div>

              <div style={{ display: "flex", gap: "8px" }}>
                <button className="btn btn-outline">Escalate to Slack</button>
                <button className="btn btn-primary">Generate Report</button>
              </div>
            </div>

            {/* Severity Floor Breakdown */}
            <div style={{ background: "rgba(20, 30, 51, 0.6)", border: "1px solid var(--border)", padding: "8px 12px", borderRadius: "4px", fontSize: "12px", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <div>
                <span style={{ color: "var(--text-muted)" }}>Deterministic Score: </span>
                <strong style={{ color: "#38bdf8" }}>{selectedIncident.deterministic_score}/100</strong>
                <span style={{ margin: "0 8px", color: "var(--border-light)" }}>|</span>
                <span style={{ color: "var(--text-muted)" }}>Calculated Floor: </span>
                <strong style={{ color: "#f97316", textTransform: "uppercase" }}>{selectedIncident.deterministic_floor}</strong>
                <span style={{ margin: "0 8px", color: "var(--border-light)" }}>|</span>
                <span style={{ color: "var(--text-muted)" }}>LLM Verdict: </span>
                <span style={{ color: "var(--text-main)" }}>{selectedIncident.llm_reasoning}</span>
              </div>
              <span title="Floor Enforcement Active: LLM cannot lower severity below deterministic score">
                <Lock size={14} color="#64748b" />
              </span>
            </div>
          </div>

          {/* Response Approval Gate Banner */}
          {selectedIncident.proposed_action && (
            <div style={{ margin: "16px 20px 0 20px", padding: "14px 16px", background: "rgba(244, 63, 94, 0.08)", border: "1px solid rgba(244, 63, 94, 0.4)", borderRadius: "6px" }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                  <AlertTriangle size={20} color="#f43f5e" />
                  <div>
                    <div style={{ fontWeight: 700, fontSize: "13px", color: "#f43f5e" }}>
                      HUMAN-IN-THE-LOOP APPROVAL REQUIRED: Action [{selectedIncident.proposed_action.action_type.toUpperCase()}]
                    </div>
                    <div style={{ fontSize: "12px", color: "var(--text-main)", marginTop: "2px" }}>
                      Target: <span className="mono" style={{ color: "#fca5a5" }}>{selectedIncident.proposed_action.target}</span> • {selectedIncident.proposed_action.rationale}
                    </div>
                  </div>
                </div>

                <div style={{ display: "flex", gap: "8px" }}>
                  {actionStatus === "proposed" ? (
                    <>
                      <button
                        className="btn btn-danger"
                        onClick={() => setActionStatus("approved")}
                      >
                        <CheckCircle size={14} />
                        <span>Approve & Execute</span>
                      </button>
                      <button
                        className="btn btn-outline"
                        onClick={() => setActionStatus("rejected")}
                      >
                        <XCircle size={14} />
                        <span>Reject Action</span>
                      </button>
                    </>
                  ) : (
                    <div style={{ fontSize: "12px", fontWeight: 700, color: actionStatus === "approved" ? "#10b981" : "#94a3b8" }}>
                      {actionStatus === "approved" ? "✓ Action Approved & Executed" : "✕ Action Rejected by Analyst"}
                    </div>
                  )}
                </div>
              </div>
            </div>
          )}

          {/* Inner Content Grid */}
          <div style={{ display: "grid", gridTemplateColumns: "2fr 1fr", gap: "16px", padding: "16px 20px", flex: 1 }}>
            {/* Left: Investigation & Timeline */}
            <div style={{ background: "var(--bg-surface)", border: "1px solid var(--border)", borderRadius: "6px", display: "flex", flexDirection: "column" }}>
              <div style={{ display: "flex", borderBottom: "1px solid var(--border)", padding: "0 12px" }}>
                <button
                  className={`btn ${activeTab === "timeline" ? "btn-primary" : "btn-outline"}`}
                  style={{ borderBottom: "none", borderRadius: "4px 4px 0 0", margin: "6px 4px -1px 0" }}
                  onClick={() => setActiveTab("timeline")}
                >
                  Investigation Timeline ({selectedIncident.timeline.length})
                </button>
                <button
                  className={`btn ${activeTab === "raw" ? "btn-primary" : "btn-outline"}`}
                  style={{ borderBottom: "none", borderRadius: "4px 4px 0 0", margin: "6px 4px -1px 0" }}
                  onClick={() => setActiveTab("raw")}
                >
                  Raw Ingested Alerts ({selectedIncident.alert_count})
                </button>
              </div>

              <div style={{ padding: "16px", overflowY: "auto", flex: 1 }}>
                {activeTab === "timeline" ? (
                  <div style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
                    {selectedIncident.timeline.map((item) => (
                      <div key={item.id} style={{ display: "flex", gap: "12px", borderLeft: "2px solid var(--border-light)", paddingLeft: "14px", position: "relative" }}>
                        <span style={{ fontSize: "11px", color: "var(--text-dim)", width: "60px", flexShrink: 0 }} className="mono">
                          {item.timestamp}
                        </span>
                        <div>
                          <div style={{ fontWeight: 600, fontSize: "12px", color: "var(--text-main)" }}>{item.title}</div>
                          <div style={{ fontSize: "12px", color: "var(--text-muted)", marginTop: "2px" }}>{item.summary}</div>
                          {item.evidence_id && (
                            <span className="mono" style={{ fontSize: "10px", color: "#38bdf8", background: "rgba(56, 189, 248, 0.1)", padding: "1px 4px", borderRadius: "2px", display: "inline-block", marginTop: "4px" }}>
                              Ref: {item.evidence_id}
                            </span>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div style={{ fontSize: "12px", color: "var(--text-muted)" }}>
                    <div style={{ marginBottom: "8px" }}>Normalized alert records linked to this correlation window:</div>
                    {selectedIncident.alerts.map((alt) => (
                      <div key={alt.id} style={{ background: "var(--bg-card)", padding: "8px 12px", border: "1px solid var(--border)", borderRadius: "4px", marginBottom: "8px" }}>
                        <div style={{ display: "flex", justifyContent: "space-between" }}>
                          <span className="mono" style={{ color: "#38bdf8" }}>{alt.id} [{alt.rule_id}]</span>
                          <span style={{ color: "var(--text-dim)" }}>{alt.source.toUpperCase()}</span>
                        </div>
                        <div style={{ fontWeight: 600, marginTop: "4px" }}>{alt.title}</div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>

            {/* Right: Affected Entities */}
            <div style={{ background: "var(--bg-surface)", border: "1px solid var(--border)", borderRadius: "6px", padding: "16px" }}>
              <h3 style={{ fontSize: "13px", fontWeight: 700, marginBottom: "12px", display: "flex", alignItems: "center", gap: "6px" }}>
                <span>Correlated Entities</span>
                <span style={{ fontSize: "11px", color: "var(--text-dim)" }}>({selectedIncident.entities.length})</span>
              </h3>

              <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
                {selectedIncident.entities.map((ent) => (
                  <div key={ent.id} style={{ background: "var(--bg-card)", border: "1px solid var(--border)", padding: "10px", borderRadius: "4px" }}>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "4px" }}>
                      <span className="entity-chip">
                        {ent.type === "ip" && <Globe size={11} />}
                        {ent.type === "host" && <Server size={11} />}
                        {ent.type === "user" && <User size={11} />}
                        <span>{ent.value}</span>
                      </span>

                      {ent.reputation && (
                        <span style={{ fontSize: "10px", fontWeight: 700, color: ent.reputation === "malicious" ? "#f43f5e" : ent.reputation === "suspicious" ? "#f97316" : "#94a3b8" }}>
                          {ent.reputation.toUpperCase()}
                        </span>
                      )}
                    </div>

                    {ent.details && (
                      <div style={{ fontSize: "11px", color: "var(--text-dim)", marginTop: "6px" }}>
                        {Object.entries(ent.details).map(([k, v]) => (
                          <div key={k}>
                            {k}: <span style={{ color: "var(--text-muted)" }}>{v}</span>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          </div>
        </main>
      </div>
    </div>
  );
}

export default App;
