import React from "react";
import { Shield, CheckCircle, Info } from "lucide-react";
import type { SecurityIncident } from "../types";

interface OverviewTabProps {
  incident: SecurityIncident;
}

export const OverviewTab: React.FC<OverviewTabProps> = ({ incident }) => {
  const breakdown = incident.scoring_breakdown;
  const score = incident.deterministic_score;

  return (
    <div className="detail-content">
      <div className="detail-main">
        {/* Severity & Deterministic Floor Card */}
        <div className="card mb-12">
          <div className="card-header">
            <div className="card-title">
              <Shield size={16} color="var(--accent)" />
              <span>Hybrid Severity Engine & Deterministic Floor Enforcement</span>
            </div>
            <span className={`badge-sev ${incident.severity}`}>
              Final: {incident.severity.toUpperCase()} ({score}/100)
            </span>
          </div>

          <div className="card-body">
            <div style={{ display: "grid", gridTemplateColumns: "140px 1fr", gap: "20px", alignItems: "center" }}>
              {/* Score visual ring */}
              <div style={{ textAlign: "center" }}>
                <div className="score-ring">
                  <span className="score-text mono">{score}</span>
                  <span className="score-label">INDEX</span>
                </div>
                <div style={{ marginTop: "8px", fontSize: "11px", color: "var(--text-dim)" }}>
                  Floor: <strong style={{ color: "var(--accent)" }}>{incident.deterministic_floor.toUpperCase()}</strong>
                </div>
              </div>

              {/* Multipliers & Rules */}
              <div>
                <div style={{ fontSize: "12px", color: "var(--text-secondary)", marginBottom: "8px" }}>
                  Deterministic Scoring Calculation:
                </div>
                {breakdown ? (
                  <div>
                    <div className="score-bar-row">
                      <span className="score-bar-label">Base Anomaly Score</span>
                      <div className="score-bar-track">
                        <div
                          className="score-bar-fill"
                          style={{ width: `${Math.min(100, breakdown.base_score)}%` }}
                        />
                      </div>
                      <span className="score-bar-val mono">{breakdown.base_score}</span>
                    </div>

                    {Object.entries(breakdown.multipliers).map(([rule, mult]) => (
                      <div key={rule} className="score-bar-row">
                        <span className="score-bar-label">{rule}</span>
                        <div className="score-bar-track">
                          <div
                            className="score-bar-fill"
                            style={{
                              width: `${Math.min(100, mult * 50)}%`,
                              background: mult > 1.2 ? "var(--sev-high)" : "var(--accent)",
                            }}
                          />
                        </div>
                        <span className="score-bar-val mono">?{mult}</span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div style={{ fontSize: "12px", color: "var(--text-dim)" }}>
                    Base heuristic correlation index: {score} / 100. Deterministic rule floor enforced.
                  </div>
                )}
              </div>
            </div>

            {/* Invariant guarantee note */}
            <div
              style={{
                marginTop: "16px",
                padding: "10px 12px",
                background: "rgba(0, 255, 204, 0.05)",
                borderLeft: "3px solid var(--accent)",
                borderRadius: "4px",
                fontSize: "12px",
                color: "var(--text-secondary)",
                display: "flex",
                gap: "8px",
              }}
            >
              <Info size={16} color="var(--accent)" style={{ flexShrink: 0, marginTop: "2px" }} />
              <div>
                <strong>Safety Invariant Enforced:</strong> The LLM is strictly prohibited from lowering
                the severity below the <strong>{incident.deterministic_floor.toUpperCase()}</strong> floor
                without a signed human analyst override log.
              </div>
            </div>

            {/* LLM Reasoning Narrative */}
            <div style={{ marginTop: "16px" }}>
              <div style={{ fontSize: "11px", fontWeight: 600, color: "var(--text-dim)", marginBottom: "6px" }}>
                AI INVESTIGATION AGENT REASONING
              </div>
              <div className="llm-reasoning-box">{incident.llm_reasoning}</div>
            </div>
          </div>
        </div>

        {/* Recommended Actions */}
        <div className="card">
          <div className="card-header">
            <div className="card-title">
              <CheckCircle size={16} color="#38bdf8" />
              <span>Recommended Containment & Remediation Actions</span>
            </div>
          </div>
          <div className="card-body">
            {incident.report?.recommended_actions && incident.report.recommended_actions.length > 0 ? (
              incident.report.recommended_actions.map((rec, i) => (
                <div key={i} className="rec-action-item">
                  <span className="rec-num">{i + 1}</span>
                  <span>{rec}</span>
                </div>
              ))
            ) : (
              <div style={{ color: "var(--text-dim)", fontSize: "13px" }}>
                1. Inspect host authentication logs and verify active user sessions.
                <br />
                2. Verify perimeter firewall blocklist for inbound source IPs.
                <br />
                3. Perform memory and disk forensics if persistence artifacts are detected.
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Aside: Key Entities & Ingested Alerts */}
      <div className="detail-aside">
        <div className="card mb-12">
          <div className="card-header">
            <div className="card-title">
              <span>Correlated Entities</span>
            </div>
            <span className="queue-count mono">{incident.entities.length}</span>
          </div>
          <div className="card-body" style={{ padding: "8px 12px" }}>
            {incident.entities.map((e) => (
              <div
                key={e.id}
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "center",
                  padding: "8px 0",
                  borderBottom: "1px solid var(--border-color)",
                }}
              >
                <div>
                  <span className="entity-chip">{e.type.toUpperCase()}</span>
                  <span className="mono" style={{ fontSize: "12px", marginLeft: "6px", color: "var(--text-primary)" }}>
                    {e.value}
                  </span>
                </div>
                {e.reputation && (
                  <span className={`rep-badge ${e.reputation}`}>{e.reputation}</span>
                )}
              </div>
            ))}
          </div>
        </div>

        <div className="card">
          <div className="card-header">
            <div className="card-title">
              <span>Ingested SIEM Alerts</span>
            </div>
            <span className="queue-count mono">{incident.alerts.length}</span>
          </div>
          <div className="card-body" style={{ padding: "8px 12px" }}>
            {incident.alerts.length === 0 ? (
              <div style={{ color: "var(--text-dim)", fontSize: "12px", padding: "8px 0" }}>
                Correlated via multi-entity window
              </div>
            ) : (
              incident.alerts.map((alt) => (
                <div key={alt.id} className="alert-row" style={{ padding: "8px 0" }}>
                  <div className="alert-row-top">
                    <span className="alert-id mono">{alt.id}</span>
                    <span className={`badge-sev ${alt.raw_severity}`}>{alt.raw_severity}</span>
                  </div>
                  <div className="alert-title">{alt.title}</div>
                  <div style={{ display: "flex", gap: "8px", marginTop: "4px" }}>
                    <span className="alert-source">{alt.source}</span>
                    {alt.tactic && <span className="alert-tactic">{alt.tactic}</span>}
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
