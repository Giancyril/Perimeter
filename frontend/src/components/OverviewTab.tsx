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
    <div className="overview-grid">
      {/* ── Main column ── */}
      <div className="detail-main">

        {/* Severity & Scoring Card */}
        <div className="card">
          <div className="card-header">
            <div className="card-title">
              <Shield size={16} color="var(--accent)" />
              <span>Severity Score &amp; Safety Floor Enforcement</span>
            </div>
            <span className={`badge-sev ${incident.severity}`}>
              {incident.severity.toUpperCase()} &mdash; {score}/100
            </span>
          </div>

          <div className="card-body">
            <div style={{ display: "grid", gridTemplateColumns: "120px 1fr", gap: "20px", alignItems: "center" }}>
              {/* Score ring */}
              <div style={{ textAlign: "center" }}>
                <div className={`score-ring ${incident.severity}`}>
                  <span className="score-text">{score}</span>
                  <span className="score-label">Score</span>
                </div>
                <div style={{ marginTop: "8px", fontSize: "11px", color: "var(--text-muted)" }}>
                  Floor:{" "}
                  <strong style={{ color: "var(--accent)" }}>
                    {incident.deterministic_floor.toUpperCase()}
                  </strong>
                </div>
              </div>

              {/* Score breakdown bars */}
              <div>
                <div className="section-label">Scoring breakdown</div>
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
                      <span className="score-bar-val">{breakdown.base_score}</span>
                    </div>

                    {Object.entries(breakdown.multipliers).map(([rule, mult]) => (
                      <div key={rule} className="score-bar-row">
                        <span className="score-bar-label">{rule}</span>
                        <div className="score-bar-track">
                          <div
                            className="score-bar-fill"
                            style={{
                              width: `${Math.min(100, (mult as number) * 50)}%`,
                              background: (mult as number) > 1.2 ? "var(--sev-high)" : "var(--accent)",
                            }}
                          />
                        </div>
                        <span className="score-bar-val">&times;{mult as number}</span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div style={{ fontSize: "12px", color: "var(--text-muted)" }}>
                    Heuristic correlation index: {score}/100. Deterministic rule floor enforced.
                  </div>
                )}
              </div>
            </div>

            {/* Safety invariant note */}
            <div className="invariant-note">
              <Info size={15} style={{ flexShrink: 0, marginTop: "1px", color: "var(--accent)" }} />
              <div>
                <strong>Safety Invariant Enforced:</strong> The AI agent cannot lower severity
                below the <strong>{incident.deterministic_floor.toUpperCase()}</strong> floor without
                a signed human analyst override log.
              </div>
            </div>

            {/* AI Reasoning */}
            <div style={{ marginTop: "14px" }}>
              <div className="section-label">Agent investigation reasoning</div>
              <div className="llm-reasoning-box">{incident.llm_reasoning}</div>
            </div>
          </div>
        </div>

        {/* Recommended Actions */}
        <div className="card">
          <div className="card-header">
            <div className="card-title">
              <CheckCircle size={16} color="var(--accent)" />
              <span>Recommended Containment &amp; Remediation</span>
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
              <div style={{ color: "var(--text-muted)", fontSize: "13px", lineHeight: 1.7 }}>
                <div className="rec-action-item"><span className="rec-num">1</span><span>Inspect host authentication logs and verify active user sessions.</span></div>
                <div className="rec-action-item"><span className="rec-num">2</span><span>Verify perimeter firewall blocklist for inbound source IPs.</span></div>
                <div className="rec-action-item"><span className="rec-num">3</span><span>Perform memory and disk forensics if persistence artifacts are detected.</span></div>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* ── Aside column ── */}
      <div className="detail-aside">

        {/* Correlated Entities */}
        <div className="card">
          <div className="card-header">
            <div className="card-title">Correlated Entities</div>
            <span className="queue-count">{incident.entities.length}</span>
          </div>
          <div style={{ padding: "4px 12px 8px" }}>
            {incident.entities.map((e) => (
              <div
                key={e.id}
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "center",
                  padding: "7px 0",
                  borderBottom: "1px solid var(--border)",
                  gap: "8px",
                }}
              >
                <div style={{ display: "flex", alignItems: "center", gap: "6px", minWidth: 0 }}>
                  <span className={`entity-chip ${e.type}`}>{e.type}</span>
                  <span
                    className="mono"
                    style={{
                      fontSize: "11px",
                      color: "var(--text-secondary)",
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                      whiteSpace: "nowrap",
                    }}
                  >
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

        {/* Ingested SIEM Alerts */}
        <div className="card">
          <div className="card-header">
            <div className="card-title">SIEM Alerts</div>
            <span className="queue-count">{incident.alerts.length}</span>
          </div>
          <div style={{ padding: "4px 12px 8px" }}>
            {incident.alerts.length === 0 ? (
              <div style={{ color: "var(--text-dim)", fontSize: "12px", padding: "8px 0" }}>
                Correlated via multi-entity window
              </div>
            ) : (
              incident.alerts.map((alt) => (
                <div key={alt.id} className="alert-row" style={{ padding: "7px 0" }}>
                  <div className="alert-row-top">
                    <span className="alert-id">{alt.id}</span>
                    <span className={`badge-sev ${alt.raw_severity}`}>{alt.raw_severity}</span>
                  </div>
                  <div className="alert-title">{alt.title}</div>
                  <div style={{ display: "flex", gap: "6px", marginTop: "4px" }}>
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
