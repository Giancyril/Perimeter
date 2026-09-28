import React, { useState, useMemo } from "react";
import { Search, AlertCircle, Shield } from "lucide-react";
import type { SecurityIncident, SeverityLevel } from "../types";

interface QueueSidebarProps {
  incidents: SecurityIncident[];
  selectedId: string | null;
  onSelect: (incident: SecurityIncident) => void;
}

export const QueueSidebar: React.FC<QueueSidebarProps> = ({
  incidents,
  selectedId,
  onSelect,
}) => {
  const [sevFilter, setSevFilter] = useState<SeverityLevel | "all">("all");
  const [searchQuery, setSearchQuery] = useState("");

  const filteredIncidents = useMemo(() => {
    return incidents.filter((inc) => {
      const matchSev = sevFilter === "all" || inc.severity === sevFilter;
      const q = searchQuery.toLowerCase().trim();
      const matchQuery =
        !q ||
        inc.id.toLowerCase().includes(q) ||
        inc.title.toLowerCase().includes(q) ||
        inc.entities.some((e) => e.value.toLowerCase().includes(q)) ||
        inc.tactics.some((t) => t.toLowerCase().includes(q));
      return matchSev && matchQuery;
    });
  }, [incidents, sevFilter, searchQuery]);

  return (
    <aside className="queue-sidebar">
      <div className="queue-header">
        <div className="queue-title-row">
          <div className="queue-title">
            <Shield size={16} color="var(--accent)" />
            <span>INCIDENT QUEUE</span>
          </div>
          <span className="queue-count mono">{filteredIncidents.length}</span>
        </div>

        {/* Severity filter pills */}
        <div className="filter-row">
          {(["all", "critical", "high", "medium", "low"] as const).map((sev) => (
            <button
              key={sev}
              className={`filter-pill ${sevFilter === sev ? "active" : ""}`}
              onClick={() => setSevFilter(sev)}
            >
              {sev.toUpperCase()}
            </button>
          ))}
        </div>

        {/* Search Input */}
        <div style={{ position: "relative", marginTop: "10px" }}>
          <Search
            size={14}
            style={{
              position: "absolute",
              left: "10px",
              top: "50%",
              transform: "translateY(-50%)",
              color: "var(--text-dim)",
            }}
          />
          <input
            type="text"
            placeholder="Search incident, IP, host, CVE..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            style={{
              width: "100%",
              boxSizing: "border-box",
              padding: "7px 10px 7px 32px",
              fontSize: "12px",
              background: "rgba(0,0,0,0.4)",
              border: "1px solid var(--border-color)",
              borderRadius: "6px",
              color: "var(--text-primary)",
              outline: "none",
            }}
          />
        </div>
      </div>

      <div className="queue-list">
        {filteredIncidents.length === 0 ? (
          <div style={{ padding: "30px 20px", textAlign: "center", color: "var(--text-dim)" }}>
            <AlertCircle size={24} style={{ margin: "0 auto 8px auto", opacity: 0.5 }} />
            <div style={{ fontSize: "12px" }}>No matching incidents found</div>
          </div>
        ) : (
          filteredIncidents.map((inc) => {
            const isSelected = inc.id === selectedId;
            return (
              <div
                key={inc.id}
                className={`queue-item ${isSelected ? "selected" : ""}`}
                onClick={() => onSelect(inc)}
              >
                <div className="qi-top">
                  <span className="qi-id mono">{inc.id}</span>
                  <div style={{ display: "flex", gap: "6px" }}>
                    <span className={`badge-sev ${inc.severity}`}>{inc.severity}</span>
                    <span className={`badge-status ${inc.status}`}>
                      {inc.status === "pending_approval" ? "HITL Gate" : inc.status}
                    </span>
                  </div>
                </div>

                <div className="qi-title">{inc.title}</div>

                <div className="qi-bottom">
                  <div className="qi-meta">
                    <span>{inc.alert_count} alerts</span>
                    <span>?</span>
                    <span>Score {inc.deterministic_score}</span>
                    <span>?</span>
                    <span>{inc.updated_at.split("T")[1]?.slice(0, 5) || "recent"}</span>
                  </div>

                  {inc.tactics.length > 0 && (
                    <span className="tactic-tag" style={{ fontSize: "10px", padding: "2px 6px" }}>
                      {inc.tactics[0]}
                    </span>
                  )}
                </div>
              </div>
            );
          })
        )}
      </div>
    </aside>
  );
};
