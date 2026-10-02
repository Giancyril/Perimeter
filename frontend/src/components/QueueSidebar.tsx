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
            <span>Incident Queue</span>
          </div>
          <span className="queue-count">{filteredIncidents.length}</span>
        </div>

        {/* Severity filter pills */}
        <div className="filter-row">
          {(["all", "critical", "high", "medium", "low"] as const).map((sev) => (
            <button
              key={sev}
              className={`filter-pill ${sev !== "all" ? sev : ""} ${sevFilter === sev ? "active" : ""}`}
              onClick={() => setSevFilter(sev)}
            >
              {sev.charAt(0).toUpperCase() + sev.slice(1)}
            </button>
          ))}
        </div>

        {/* Search */}
        <div className="queue-search-wrap">
          <Search size={14} />
          <input
            type="text"
            className="queue-search"
            placeholder="Search incident, IP, host..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
          />
        </div>
      </div>

      <div className="queue-list">
        {filteredIncidents.length === 0 ? (
          <div style={{ padding: "30px 20px", textAlign: "center", color: "var(--text-dim)" }}>
            <AlertCircle size={24} style={{ margin: "0 auto 8px auto", display: "block", opacity: 0.5 }} />
            <div style={{ fontSize: "12px" }}>No matching incidents</div>
          </div>
        ) : (
          filteredIncidents.map((inc) => {
            const isSelected = inc.id === selectedId;
            return (
              <div
                key={inc.id}
                className={`queue-item ${isSelected ? "selected" : ""} ${inc.severity}`}
                onClick={() => onSelect(inc)}
              >
                <div className="qi-top">
                  <span className="qi-id">{inc.id}</span>
                  <div style={{ display: "flex", gap: "4px", alignItems: "center" }}>
                    <span className={`badge-sev ${inc.severity}`}>{inc.severity}</span>
                    {inc.status === "pending_approval" && (
                      <span className="badge-status pending_approval" style={{ fontSize: "9px" }}>HITL</span>
                    )}
                  </div>
                </div>

                <div className="qi-title">{inc.title}</div>

                <div className="qi-bottom">
                  <div className="qi-meta">
                    <span>{inc.alert_count} alerts</span>
                    <span>&middot;</span>
                    <span>Score {inc.deterministic_score}</span>
                  </div>
                  {inc.tactics.length > 0 && (
                    <span
                      className="tactic-tag"
                      style={{ fontSize: "9px", padding: "2px 6px" }}
                    >
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
