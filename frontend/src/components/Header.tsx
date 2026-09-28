import React from "react";
import { ShieldAlert, RefreshCw } from "lucide-react";
import type { DashboardStats } from "../types";

interface HeaderProps {
  stats: DashboardStats;
  loading: boolean;
  onRefresh: () => void;
}

export const Header: React.FC<HeaderProps> = ({ stats, loading, onRefresh }) => {
  return (
    <header className="soc-header">
      <div className="brand">
        <div className="brand-logo">
          <ShieldAlert size={22} color="#00ffcc" />
        </div>
        <div>
          <div className="brand-name">
            AUTONOMOUS SECOPS AGENT
            <span className="brand-version">v1.0.0-prod</span>
          </div>
          <div style={{ fontSize: "11px", color: "var(--text-dim)", letterSpacing: "0.5px" }}>
            Real-Time AI Incident Triage ? Correlation ? HITL Response Gate
          </div>
        </div>
      </div>

      <div className="header-right">
        <div className="header-status">
          <span className="status-dot"></span>
          <span>LANGGRAPH AGENT ONLINE</span>
        </div>

        <div className="header-divider" />

        <div className="header-stat">
          <span className="header-stat-label">TOTAL INCIDENTS</span>
          <span className="header-stat-val mono">{stats.total}</span>
        </div>

        <div className="header-stat">
          <span className="header-stat-label">CRITICAL</span>
          <span className="header-stat-val mono text-critical">{stats.critical}</span>
        </div>

        <div className="header-stat">
          <span className="header-stat-label">HITL GATES</span>
          <span className="header-stat-val mono" style={{ color: "var(--sev-high)" }}>
            {stats.pending_approval}
          </span>
        </div>

        <div className="header-stat">
          <span className="header-stat-label">MTTR</span>
          <span className="header-stat-val mono" style={{ color: "#38bdf8" }}>
            {stats.mttr_minutes}m
          </span>
        </div>

        <button
          className="btn btn-ghost btn-sm"
          onClick={onRefresh}
          title="Refresh incidents and synchronize backend"
          disabled={loading}
          style={{ display: "flex", alignItems: "center", gap: "6px" }}
        >
          <RefreshCw size={14} className={loading ? "spinner" : ""} />
          <span>Sync</span>
        </button>
      </div>
    </header>
  );
};
