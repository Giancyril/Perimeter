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
          <ShieldAlert size={20} color="var(--accent)" />
        </div>
        <div>
          <div className="brand-name">
            Autonomous SecOps Agent
            <span className="brand-version">v1.0.0</span>
          </div>
          <div className="brand-tagline">
            AI Incident Triage &bull; Correlation &bull; HITL Response Gate
          </div>
        </div>
      </div>

      <div className="header-right">
        <div className="header-status">
          <span className="status-dot" />
          <span>Agent Online</span>
        </div>

        <div className="header-divider" />

        <div className="header-stat">
          <span className="header-stat-label">Total</span>
          <span className="header-stat-val">{stats.total}</span>
        </div>

        <div className="header-stat">
          <span className="header-stat-label">Critical</span>
          <span className="header-stat-val text-critical">{stats.critical}</span>
        </div>

        <div className="header-stat">
          <span className="header-stat-label">HITL Gates</span>
          <span className="header-stat-val" style={{ color: "var(--hitl-accent)" }}>
            {stats.pending_approval}
          </span>
        </div>

        <div className="header-stat">
          <span className="header-stat-label">MTTR</span>
          <span className="header-stat-val" style={{ color: "var(--accent)" }}>
            {stats.mttr_minutes}m
          </span>
        </div>

        <button
          className="btn btn-ghost btn-sm"
          onClick={onRefresh}
          title="Refresh incidents"
          disabled={loading}
        >
          <RefreshCw size={14} className={loading ? "spinner" : ""} />
          <span>Sync</span>
        </button>
      </div>
    </header>
  );
};
