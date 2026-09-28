import React, { useState, useEffect, useCallback, useMemo } from "react";
import {
  ShieldAlert,
  Activity,
  User,
  Server,
  Crosshair,
  FileText,
  Clock,
  Layers,
} from "lucide-react";
import type { SecurityIncident, DashboardStats } from "./types";
import { MOCK_INCIDENTS } from "./mockData";
import {
  fetchIncidents,
  approveContainmentAction,
  rejectContainmentAction,
  rollbackContainmentAction,
} from "./api";
import { Header } from "./components/Header";
import { QueueSidebar } from "./components/QueueSidebar";
import { HitlActionBanner } from "./components/HitlActionBanner";
import { OverviewTab } from "./components/OverviewTab";
import { TimelineTab } from "./components/TimelineTab";
import { EntitiesTab } from "./components/EntitiesTab";
import { MitreIocTab } from "./components/MitreIocTab";
import { ReportTab } from "./components/ReportTab";

type TabKey = "overview" | "timeline" | "entities" | "mitre" | "report";

export const App: React.FC = () => {
  const [incidents, setIncidents] = useState<SecurityIncident[]>(MOCK_INCIDENTS);
  const [selectedId, setSelectedId] = useState<string | null>(MOCK_INCIDENTS[0]?.id || null);
  const [activeTab, setActiveTab] = useState<TabKey>("overview");
  const [loading, setLoading] = useState(false);

  // Load incidents from API or fallback
  const loadData = useCallback(async () => {
    setLoading(true);
    try {
      const data = await fetchIncidents();
      setIncidents(data);
      if (data.length > 0 && !selectedId) {
        setSelectedId(data[0].id);
      }
    } finally {
      setLoading(false);
    }
  }, [selectedId]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  // Selected incident reference
  const selectedIncident = useMemo(() => {
    return incidents.find((i) => i.id === selectedId) || null;
  }, [incidents, selectedId]);

  // Compute live dashboard stats
  const stats: DashboardStats = useMemo(() => {
    const total = incidents.length;
    const critical = incidents.filter((i) => i.severity === "critical").length;
    const pending_approval = incidents.filter((i) => i.status === "pending_approval").length;
    return {
      total,
      critical,
      pending_approval,
      mttr_minutes: 4.2,
    };
  }, [incidents]);

  // Action handlers with audit timeline appending
  const handleApprove = async (actionId: string, notes: string) => {
    if (!selectedIncident) return;
    await approveContainmentAction(selectedIncident.id, actionId, "analyst.giancyril", notes);

    const now = new Date().toLocaleTimeString("en-US", { hour12: false });
    setIncidents((prev) =>
      prev.map((inc) => {
        if (inc.id === selectedIncident.id) {
          const updatedAction = inc.proposed_action
            ? { ...inc.proposed_action, status: "approved" as const, executed_at: now, executed_by: "analyst.giancyril" }
            : undefined;
          return {
            ...inc,
            status: "active",
            proposed_action: updatedAction,
            timeline: [
              ...inc.timeline,
              {
                id: `tl-appr-${Date.now()}`,
                timestamp: now,
                type: "action",
                title: "Containment Action Approved & Executed",
                summary: `Human Analyst authorized: ${inc.proposed_action?.action_type} on ${inc.proposed_action?.target}. System enforcement completed.`,
                evidence_id: "AUDIT-SIGNOFF",
              },
            ],
          };
        }
        return inc;
      })
    );
  };

  const handleReject = async (actionId: string, reason: string) => {
    if (!selectedIncident) return;
    await rejectContainmentAction(selectedIncident.id, actionId, "analyst.giancyril", reason);

    const now = new Date().toLocaleTimeString("en-US", { hour12: false });
    setIncidents((prev) =>
      prev.map((inc) => {
        if (inc.id === selectedIncident.id) {
          const updatedAction = inc.proposed_action
            ? { ...inc.proposed_action, status: "rejected" as const }
            : undefined;
          return {
            ...inc,
            status: "investigating",
            proposed_action: updatedAction,
            timeline: [
              ...inc.timeline,
              {
                id: `tl-rej-${Date.now()}`,
                timestamp: now,
                type: "action",
                title: "Containment Action Declined by Analyst",
                summary: `Analyst rejected proposed action. Rationale: "${reason}"`,
              },
            ],
          };
        }
        return inc;
      })
    );
  };

  const handleRollback = async (actionId: string) => {
    if (!selectedIncident) return;
    await rollbackContainmentAction(selectedIncident.id, actionId, "analyst.giancyril");

    const now = new Date().toLocaleTimeString("en-US", { hour12: false });
    setIncidents((prev) =>
      prev.map((inc) => {
        if (inc.id === selectedIncident.id) {
          const updatedAction = inc.proposed_action
            ? { ...inc.proposed_action, status: "rolled_back" as const }
            : undefined;
          return {
            ...inc,
            proposed_action: updatedAction,
            timeline: [
              ...inc.timeline,
              {
                id: `tl-rb-${Date.now()}`,
                timestamp: now,
                type: "action",
                title: "Containment Action Rolled Back",
                summary: `Analyst initiated rollback for ${inc.proposed_action?.action_type} on ${inc.proposed_action?.target}. Target restored to previous network policy.`,
              },
            ],
          };
        }
        return inc;
      })
    );
  };

  return (
    <div className="app-shell">
      <Header stats={stats} loading={loading} onRefresh={loadData} />

      <div className="soc-body">
        {/* Left column: Incident Queue Sidebar */}
        <QueueSidebar
          incidents={incidents}
          selectedId={selectedId}
          onSelect={(inc) => setSelectedId(inc.id)}
        />

        {/* Right column: Incident Details & Workbench */}
        <main className="detail-panel">
          {!selectedIncident ? (
            <div className="empty-state">
              <div className="empty-state-icon">
                <ShieldAlert size={48} color="var(--accent)" />
              </div>
              <div className="empty-state-text">No Incident Selected</div>
              <div className="empty-state-sub">
                Select an incident from the queue to inspect correlated evidence, agent traces, and execute HITL containment.
              </div>
            </div>
          ) : (
            <>
              {/* Incident Header */}
              <div className="incident-header">
                <div className="incident-header-top">
                  <div className="incident-id-row">
                    <span className="incident-id mono">{selectedIncident.id}</span>
                    <span className={`badge-sev ${selectedIncident.severity}`}>
                      {selectedIncident.severity.toUpperCase()}
                    </span>
                    <span className={`badge-status ${selectedIncident.status}`}>
                      {selectedIncident.status === "pending_approval"
                        ? "HITL GATE REQUIRED"
                        : selectedIncident.status.toUpperCase()}
                    </span>
                  </div>

                  <div className="incident-meta-row">
                    <div className="incident-meta-item">
                      <User size={13} />
                      <span>{selectedIncident.owner}</span>
                    </div>
                    <div className="incident-meta-item">
                      <Clock size={13} />
                      <span className="mono">Updated {selectedIncident.updated_at}</span>
                    </div>
                    <div className="incident-meta-item">
                      <Layers size={13} />
                      <span>{selectedIncident.alert_count} Raw Alerts</span>
                    </div>
                  </div>
                </div>

                <h1 className="incident-title">{selectedIncident.title}</h1>

                {/* MITRE Tactic Tags */}
                <div className="tactic-strip">
                  {selectedIncident.tactics.map((tac) => (
                    <span key={tac} className="tactic-tag">
                      {tac}
                    </span>
                  ))}
                  {selectedIncident.techniques.map((tech) => (
                    <span key={tech} className="technique-tag mono">
                      {tech}
                    </span>
                  ))}
                </div>
              </div>

              {/* Phase 6 HITL Containment Gate Banner */}
              {selectedIncident.proposed_action && (
                <HitlActionBanner
                  action={selectedIncident.proposed_action}
                  onApprove={handleApprove}
                  onReject={handleReject}
                  onRollback={handleRollback}
                />
              )}

              {/* Navigation Tabs */}
              <nav className="tab-bar">
                <button
                  className={`tab-btn ${activeTab === "overview" ? "active" : ""}`}
                  onClick={() => setActiveTab("overview")}
                >
                  <Activity size={14} />
                  <span>Overview & Scoring</span>
                </button>

                <button
                  className={`tab-btn ${activeTab === "timeline" ? "active" : ""}`}
                  onClick={() => setActiveTab("timeline")}
                >
                  <Clock size={14} />
                  <span>Timeline & Agent Trace</span>
                  <span className="tab-count mono">{selectedIncident.timeline.length}</span>
                </button>

                <button
                  className={`tab-btn ${activeTab === "entities" ? "active" : ""}`}
                  onClick={() => setActiveTab("entities")}
                >
                  <Server size={14} />
                  <span>Correlated Entities</span>
                  <span className="tab-count mono">{selectedIncident.entities.length}</span>
                </button>

                <button
                  className={`tab-btn ${activeTab === "mitre" ? "active" : ""}`}
                  onClick={() => setActiveTab("mitre")}
                >
                  <Crosshair size={14} />
                  <span>MITRE ATT&CK & IOCs</span>
                </button>

                <button
                  className={`tab-btn ${activeTab === "report" ? "active" : ""}`}
                  onClick={() => setActiveTab("report")}
                >
                  <FileText size={14} />
                  <span>Reports & Signoff</span>
                </button>
              </nav>

              {/* Tab Content Panel */}
              <div style={{ minHeight: "400px" }}>
                {activeTab === "overview" && <OverviewTab incident={selectedIncident} />}
                {activeTab === "timeline" && <TimelineTab timeline={selectedIncident.timeline} />}
                {activeTab === "entities" && <EntitiesTab entities={selectedIncident.entities} />}
                {activeTab === "mitre" && <MitreIocTab incident={selectedIncident} />}
                {activeTab === "report" && <ReportTab incident={selectedIncident} />}
              </div>
            </>
          )}
        </main>
      </div>
    </div>
  );
};

export default App;
