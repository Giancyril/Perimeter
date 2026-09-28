import React from "react";
import { Clock, Terminal, Activity, AlertTriangle, Zap } from "lucide-react";
import type { TimelineEvent } from "../types";

interface TimelineTabProps {
  timeline: TimelineEvent[];
}

export const TimelineTab: React.FC<TimelineTabProps> = ({ timeline }) => {
  const renderIcon = (type: string) => {
    switch (type) {
      case "alert":
        return <AlertTriangle size={14} />;
      case "tool_call":
        return <Terminal size={14} />;
      case "reasoning":
        return <Activity size={14} />;
      case "escalation":
      case "action":
        return <Zap size={14} />;
      default:
        return <Clock size={14} />;
    }
  };

  return (
    <div className="card">
      <div className="card-header">
        <div className="card-title">
          <Clock size={16} color="var(--accent)" />
          <span>Investigation Audit Trail & Agent Execution Trace</span>
        </div>
        <span className="queue-count mono">{timeline.length} Events</span>
      </div>

      <div className="card-body">
        <div className="timeline">
          {timeline.map((evt, idx) => (
            <div key={evt.id || idx} className="timeline-item">
              <div className="timeline-left">
                <div className={`tl-dot ${evt.type}`}>
                  {renderIcon(evt.type)}
                </div>
                {idx < timeline.length - 1 && <div className="tl-line" />}
              </div>

              <div className="timeline-body">
                <div className="tl-header">
                  <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                    <span className={`tl-type-badge ${evt.type}`}>
                      {evt.type.replace("_", " ").toUpperCase()}
                    </span>
                    <span className="tl-title">{evt.title}</span>
                  </div>
                  <span className="tl-time mono">{evt.timestamp}</span>
                </div>

                <div className="tl-summary">{evt.summary}</div>

                {evt.evidence_id && (
                  <div style={{ marginTop: "6px" }}>
                    <span className="tl-evidence-ref mono">Evidence: {evt.evidence_id}</span>
                  </div>
                )}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
