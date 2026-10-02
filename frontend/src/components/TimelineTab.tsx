import React from "react";
import { Clock, AlertTriangle, Terminal, Activity, Zap } from "lucide-react";
import type { TimelineEvent } from "../types";

interface TimelineTabProps {
  timeline: TimelineEvent[];
}

const EventIcon: React.FC<{ type: string }> = ({ type }) => {
  switch (type) {
    case "alert":     return <AlertTriangle size={14} />;
    case "tool_call": return <Terminal size={14} />;
    case "reasoning": return <Activity size={14} />;
    case "action":    return <Zap size={14} />;
    default:          return <Clock size={14} />;
  }
};

export const TimelineTab: React.FC<TimelineTabProps> = ({ timeline }) => {
  return (
    <div className="timeline-wrap">
      <div className="card" style={{ padding: 0, overflow: "hidden" }}>
        <div className="card-header">
          <div className="card-title">
            <Clock size={16} color="var(--accent)" />
            <span>Investigation Audit Trail &amp; Agent Execution Trace</span>
          </div>
          <span className="queue-count">{timeline.length} events</span>
        </div>

        <div style={{ padding: "16px" }}>
          {timeline.map((evt, idx) => (
            <div key={evt.id || idx} className="timeline-event">
              {/* Icon */}
              <div className={`timeline-icon ${evt.type}`}>
                <EventIcon type={evt.type} />
              </div>

              {/* Body */}
              <div className="timeline-body">
                <div className="timeline-ts">{evt.timestamp}</div>
                <div className="timeline-event-title">{evt.title}</div>
                <div className="timeline-event-summary">{evt.summary}</div>
                {evt.evidence_id && (
                  <div className="timeline-detail">Evidence ref: {evt.evidence_id}</div>
                )}
              </div>
            </div>
          ))}

          {timeline.length === 0 && (
            <div style={{ textAlign: "center", padding: "32px", color: "var(--text-muted)", fontSize: "13px" }}>
              No timeline events recorded yet.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
