import React from "react";
import { Crosshair, FileWarning, ExternalLink } from "lucide-react";
import type { SecurityIncident } from "../types";

interface MitreIocTabProps {
  incident: SecurityIncident;
}

export const MitreIocTab: React.FC<MitreIocTabProps> = ({ incident }) => {
  const mitreCoverage = incident.report?.mitre_coverage || incident.techniques.map((t, idx) => ({
    tactic: incident.tactics[idx % incident.tactics.length] || "Lateral Movement",
    technique: t,
    technique_id: t.split(" - ")[0] || "T1000",
  }));

  const iocs = incident.report?.iocs || incident.entities.map((e) => ({
    type: e.type,
    value: e.value,
    context: e.reputation ? `Flagged as ${e.reputation}` : "Correlated entity",
  }));

  return (
    <div className="mitre-grid">
      {/* MITRE ATT&CK column */}
      <div className="card">
        <div className="card-header">
          <div className="card-title">
            <Crosshair size={16} color="var(--accent)" />
            <span>MITRE ATT&amp;CK Coverage</span>
          </div>
          <span className="queue-count">{mitreCoverage.length} techniques</span>
        </div>

        <div className="card-body">
          {mitreCoverage.map((item, idx) => (
            <div key={idx} className="mitre-technique-row">
              <div className="mitre-technique-top">
                <span className="mitre-id">{item.technique_id}</span>
                <div>
                  <div className="mitre-name">{item.technique}</div>
                  <div className="mitre-tactic">{item.tactic}</div>
                </div>
                <a
                  href={`https://attack.mitre.org/techniques/${item.technique_id.replace(".", "/")}`}
                  target="_blank"
                  rel="noreferrer"
                  style={{ color: "var(--text-dim)", marginLeft: "auto", display: "flex", alignItems: "center" }}
                  title="View on MITRE ATT&CK"
                >
                  <ExternalLink size={12} />
                </a>
              </div>
            </div>
          ))}

          {mitreCoverage.length === 0 && (
            <div style={{ color: "var(--text-muted)", fontSize: "13px" }}>No MITRE mappings available.</div>
          )}
        </div>
      </div>

      {/* IOC column */}
      <div className="card">
        <div className="card-header">
          <div className="card-title">
            <FileWarning size={16} color="var(--sev-critical)" />
            <span>Indicators of Compromise (IOCs)</span>
          </div>
          <span className="queue-count">{iocs.length} IOCs</span>
        </div>

        <div className="card-body">
          {iocs.map((ioc, idx) => (
            <div key={idx} className="ioc-row">
              <div style={{ flex: 1, minWidth: 0 }}>
                <div className="ioc-value">{ioc.value}</div>
                {ioc.context && (
                  <div style={{ fontSize: "10px", color: "var(--text-dim)", marginTop: "2px" }}>{ioc.context}</div>
                )}
              </div>
              <span className="ioc-type">{ioc.type}</span>
            </div>
          ))}

          {iocs.length === 0 && (
            <div style={{ color: "var(--text-muted)", fontSize: "13px" }}>No IOCs extracted.</div>
          )}
        </div>
      </div>
    </div>
  );
};
