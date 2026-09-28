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
    type: e.type.toUpperCase(),
    value: e.value,
    context: e.reputation ? `Flagged as ${e.reputation}` : "Correlated entity",
  }));

  return (
    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "16px" }}>
      {/* MITRE ATT&CK Tactics & Techniques */}
      <div className="card">
        <div className="card-header">
          <div className="card-title">
            <Crosshair size={16} color="var(--accent)" />
            <span>MITRE ATT&CK Framework Mapping</span>
          </div>
          <span className="queue-count mono">{mitreCoverage.length} Techniques</span>
        </div>

        <div className="card-body">
          <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
            {mitreCoverage.map((item, idx) => (
              <div key={idx} className="mitre-item">
                <div className="mitre-info">
                  <span className="mitre-tactic">{item.tactic}</span>
                  <div className="mitre-technique">{item.technique}</div>
                </div>
                <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
                  <span className="mitre-technique-id mono">{item.technique_id}</span>
                  <a
                    href={`https://attack.mitre.org/techniques/${item.technique_id.replace(".", "/")}`}
                    target="_blank"
                    rel="noreferrer"
                    style={{ color: "var(--text-dim)", display: "flex", alignItems: "center" }}
                    title="View on MITRE ATT&CK"
                  >
                    <ExternalLink size={12} />
                  </a>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Indicators of Compromise */}
      <div className="card">
        <div className="card-header">
          <div className="card-title">
            <FileWarning size={16} color="#f87171" />
            <span>Extracted Indicators of Compromise (IOCs)</span>
          </div>
          <span className="queue-count mono">{iocs.length} IOCs</span>
        </div>

        <div className="card-body">
          <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
            {iocs.map((ioc, idx) => (
              <div key={idx} className="ioc-item">
                <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "4px" }}>
                  <span className="ioc-type">{ioc.type}</span>
                  <span className="ioc-context">{ioc.context}</span>
                </div>
                <div className="ioc-value mono">{ioc.value}</div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};
