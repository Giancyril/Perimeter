import React from "react";
import { Server, User, Globe, Hash, Cpu, ShieldAlert } from "lucide-react";
import type { SecurityEntity } from "../types";

interface EntitiesTabProps {
  entities: SecurityEntity[];
}

const ENTITY_ICON_COLOR: Record<string, string> = {
  ip:        "var(--sev-info)",
  host:      "var(--status-new)",
  user:      "var(--action-approve)",
  file_hash: "var(--sev-critical)",
  process:   "var(--sev-high)",
};

const EntityIcon: React.FC<{ type: string }> = ({ type }) => {
  const color = ENTITY_ICON_COLOR[type] ?? "var(--accent)";
  switch (type) {
    case "ip":        return <Globe size={16} color={color} />;
    case "host":      return <Server size={16} color={color} />;
    case "user":      return <User size={16} color={color} />;
    case "file_hash": return <Hash size={16} color={color} />;
    case "process":   return <Cpu size={16} color={color} />;
    default:          return <ShieldAlert size={16} color={color} />;
  }
};

export const EntitiesTab: React.FC<EntitiesTabProps> = ({ entities }) => {
  return (
    <div className="entities-grid">
      {entities.map((entity) => (
        <div key={entity.id} className="entity-card">
          <div className="entity-card-top">
            <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
              <EntityIcon type={entity.type} />
              <span className={`entity-chip ${entity.type}`}>{entity.type}</span>
            </div>
            {entity.reputation && (
              <span className={`rep-badge ${entity.reputation}`}>{entity.reputation}</span>
            )}
          </div>

          <div className="entity-value">{entity.value}</div>

          {entity.details && Object.keys(entity.details).length > 0 && (
            <div className="entity-meta-row">
              {Object.entries(entity.details).map(([key, val]) => (
                <div key={key} className="entity-meta-line">
                  <span className="entity-meta-k">{key}</span>
                  <span className="entity-meta-v mono">{String(val)}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      ))}

      {entities.length === 0 && (
        <div style={{ gridColumn: "1/-1", textAlign: "center", padding: "40px", color: "var(--text-muted)" }}>
          No entities extracted for this incident.
        </div>
      )}
    </div>
  );
};
