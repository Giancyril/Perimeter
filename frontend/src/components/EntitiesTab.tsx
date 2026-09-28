import React from "react";
import { Server, User, Globe, Hash, Cpu, ShieldAlert } from "lucide-react";
import type { SecurityEntity } from "../types";

interface EntitiesTabProps {
  entities: SecurityEntity[];
}

export const EntitiesTab: React.FC<EntitiesTabProps> = ({ entities }) => {
  const getEntityIcon = (type: string) => {
    switch (type) {
      case "ip":
        return <Globe size={16} color="#38bdf8" />;
      case "host":
        return <Server size={16} color="#a78bfa" />;
      case "user":
        return <User size={16} color="#fbbf24" />;
      case "file_hash":
        return <Hash size={16} color="#f87171" />;
      case "process":
        return <Cpu size={16} color="#34d399" />;
      default:
        return <ShieldAlert size={16} color="var(--accent)" />;
    }
  };

  return (
    <div>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(320px, 1fr))", gap: "16px" }}>
        {entities.map((entity) => (
          <div key={entity.id} className="entity-card">
            <div className="entity-top">
              <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                {getEntityIcon(entity.type)}
                <div>
                  <span className="entity-chip">{entity.type.toUpperCase()}</span>
                  <div
                    className="mono"
                    style={{
                      fontSize: "13px",
                      fontWeight: 600,
                      color: "var(--text-primary)",
                      marginTop: "4px",
                      wordBreak: "break-all",
                    }}
                  >
                    {entity.value}
                  </div>
                </div>
              </div>

              {entity.reputation && (
                <span className={`rep-badge ${entity.reputation}`}>
                  {entity.reputation.toUpperCase()}
                </span>
              )}
            </div>

            {entity.details && Object.keys(entity.details).length > 0 && (
              <div className="entity-details">
                {Object.entries(entity.details).map(([key, val]) => (
                  <div key={key} style={{ display: "flex", justifyContent: "space-between", padding: "4px 0" }}>
                    <span className="entity-detail-key">{key}:</span>
                    <span className="entity-detail-val mono">{val}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
};
