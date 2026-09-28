import React, { useState } from "react";
import { AlertTriangle, ShieldCheck, XCircle, RotateCcw, Check, Loader2 } from "lucide-react";
import type { ProposedAction } from "../types";

interface HitlActionBannerProps {
  action: ProposedAction;
  onApprove: (actionId: string, notes: string) => Promise<void>;
  onReject: (actionId: string, reason: string) => Promise<void>;
  onRollback?: (actionId: string) => Promise<void>;
}

export const HitlActionBanner: React.FC<HitlActionBannerProps> = ({
  action,
  onApprove,
  onReject,
  onRollback,
}) => {
  const [submitting, setSubmitting] = useState(false);
  const [rejectReason, setRejectReason] = useState("");
  const [showRejectModal, setShowRejectModal] = useState(false);

  const handleApprove = async () => {
    setSubmitting(true);
    try {
      await onApprove(action.action_id, "Approved by SOC Lead via dashboard gate");
    } finally {
      setSubmitting(false);
    }
  };

  const handleRejectConfirm = async () => {
    setSubmitting(true);
    try {
      await onReject(action.action_id, rejectReason || "Declined by analyst");
      setShowRejectModal(false);
    } finally {
      setSubmitting(false);
    }
  };

  const handleRollback = async () => {
    if (!onRollback) return;
    setSubmitting(true);
    try {
      await onRollback(action.action_id);
    } finally {
      setSubmitting(false);
    }
  };

  const formatActionName = (type: string) => {
    switch (type) {
      case "isolate_host":
        return "ISOLATE HOST FROM NETWORK";
      case "block_ip":
        return "BLOCK IP AT PERIMETER FIREWALL";
      case "disable_user":
        return "DISABLE USER & REVOKE ACTIVE SESSIONS";
      case "kill_process":
        return "TERMINATE MALICIOUS PROCESS";
      case "quarantine_file":
        return "QUARANTINE FILE HASH";
      default:
        return type.toUpperCase();
    }
  };

  return (
    <div className="hitl-banner">
      <div className="hitl-icon-wrap">
        {action.status === "approved" || action.status === "executed" ? (
          <ShieldCheck size={28} color="#00ffcc" />
        ) : action.status === "rejected" ? (
          <XCircle size={28} color="#ff3366" />
        ) : (
          <AlertTriangle size={28} color="#ffaa00" />
        )}
      </div>

      <div className="hitl-content">
        <div className="hitl-label">
          {action.status === "proposed"
            ? "?? HUMAN-IN-THE-LOOP CONTAINMENT GATE ? AUTHORIZATION REQUIRED"
            : action.status === "approved" || action.status === "executed"
            ? "? CONTAINMENT ACTION EXECUTED"
            : action.status === "rejected"
            ? "? CONTAINMENT ACTION REJECTED"
            : "? CONTAINMENT ACTION ROLLED BACK"}
        </div>

        <div className="hitl-action-line">
          <strong>{formatActionName(action.action_type)}:</strong>{" "}
          <span className="mono" style={{ color: "var(--accent)", fontWeight: 600 }}>
            {action.target}
          </span>
        </div>

        <div className="hitl-rationale">{action.rationale}</div>
      </div>

      <div className="hitl-buttons">
        {action.status === "proposed" && (
          <>
            <button
              className="btn btn-approve"
              onClick={handleApprove}
              disabled={submitting}
            >
              {submitting ? <Loader2 size={14} className="spinner" /> : <Check size={14} />}
              <span>Approve & Contain</span>
            </button>

            <button
              className="btn btn-reject"
              onClick={() => setShowRejectModal(true)}
              disabled={submitting}
            >
              <XCircle size={14} />
              <span>Reject</span>
            </button>
          </>
        )}

        {(action.status === "approved" || action.status === "executed") && (
          <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
            <span className="hitl-result-badge approved">ACTIVE ENFORCEMENT</span>
            {action.rollback_available && onRollback && (
              <button
                className="btn btn-ghost btn-sm"
                onClick={handleRollback}
                disabled={submitting}
                style={{ display: "flex", alignItems: "center", gap: "6px" }}
              >
                <RotateCcw size={12} />
                <span>Rollback</span>
              </button>
            )}
          </div>
        )}

        {action.status === "rejected" && (
          <span className="hitl-result-badge rejected">DECLINED BY ANALYST</span>
        )}

        {action.status === "rolled_back" && (
          <span className="hitl-result-badge rejected" style={{ borderColor: "#888", color: "#aaa" }}>
            REVERSED
          </span>
        )}
      </div>

      {/* Reject Modal */}
      {showRejectModal && (
        <div
          style={{
            position: "fixed",
            inset: 0,
            background: "rgba(0, 0, 0, 0.75)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            zIndex: 1000,
          }}
        >
          <div
            style={{
              background: "#161b22",
              border: "1px solid #30363d",
              borderRadius: "8px",
              padding: "24px",
              width: "420px",
              maxWidth: "90vw",
            }}
          >
            <h3 style={{ margin: "0 0 12px 0", color: "#f85149", display: "flex", alignItems: "center", gap: "8px" }}>
              <XCircle size={18} /> Reject Containment Action
            </h3>
            <p style={{ fontSize: "13px", color: "var(--text-secondary)", marginBottom: "14px" }}>
              Please specify the operational or investigation rationale for rejecting action on{" "}
              <strong>{action.target}</strong>:
            </p>
            <textarea
              rows={3}
              value={rejectReason}
              onChange={(e) => setRejectReason(e.target.value)}
              placeholder="e.g. Scheduled maintenance window, legitimate failover, or false positive test..."
              style={{
                width: "100%",
                boxSizing: "border-box",
                background: "#0d1117",
                border: "1px solid #30363d",
                borderRadius: "6px",
                color: "#c9d1d9",
                padding: "8px",
                fontSize: "12px",
                outline: "none",
                marginBottom: "16px",
              }}
            />
            <div style={{ display: "flex", justifyContent: "flex-end", gap: "10px" }}>
              <button
                className="btn btn-ghost btn-sm"
                onClick={() => setShowRejectModal(false)}
                disabled={submitting}
              >
                Cancel
              </button>
              <button
                className="btn btn-reject btn-sm"
                onClick={handleRejectConfirm}
                disabled={submitting}
              >
                {submitting ? "Rejecting..." : "Confirm Rejection"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
