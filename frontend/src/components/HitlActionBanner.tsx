import React, { useState } from "react";
import { AlertTriangle, ShieldCheck, XCircle, RotateCcw, Loader2 } from "lucide-react";
import type { ProposedAction } from "../types";

interface HitlActionBannerProps {
  action: ProposedAction;
  onApprove: (actionId: string, notes: string) => Promise<void>;
  onReject: (actionId: string, reason: string) => Promise<void>;
  onRollback?: (actionId: string) => Promise<void>;
}

const ACTION_NAMES: Record<string, string> = {
  isolate_host: "Isolate Host from Network",
  block_ip: "Block IP at Perimeter Firewall",
  disable_user: "Disable User & Revoke Active Sessions",
  kill_process: "Terminate Malicious Process",
  quarantine_file: "Quarantine File by Hash",
};

export const HitlActionBanner: React.FC<HitlActionBannerProps> = ({
  action,
  onApprove,
  onReject,
  onRollback,
}) => {
  const [submitting, setSubmitting] = useState(false);
  const [rejectReason, setRejectReason] = useState("");
  const [showRejectForm, setShowRejectForm] = useState(false);

  const handleApprove = async () => {
    setSubmitting(true);
    try { await onApprove(action.action_id, "Approved by SOC Lead via dashboard gate"); }
    finally { setSubmitting(false); }
  };

  const handleRejectConfirm = async () => {
    setSubmitting(true);
    try {
      await onReject(action.action_id, rejectReason || "Declined by analyst");
      setShowRejectForm(false);
    } finally { setSubmitting(false); }
  };

  const handleRollback = async () => {
    if (!onRollback) return;
    setSubmitting(true);
    try { await onRollback(action.action_id); }
    finally { setSubmitting(false); }
  };

  const isPending = action.status === "proposed";
  const isApproved = action.status === "approved" || action.status === "executed";
  const isRejected = action.status === "rejected";
  const isRolledBack = action.status === "rolled_back";

  const iconColor = isApproved ? "var(--action-approve)"
    : isRejected ? "var(--action-reject)"
      : "var(--hitl-accent)";

  const icon = isApproved ? <ShieldCheck size={18} color={iconColor} />
    : isRejected ? <XCircle size={18} color={iconColor} />
      : <AlertTriangle size={18} color={iconColor} />;

  return (
    <div className="hitl-banner">
      {/* Banner header */}
      <div className="hitl-banner-header">
        <div className="hitl-banner-title">
          <div className="hitl-icon-wrap">{icon}</div>
          <div>
            <div className="hitl-banner-label">
              {isPending ? "Human-in-the-Loop Containment Gate — Authorization Required"
                : isApproved ? "Containment Action Approved & Active"
                  : isRejected ? "Containment Action Declined"
                    : "Containment Action Reversed"}
            </div>
            <div className="hitl-banner-name">
              {ACTION_NAMES[action.action_type] ?? action.action_type}:{" "}
              <span className="mono">{action.target}</span>
            </div>
          </div>
        </div>
        {isPending && (
          <span className="hitl-risk-badge">High-Risk Action</span>
        )}
      </div>

      {/* Banner body */}
      <div className="hitl-banner-body">
        {/* Rationale */}
        <div className="hitl-command-box">{action.rationale}</div>

        {/* Meta */}
        <div className="hitl-meta-grid">
          <div className="hitl-meta-item">
            <span className="hitl-meta-label">Action Type</span>
            <span className="hitl-meta-val">{action.action_type}</span>
          </div>
          <div className="hitl-meta-item">
            <span className="hitl-meta-label">Target</span>
            <span className="hitl-meta-val mono">{action.target}</span>
          </div>
          <div className="hitl-meta-item">
            <span className="hitl-meta-label">Status</span>
            <span className="hitl-meta-val">{action.status}</span>
          </div>
          {action.rollback_available && (
            <div className="hitl-meta-item">
              <span className="hitl-meta-label">Rollback</span>
              <span className="hitl-meta-val" style={{ color: "var(--action-approve)" }}>Available</span>
            </div>
          )}
        </div>

        {/* Action buttons */}
        <div className="hitl-actions">
          {isPending && (
            <>
              <button className="btn btn-approve" onClick={handleApprove} disabled={submitting}>
                {submitting && <Loader2 size={14} className="spinner" />}
                <span>Approve & Contain</span>
              </button>
              <button
                className="btn btn-reject"
                onClick={() => setShowRejectForm((v) => !v)}
                disabled={submitting}
              >
                <span>Reject</span>
              </button>
            </>
          )}

          {isApproved && (
            <>
              <span className="hitl-result-badge approved">Active Enforcement</span>
              {action.rollback_available && onRollback && (
                <button className="btn btn-ghost btn-sm" onClick={handleRollback} disabled={submitting}>
                  <RotateCcw size={12} />
                  <span>Rollback</span>
                </button>
              )}
            </>
          )}

          {isRejected && (
            <span className="hitl-result-badge rejected">Declined by Analyst</span>
          )}

          {isRolledBack && (
            <span
              className="hitl-result-badge"
              style={{
                background: "var(--bg-hover)",
                color: "var(--text-muted)",
                border: "1px solid var(--border)",
              }}
            >
              Reversed
            </span>
          )}
        </div>

        {/* Inline reject form (no separate modal) */}
        {showRejectForm && isPending && (
          <div className="reject-form">
            <div style={{ fontSize: "12px", color: "var(--text-secondary)", marginBottom: "8px" }}>
              Provide a brief rationale for declining action on{" "}
              <strong className="mono">{action.target}</strong>:
            </div>
            <textarea
              className="reject-textarea"
              rows={3}
              value={rejectReason}
              onChange={(e) => setRejectReason(e.target.value)}
              placeholder="e.g. Scheduled maintenance window, legitimate failover, or false positive..."
            />
            <div style={{ display: "flex", justifyContent: "flex-end", gap: "8px" }}>
              <button
                className="btn btn-ghost btn-sm"
                onClick={() => setShowRejectForm(false)}
                disabled={submitting}
              >
                Cancel
              </button>
              <button
                className="btn btn-confirm-reject btn-sm"
                onClick={handleRejectConfirm}
                disabled={submitting}
              >
                {submitting ? "Rejecting..." : "Confirm Rejection"}
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
