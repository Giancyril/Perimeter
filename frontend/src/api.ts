import type { SecurityIncident, ProposedAction } from "./types";
import { MOCK_INCIDENTS } from "./mockData";

const API_BASE = "http://localhost:8000/api/v1";

export async function fetchIncidents(): Promise<SecurityIncident[]> {
  try {
    const res = await fetch(`${API_BASE}/incidents`, { signal: AbortSignal.timeout(2000) });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    if (Array.isArray(data) && data.length > 0) {
      return data;
    }
    return MOCK_INCIDENTS;
  } catch (err) {
    console.warn("Backend API not reachable or empty, running in offline/demo mode:", err);
    return MOCK_INCIDENTS;
  }
}

export async function approveContainmentAction(
  incidentId: string,
  actionId: string,
  analystId: string = "analyst.giancyril",
  notes: string = "Authorized via SOC Dashboard human-in-the-loop gate"
): Promise<ProposedAction | null> {
  try {
    const res = await fetch(`${API_BASE}/incidents/${incidentId}/actions/${actionId}/approve`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ analyst_id: analystId, notes }),
      signal: AbortSignal.timeout(3000)
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  } catch (err) {
    console.warn("Approve API call failed, falling back to local state:", err);
    return null;
  }
}

export async function rejectContainmentAction(
  incidentId: string,
  actionId: string,
  analystId: string = "analyst.giancyril",
  reason: string = "Declined by human analyst - false positive or operational conflict"
): Promise<ProposedAction | null> {
  try {
    const res = await fetch(`${API_BASE}/incidents/${incidentId}/actions/${actionId}/reject`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ analyst_id: analystId, reason, notes: reason }),
      signal: AbortSignal.timeout(3000)
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  } catch (err) {
    console.warn("Reject API call failed, falling back to local state:", err);
    return null;
  }
}

export async function rollbackContainmentAction(
  incidentId: string,
  actionId: string,
  analystId: string = "analyst.giancyril"
): Promise<ProposedAction | null> {
  try {
    const res = await fetch(`${API_BASE}/incidents/${incidentId}/actions/${actionId}/rollback`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ analyst_id: analystId }),
      signal: AbortSignal.timeout(3000)
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  } catch (err) {
    console.warn("Rollback API call failed, falling back to local state:", err);
    return null;
  }
}

export function getReportDownloadUrl(incidentId: string, format: "pdf" | "markdown"): string {
  return `${API_BASE}/incidents/${incidentId}/report/${format}`;
}
