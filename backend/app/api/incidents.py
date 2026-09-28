"""
Incidents REST API.
Exposes endpoints for querying correlated security incidents produced by the CorrelationEngine.
All severity data returned is the deterministic floor; LLM-raised severity is handled by the
Investigation Agent (Phase 3 & 4) and stored in a separate field -- never replaces the floor.
Phase 5 introduces evidence-linked structured reports with Markdown & PDF export.
"""
from typing import Dict, Any, Optional
from fastapi import APIRouter, HTTPException, Path, Query, Response, status
from backend.correlation import correlation_engine, CorrelatedIncident, IncidentStatus
from backend.ingestion.models import SeverityLevel
from backend.reporting import render_pdf, render_markdown

router = APIRouter(prefix="/incidents", tags=["incidents"])

# In-memory investigation results cache (keyed by incident_id)
_investigation_cache: Dict[str, dict] = {}


def _get_or_run_investigation(incident_id: str) -> dict:
    """Helper to fetch an existing investigation state or trigger a new one."""
    incident = correlation_engine.get_incident(incident_id)
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{incident_id}' not found",
        )
    if incident_id in _investigation_cache:
        return _investigation_cache[incident_id]

    from backend.agent import investigate_incident
    result = investigate_incident(incident_id)
    if result.get("error"):
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=result["error"],
        )
    _investigation_cache[incident_id] = result
    return result


@router.get(
    "/",
    response_model=Dict[str, Any],
    summary="List correlated security incidents with optional filtering",
)
async def list_incidents(
    limit: int = Query(50, ge=1, le=500),
    severity: Optional[SeverityLevel] = Query(None, description="Filter by deterministic severity floor"),
    status_filter: Optional[IncidentStatus] = Query(None, alias="status", description="Filter by incident status"),
    tactic: Optional[str] = Query(None, description="Filter by MITRE ATT&CK tactic name"),
):
    incidents = correlation_engine.list_incidents(
        limit=limit,
        severity=severity,
        status=status_filter,
        tactic=tactic,
    )
    return {
        "incidents": [inc.model_dump(exclude={"alerts"}) for inc in incidents],
        "count": len(incidents),
    }


@router.get(
    "/stats",
    summary="Get high-level incident statistics",
)
async def get_incident_stats():
    incidents = correlation_engine.list_incidents(limit=10_000)
    by_severity: Dict[str, int] = {sev.value: 0 for sev in SeverityLevel}
    by_status: Dict[str, int] = {s.value: 0 for s in IncidentStatus}
    total_alerts = 0
    for inc in incidents:
        by_severity[inc.severity.value] += 1
        by_status[inc.status.value] += 1
        total_alerts += inc.alert_count
    return {
        "total_incidents": len(incidents),
        "total_alerts_correlated": total_alerts,
        "by_severity": by_severity,
        "by_status": by_status,
    }


@router.get(
    "/{incident_id}",
    response_model=CorrelatedIncident,
    summary="Get full incident details including all correlated alert payloads",
)
async def get_incident(incident_id: str = Path(..., description="Incident ID (e.g. INC-2026-0001)")):
    incident = correlation_engine.get_incident(incident_id)
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{incident_id}' not found",
        )
    return incident


@router.patch(
    "/{incident_id}/status",
    response_model=CorrelatedIncident,
    summary="Update incident lifecycle status (new -> active -> investigating -> resolved / closed)",
)
async def update_incident_status(
    incident_id: str = Path(..., description="Incident ID"),
    new_status: IncidentStatus = Query(..., description="New lifecycle status"),
):
    incident = correlation_engine.get_incident(incident_id)
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{incident_id}' not found",
        )
    from backend.ingestion.models import utc_now
    incident.status = new_status
    incident.updated_at = utc_now()
    return incident


@router.post(
    "/{incident_id}/investigate",
    response_model=dict,
    summary="Trigger the LangGraph investigation agent for a correlated incident",
)
async def investigate(incident_id: str = Path(..., description="Incident ID to investigate")):
    """
    Runs the full Phase 3-5 investigation pipeline:
    fetch context -> TI enrichment -> asset context -> log query -> lateral movement -> risk score -> report.
    Returns the investigation state including narrative, defense audit, and recommended actions.
    """
    incident = correlation_engine.get_incident(incident_id)
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident {incident_id!r} not found",
        )
    from backend.agent import investigate_incident
    result = investigate_incident(incident_id)
    if result.get("error"):
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=result["error"],
        )
    _investigation_cache[incident_id] = result

    report = result.get("incident_report")
    return {
        "incident_id": incident_id,
        "severity": result["incident"].severity.value if result.get("incident") else None,
        "enforced_floor": result["incident"].deterministic_floor.value if result.get("incident") else None,
        "floor_enforced": result.get("floor_enforced", False),
        "audit_note": result.get("audit_note"),
        "scoring_breakdown": result.get("scoring_breakdown"),
        "narrative": result.get("narrative", ""),
        "recommended_actions": result.get("recommended_actions", []),
        "lateral_movement_detected": bool(result.get("lateral_movement_paths")),
        "lateral_movement_paths": result.get("lateral_movement_paths", []),
        "adversarial_injection_detected": result.get("adversarial_injection_detected", False),
        "threat_intel_summary": {
            k: v.get("verdict") for k, v in result.get("threat_intel", {}).items()
        },
        "asset_context_summary": {
            k: v.get("criticality") for k, v in result.get("asset_context", {}).items()
        },
        "report_id": report.report_id if report else None,
        "has_report": bool(report),
        "investigation_complete": result.get("investigation_complete", False),
    }


@router.get(
    "/{incident_id}/report",
    response_model=dict,
    summary="Get structured JSON investigation report with evidence timeline and entity traceability",
)
async def get_report_json(incident_id: str = Path(..., description="Incident ID")):
    """
    Returns the Phase 5 structured IncidentReport model as JSON.
    Auto-triggers investigation if not yet run.
    """
    result = _get_or_run_investigation(incident_id)
    report = result.get("incident_report")
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Report not available for incident '{incident_id}'",
        )
    return report.model_dump(mode="json")


@router.get(
    "/{incident_id}/report/markdown",
    summary="Download or view investigation report in Markdown format",
)
async def get_report_markdown(incident_id: str = Path(..., description="Incident ID")):
    """
    Returns the report rendered as clean Markdown text.
    """
    result = _get_or_run_investigation(incident_id)
    report = result.get("incident_report")
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Report not available for incident '{incident_id}'",
        )
    md_content = result.get("report_markdown") or render_markdown(report)
    return Response(
        content=md_content,
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": f'inline; filename="incident_report_{incident_id}.md"'},
    )


@router.get(
    "/{incident_id}/report/pdf",
    summary="Export investigation report as a publication-ready PDF document",
)
async def get_report_pdf(incident_id: str = Path(..., description="Incident ID")):
    """
    Generates and downloads a publication-grade PDF investigation report with color-coded
    severity branding, complete evidence timeline, entity mapping, and audit trail.
    """
    result = _get_or_run_investigation(incident_id)
    report = result.get("incident_report")
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Report not available for incident '{incident_id}'",
        )
    try:
        pdf_bytes = render_pdf(report)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to generate PDF: {exc}",
        )
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="incident_report_{incident_id}.pdf"'},
    )
