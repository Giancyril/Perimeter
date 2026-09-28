"""
Alert Ingestion & Management REST API.
Exposes endpoints for receiving SIEM webhooks, querying normalized alerts, and viewing deduplication stats.
"""
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, HTTPException, Path, Query, Body, status
from backend.ingestion import (
    ingestion_engine,
    NormalizedAlert,
    IngestionResult,
    SeverityLevel,
    AlertSourceType,
)

router = APIRouter(prefix="/alerts", tags=["alerts"])

@router.post(
    "/webhook/{source}",
    response_model=IngestionResult,
    status_code=status.HTTP_201_CREATED,
    summary="Ingest SIEM alert through dedicated source adapter (Wazuh, Syslog, Splunk, Elastic, Sentinel)",
)
async def ingest_alert_by_source(
    source: str = Path(..., description="SIEM source identifier (e.g. wazuh, syslog)"),
    payload: Dict[str, Any] = Body(..., description="Raw SIEM alert payload"),
):
    if not payload or not isinstance(payload, dict):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Alert payload must be a non-empty JSON object",
        )
    try:
        result = ingestion_engine.ingest(payload, explicit_source=source)
        return result
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Failed to normalize alert from source '{source}': {str(e)}",
        )

@router.post(
    "/webhook",
    response_model=IngestionResult,
    status_code=status.HTTP_201_CREATED,
    summary="Ingest SIEM alert with automatic source adapter resolution",
)
async def ingest_alert_auto(
    payload: Dict[str, Any] = Body(..., description="Raw SIEM alert payload"),
):
    if not payload or not isinstance(payload, dict):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Alert payload must be a non-empty JSON object",
        )
    try:
        result = ingestion_engine.ingest(payload)
        return result
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Failed to normalize alert: {str(e)}",
        )

@router.get(
    "/",
    response_model=Dict[str, Any],
    summary="List normalized security alerts with entity filtering",
)
async def list_alerts(
    limit: int = Query(50, ge=1, le=500),
    severity: Optional[SeverityLevel] = Query(None, description="Filter by normalized severity"),
    source: Optional[AlertSourceType] = Query(None, description="Filter by SIEM source"),
    host: Optional[str] = Query(None, description="Filter by target host substring"),
    user: Optional[str] = Query(None, description="Filter by target user substring"),
    ip: Optional[str] = Query(None, description="Filter by source or destination IP"),
):
    alerts = ingestion_engine.list_alerts(
        limit=limit,
        severity=severity,
        source=source,
        host=host,
        user=user,
        ip=ip,
    )
    return {
        "alerts": [a.model_dump() for a in alerts],
        "count": len(alerts),
    }

@router.get(
    "/stats",
    summary="Get alert ingestion and deduplication statistics",
)
async def get_alert_stats():
    return ingestion_engine.get_stats()

@router.get(
    "/{alert_id}",
    response_model=NormalizedAlert,
    summary="Get single normalized alert by ID (includes raw payload for forensics)",
)
async def get_alert(alert_id: str = Path(..., description="Alert ID")):
    alert = ingestion_engine.get_alert(alert_id)
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert with ID '{alert_id}' not found",
        )
    return alert
