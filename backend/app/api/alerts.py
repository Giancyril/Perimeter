"""
Alert Ingestion & Management REST API.
Exposes endpoints for receiving SIEM webhooks, querying normalized alerts, and viewing deduplication stats.
"""
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, HTTPException, Path, Query, Body, Header, Request, status
from backend.ingestion.security import webhook_security_manager, WebhookSecurityManager
from backend.app.core.config import settings
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
    request: Request,
    source: str = Path(..., description="SIEM source identifier (e.g. wazuh, syslog)"),
    payload: Dict[str, Any] = Body(..., description="Raw SIEM alert payload"),
    x_secops_signature: Optional[str] = Header(None, alias="X-SecOps-Signature"),
    x_secops_timestamp: Optional[str] = Header(None, alias="X-SecOps-Timestamp"),
):
    # Verify HMAC signature if configured or provided
    raw_body = await request.body()
    # Configure security manager dynamically from app settings
    sec_mgr = WebhookSecurityManager(
        primary_secret=settings.WEBHOOK_SECRET,
        fallback_secrets=settings.WEBHOOK_FALLBACK_SECRETS,
        max_drift_seconds=settings.WEBHOOK_MAX_DRIFT_SECONDS,
    )
    is_valid, reason = sec_mgr.verify_signature(
        payload_bytes=raw_body,
        signature_header=x_secops_signature,
        timestamp_header=x_secops_timestamp,
    )
    if not is_valid:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=f"Webhook authentication failed: {reason}")
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
    request: Request,
    payload: Dict[str, Any] = Body(..., description="Raw SIEM alert payload"),
    x_secops_signature: Optional[str] = Header(None, alias="X-SecOps-Signature"),
    x_secops_timestamp: Optional[str] = Header(None, alias="X-SecOps-Timestamp"),
):
    # Verify HMAC signature if configured or provided
    raw_body = await request.body()
    sec_mgr = WebhookSecurityManager(
        primary_secret=settings.WEBHOOK_SECRET,
        fallback_secrets=settings.WEBHOOK_FALLBACK_SECRETS,
        max_drift_seconds=settings.WEBHOOK_MAX_DRIFT_SECONDS,
    )
    is_valid, reason = sec_mgr.verify_signature(
        payload_bytes=raw_body,
        signature_header=x_secops_signature,
        timestamp_header=x_secops_timestamp,
    )
    if not is_valid:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=f"Webhook authentication failed: {reason}")
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

@router.post(
    "/seed",
    summary="Seed demo alerts and scenarios for local development and testing",
)
async def seed_demo_alerts():
    from backend.evaluation.dataset import BENCHMARK_SCENARIOS
    count = 0
    for scenario in BENCHMARK_SCENARIOS:
        for alert in scenario.alerts:
            ingestion_engine.ingest(alert)
            count += 1
    return {
        "status": "success",
        "message": f"Seeded {count} alerts across {len(BENCHMARK_SCENARIOS)} benchmark scenarios",
    }
