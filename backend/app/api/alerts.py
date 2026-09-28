from typing import Dict, Any, List
from fastapi import APIRouter, HTTPException, Path
from pydantic import BaseModel, Field
from datetime import datetime, timezone

router = APIRouter(prefix="/alerts", tags=["alerts"])

class AlertWebhookPayload(BaseModel):
    raw_payload: Dict[str, Any] = Field(..., description="Raw SIEM alert payload")

@router.post("/webhook/{source}", summary="Ingest alerts from SIEM sources (Wazuh, Splunk, Elastic, Sentinel)")
async def ingest_alert_webhook(
    source: str = Path(..., description="SIEM source identifier"),
    payload: Dict[str, Any] = None
):
    return {
        "status": "received",
        "source": source,
        "received_at": datetime.now(timezone.utc).isoformat(),
        "details": "Alert accepted for normalization and correlation"
    }

@router.get("/", summary="List normalized alerts")
async def list_alerts():
    return {"alerts": [], "total": 0}
