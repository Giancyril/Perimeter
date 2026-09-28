from typing import List, Optional
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

router = APIRouter(prefix="/incidents", tags=["incidents"])

@router.get("/", summary="List correlated security incidents")
async def list_incidents():
    return {"incidents": [], "total": 0}

@router.get("/{incident_id}", summary="Get incident details by ID")
async def get_incident(incident_id: str):
    return {
        "incident_id": incident_id,
        "title": "Placeholder Security Incident",
        "severity": "low",
        "status": "open",
        "entities": [],
        "alerts_count": 0,
    }
