import pytest
from httpx import AsyncClient, ASGITransport
from backend.app.main import app

@pytest.mark.asyncio
async def test_health_check():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "service" in data
        assert "version" in data

@pytest.mark.asyncio
async def test_root_endpoint():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/")
        assert response.status_code == 200
        data = response.json()
        assert "docs_url" in data
        assert data["health_check"] == "/health"

@pytest.mark.asyncio
async def test_alert_webhook_stub():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/api/v1/alerts/webhook/wazuh",
            json={"rule": {"id": "100200", "description": "SSH Brute Force Attempt"}}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "received"
        assert data["source"] == "wazuh"

@pytest.mark.asyncio
async def test_incidents_list_stub():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/v1/incidents/")
        assert response.status_code == 200
        data = response.json()
        assert "incidents" in data
