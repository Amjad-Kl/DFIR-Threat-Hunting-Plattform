"""Integration tests for cases, artifacts, and event ingestion."""

import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app


@pytest.mark.asyncio
async def test_case_lifecycle():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Create case
        resp = await client.post(
            "/api/v1/cases",
            json={
                "name": "Incident 2026-ALPHA",
                "description": "Ransomware triage host A",
                "analyst": "SecOps",
                "classification": "incident",
            },
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["name"] == "Incident 2026-ALPHA"
        case_id = data["id"]

        # Fetch case
        get_resp = await client.get(f"/api/v1/cases/{case_id}")
        assert get_resp.status_code == 200
        assert get_resp.json()["id"] == case_id

        # Stats
        stats_resp = await client.get(f"/api/v1/cases/{case_id}/stats")
        assert stats_resp.status_code == 200
        assert stats_resp.json()["total_events"] == 0

        # Update case
        update_resp = await client.put(
            f"/api/v1/cases/{case_id}",
            json={"status": "in_progress", "notes": "Investigating registry persistence"},
        )
        assert update_resp.status_code == 200
        assert update_resp.json()["status"] == "in_progress"

        # Delete case
        del_resp = await client.delete(f"/api/v1/cases/{case_id}")
        assert del_resp.status_code == 204


@pytest.mark.asyncio
async def test_web_gui_root_serving():
    """Verify that the root endpoint serves the local HTML Web GUI and static assets."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/")
        assert resp.status_code == 200
        assert "Threat Hunting Workbench" in resp.text
        assert "THREAT WORKBENCH" in resp.text

        # Verify static CSS
        css_resp = await client.get("/static/styles.css")
        assert css_resp.status_code == 200
        assert "--bg-dark" in css_resp.text

        # Verify static JS
        js_resp = await client.get("/static/app.js")
        assert js_resp.status_code == 200
        assert "switchView" in js_resp.text

        # Health endpoint
        health_resp = await client.get("/api/v1/health")
        assert health_resp.status_code == 200
        assert health_resp.json()["status"] == "online"
