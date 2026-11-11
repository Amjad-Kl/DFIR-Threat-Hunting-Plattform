"""Report Generator Engine.

Generates structured forensic investigation reports in HTML format
using Jinja2 templates. Reports include:
  - Executive Summary (high-level for management)
  - Technical Report (detailed for analysts)
  - Timeline overview
  - All findings grouped by severity
  - IOC list
  - Artifact inventory
"""

import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
import aiosqlite

from jinja2 import Environment, FileSystemLoader

from app.config import settings


TEMPLATES_DIR = Path(__file__).parent / "templates"


def _get_jinja_env() -> Environment:
    """Create a Jinja2 environment with the templates directory."""
    return Environment(
        loader=FileSystemLoader(str(TEMPLATES_DIR)),
        autoescape=True,
    )


async def generate_report(
    case_id: str,
    db: aiosqlite.Connection,
    report_type: str = "full",
    analyst_name: Optional[str] = None,
) -> dict:
    """Generate a forensic report for a case.
    
    Args:
        case_id: The case to report on
        db: Database connection
        report_type: 'full' or 'executive'
        analyst_name: Name to put on the report
    
    Returns:
        dict with report_id, filepath, and metadata
    """
    # Fetch case info
    case_cursor = await db.execute("SELECT * FROM cases WHERE id = ?", (case_id,))
    case = await case_cursor.fetchone()
    if not case:
        raise ValueError(f"Case {case_id} not found")

    # Fetch artifacts
    art_cursor = await db.execute(
        "SELECT * FROM artifacts WHERE case_id = ? ORDER BY import_time",
        (case_id,),
    )
    artifacts = [dict(r) for r in await art_cursor.fetchall()]

    # Fetch findings grouped by severity
    findings_cursor = await db.execute(
        """
        SELECT f.*, e.timestamp as event_timestamp, e.process_name, e.command_line, e.source_type
        FROM findings f
        LEFT JOIN events e ON f.event_id = e.id
        WHERE f.case_id = ? AND f.false_positive = 0
        ORDER BY
            CASE f.severity
                WHEN 'critical' THEN 0
                WHEN 'high' THEN 1
                WHEN 'medium' THEN 2
                WHEN 'low' THEN 3
                ELSE 4
            END,
            f.created_at DESC
        """,
        (case_id,),
    )
    findings = [dict(r) for r in await findings_cursor.fetchall()]

    # Severity counts
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = f.get("severity", "info")
        sev_counts[sev] = sev_counts.get(sev, 0) + 1

    # Event statistics
    stats_cursor = await db.execute(
        """
        SELECT
            COUNT(*) as total_events,
            COUNT(CASE WHEN is_suspicious = 1 THEN 1 END) as suspicious_events,
            COUNT(CASE WHEN is_ioc_match = 1 THEN 1 END) as ioc_matches,
            MIN(timestamp) as earliest,
            MAX(timestamp) as latest
        FROM events WHERE case_id = ?
        """,
        (case_id,),
    )
    stats = dict(await stats_cursor.fetchone())

    # IOCs used
    ioc_cursor = await db.execute(
        "SELECT * FROM iocs WHERE case_id = ? OR case_id IS NULL ORDER BY ioc_type",
        (case_id,),
    )
    iocs = [dict(r) for r in await ioc_cursor.fetchall()]

    # MITRE techniques found
    mitre_cursor = await db.execute(
        "SELECT DISTINCT mitre_technique FROM events WHERE case_id = ? AND mitre_technique IS NOT NULL",
        (case_id,),
    )
    mitre_techniques = [r["mitre_technique"] for r in await mitre_cursor.fetchall()]

    # Render the report
    now = datetime.now(timezone.utc)
    report_id = str(uuid.uuid4())

    template_name = "full_report.html" if report_type == "full" else "executive_summary.html"
    env = _get_jinja_env()
    template = env.get_template(template_name)

    html_content = template.render(
        report_id=report_id,
        case=dict(case),
        artifacts=artifacts,
        findings=findings,
        severity_counts=sev_counts,
        stats=stats,
        iocs=iocs,
        mitre_techniques=mitre_techniques,
        generated_at=now.isoformat(),
        analyst=analyst_name or case["analyst"] or "Unknown",
        total_findings=len(findings),
    )

    # Save to disk
    report_dir = settings.reports_dir / case_id
    report_dir.mkdir(parents=True, exist_ok=True)
    report_filename = f"report_{report_type}_{now.strftime('%Y%m%d_%H%M%S')}.html"
    report_path = report_dir / report_filename
    report_path.write_text(html_content, encoding="utf-8")

    return {
        "report_id": report_id,
        "filepath": str(report_path),
        "filename": report_filename,
        "type": report_type,
        "generated_at": now.isoformat(),
        "findings_count": len(findings),
        "severity_summary": sev_counts,
    }
