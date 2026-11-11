"""Reporting API Endpoints.

Provides report generation and download for investigations.
"""

from pathlib import Path
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import FileResponse
from pydantic import BaseModel
import aiosqlite

from app.config import settings
from app.database import get_db
from app.reporting.generator import generate_report
from app.utils.audit import log_action

router = APIRouter(prefix="/cases/{case_id}/reports", tags=["Reports"])


class ReportGenerateRequest(BaseModel):
    report_type: str = "full"  # "full" or "executive"
    analyst_name: Optional[str] = None


@router.post("/generate", status_code=status.HTTP_201_CREATED)
async def create_report(
    case_id: str,
    payload: ReportGenerateRequest,
    db: aiosqlite.Connection = Depends(get_db),
):
    """Generate an HTML investigation report for a case."""
    try:
        result = await generate_report(
            case_id=case_id,
            db=db,
            report_type=payload.report_type,
            analyst_name=payload.analyst_name,
        )
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate report: {e}")

    await log_action(
        db,
        action="export",
        entity_type="report",
        entity_id=result["report_id"],
        details={"report_type": payload.report_type, "filename": result["filename"]},
    )

    return result


@router.get("")
async def list_reports(case_id: str):
    """List all generated reports for a case."""
    case_report_dir = settings.reports_dir / case_id
    if not case_report_dir.exists():
        return []

    reports = []
    for f in sorted(case_report_dir.glob("*.html"), key=lambda p: p.stat().st_mtime, reverse=True):
        reports.append({
            "filename": f.name,
            "filepath": str(f),
            "size": f.stat().st_size,
            "modified": f.stat().st_mtime,
        })
    return reports


@router.get("/{filename}")
async def download_report(case_id: str, filename: str):
    """Download or view a generated HTML report."""
    report_file = settings.reports_dir / case_id / filename
    if not report_file.exists():
        raise HTTPException(status_code=404, detail=f"Report {filename} not found")

    return FileResponse(
        path=report_file,
        media_type="text/html",
        filename=filename,
    )
