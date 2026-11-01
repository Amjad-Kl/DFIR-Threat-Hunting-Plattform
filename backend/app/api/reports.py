"""Reporting API Endpoints."""

from pathlib import Path
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
import aiosqlite

from app.config import settings
from app.database import get_db

router = APIRouter(prefix="/cases/{case_id}/reports", tags=["Reports"])


@router.get("")
async def list_reports(case_id: str):
    """List generated report files for a case."""
    case_report_dir = settings.reports_dir / case_id
    if not case_report_dir.exists():
        return []

    reports = []
    for f in case_report_dir.glob("*.html"):
        reports.append({
            "filename": f.name,
            "size": f.stat().st_size,
            "modified": f.stat().st_mtime,
        })
    return reports
