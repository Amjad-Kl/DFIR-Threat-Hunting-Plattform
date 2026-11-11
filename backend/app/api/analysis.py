"""Analysis execution and findings API.

Provides endpoints to trigger all detection engines and review results.
"""

from datetime import datetime
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
import aiosqlite

from app.analysis.ioc_matcher import run_ioc_matching
from app.analysis.persistence_detector import run_persistence_detection
from app.analysis.suspicious_patterns import run_suspicious_pattern_detection
from app.analysis.timeline_builder import build_full_timeline
from app.analysis.yara_scanner import run_yara_scan
from app.database import get_db
from app.models.finding import Finding, FindingType
from app.utils.audit import log_action

router = APIRouter(prefix="/cases/{case_id}", tags=["Analysis"])


@router.post("/analyze")
async def trigger_full_analysis(case_id: str, db: aiosqlite.Connection = Depends(get_db)):
    """Run ALL detection engines on a case: IOC, Persistence, Suspicious Patterns, YARA."""
    c = await db.execute("SELECT id FROM cases WHERE id = ?", (case_id,))
    if not await c.fetchone():
        raise HTTPException(status_code=404, detail=f"Case {case_id} not found")

    ioc_matches = await run_ioc_matching(case_id, db)
    persistence_matches = await run_persistence_detection(case_id, db)
    suspicious_matches = await run_suspicious_pattern_detection(case_id, db)
    yara_matches = await run_yara_scan(case_id, db)

    await log_action(
        db,
        action="analyze",
        entity_type="case",
        entity_id=case_id,
        details={
            "ioc_matches": ioc_matches,
            "persistence_matches": persistence_matches,
            "suspicious_pattern_matches": suspicious_matches,
            "yara_matches": yara_matches,
        },
    )

    total = ioc_matches + persistence_matches + suspicious_matches + yara_matches
    return {
        "case_id": case_id,
        "status": "completed",
        "results": {
            "ioc_findings": ioc_matches,
            "persistence_findings": persistence_matches,
            "suspicious_pattern_findings": suspicious_matches,
            "yara_findings": yara_matches,
        },
        "total_new_findings": total,
    }


@router.post("/analyze/ioc")
async def trigger_ioc_analysis(case_id: str, db: aiosqlite.Connection = Depends(get_db)):
    """Run only the IOC matching engine."""
    c = await db.execute("SELECT id FROM cases WHERE id = ?", (case_id,))
    if not await c.fetchone():
        raise HTTPException(status_code=404, detail=f"Case {case_id} not found")
    matches = await run_ioc_matching(case_id, db)
    return {"case_id": case_id, "engine": "ioc_matcher", "findings": matches}


@router.post("/analyze/persistence")
async def trigger_persistence_analysis(case_id: str, db: aiosqlite.Connection = Depends(get_db)):
    """Run only the persistence detection engine."""
    c = await db.execute("SELECT id FROM cases WHERE id = ?", (case_id,))
    if not await c.fetchone():
        raise HTTPException(status_code=404, detail=f"Case {case_id} not found")
    matches = await run_persistence_detection(case_id, db)
    return {"case_id": case_id, "engine": "persistence_detector", "findings": matches}


@router.post("/analyze/suspicious")
async def trigger_suspicious_analysis(case_id: str, db: aiosqlite.Connection = Depends(get_db)):
    """Run only the suspicious pattern detection engine."""
    c = await db.execute("SELECT id FROM cases WHERE id = ?", (case_id,))
    if not await c.fetchone():
        raise HTTPException(status_code=404, detail=f"Case {case_id} not found")
    matches = await run_suspicious_pattern_detection(case_id, db)
    return {"case_id": case_id, "engine": "suspicious_patterns", "findings": matches}


@router.post("/analyze/yara")
async def trigger_yara_analysis(case_id: str, db: aiosqlite.Connection = Depends(get_db)):
    """Run only the YARA scanner on artifact files."""
    c = await db.execute("SELECT id FROM cases WHERE id = ?", (case_id,))
    if not await c.fetchone():
        raise HTTPException(status_code=404, detail=f"Case {case_id} not found")
    matches = await run_yara_scan(case_id, db)
    return {"case_id": case_id, "engine": "yara_scanner", "findings": matches}


@router.get("/timeline/full")
async def get_full_timeline(
    case_id: str,
    start_time: Optional[datetime] = Query(None),
    end_time: Optional[datetime] = Query(None),
    limit: int = Query(10000, ge=1, le=50000),
    db: aiosqlite.Connection = Depends(get_db),
):
    """Build a complete forensic timeline with gap/cluster detection."""
    c = await db.execute("SELECT id FROM cases WHERE id = ?", (case_id,))
    if not await c.fetchone():
        raise HTTPException(status_code=404, detail=f"Case {case_id} not found")
    return await build_full_timeline(case_id, db, start_time, end_time, limit)


@router.get("/findings", response_model=list[Finding])
async def list_findings(
    case_id: str,
    finding_type: Optional[FindingType] = Query(None),
    severity: Optional[str] = Query(None),
    include_fp: bool = Query(False),
    db: aiosqlite.Connection = Depends(get_db),
):
    """Retrieve findings with optional filters."""
    query = "SELECT * FROM findings WHERE case_id = ?"
    params: list = [case_id]

    if finding_type:
        query += " AND finding_type = ?"
        params.append(finding_type.value)
    if severity:
        query += " AND severity = ?"
        params.append(severity)
    if not include_fp:
        query += " AND false_positive = 0"

    query += """ ORDER BY
        CASE severity
            WHEN 'critical' THEN 0
            WHEN 'high' THEN 1
            WHEN 'medium' THEN 2
            WHEN 'low' THEN 3
            ELSE 4
        END,
        created_at DESC
    """

    cursor = await db.execute(query, params)
    rows = await cursor.fetchall()
    return [
        Finding(
            id=r["id"],
            case_id=r["case_id"],
            event_id=r["event_id"],
            finding_type=FindingType(r["finding_type"]),
            title=r["title"],
            description=r["description"],
            severity=r["severity"],
            evidence=r["evidence"],
            rule_name=r["rule_name"],
            false_positive=bool(r["false_positive"]),
            analyst_notes=r["analyst_notes"],
            created_at=r["created_at"],
        )
        for r in rows
    ]


class FindingNoteUpdate(BaseModel):
    analyst_notes: str


@router.put("/findings/{finding_id}/notes")
async def update_finding_notes(
    finding_id: str, payload: FindingNoteUpdate, db: aiosqlite.Connection = Depends(get_db)
):
    """Add or update analyst notes on a finding."""
    cursor = await db.execute("SELECT id FROM findings WHERE id = ?", (finding_id,))
    if not await cursor.fetchone():
        raise HTTPException(status_code=404, detail=f"Finding {finding_id} not found")

    await db.execute(
        "UPDATE findings SET analyst_notes = ? WHERE id = ?",
        (payload.analyst_notes, finding_id),
    )
    await db.commit()
    return {"id": finding_id, "analyst_notes": payload.analyst_notes}


@router.put("/findings/{finding_id}/toggle-fp")
async def toggle_false_positive(finding_id: str, db: aiosqlite.Connection = Depends(get_db)):
    """Toggle false positive flag for a finding."""
    cursor = await db.execute("SELECT false_positive FROM findings WHERE id = ?", (finding_id,))
    row = await cursor.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail=f"Finding {finding_id} not found")

    new_val = 0 if row["false_positive"] else 1
    await db.execute("UPDATE findings SET false_positive = ? WHERE id = ?", (new_val, finding_id))
    await db.commit()
    return {"id": finding_id, "false_positive": bool(new_val)}
