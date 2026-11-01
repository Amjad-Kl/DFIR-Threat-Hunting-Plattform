"""Analysis execution and findings API."""

from fastapi import APIRouter, Depends, HTTPException
import aiosqlite

from app.analysis.ioc_matcher import run_ioc_matching
from app.analysis.persistence_detector import run_persistence_detection
from app.database import get_db
from app.models.finding import Finding, FindingType
from app.utils.audit import log_action

router = APIRouter(prefix="/cases/{case_id}", tags=["Analysis"])


@router.post("/analyze")
async def trigger_full_analysis(case_id: str, db: aiosqlite.Connection = Depends(get_db)):
    """Run all detection engines (IOC matching, persistence detection) for a case."""
    # Ensure case exists
    c = await db.execute("SELECT id FROM cases WHERE id = ?", (case_id,))
    if not await c.fetchone():
        raise HTTPException(status_code=404, detail=f"Case {case_id} not found")

    ioc_matches = await run_ioc_matching(case_id, db)
    persistence_matches = await run_persistence_detection(case_id, db)

    await log_action(
        db,
        action="analyze",
        entity_type="case",
        entity_id=case_id,
        details={
            "ioc_matches": ioc_matches,
            "persistence_matches": persistence_matches,
        },
    )

    return {
        "case_id": case_id,
        "status": "completed",
        "ioc_findings": ioc_matches,
        "persistence_findings": persistence_matches,
        "total_new_findings": ioc_matches + persistence_matches,
    }


@router.get("/findings", response_model=list[Finding])
async def list_findings(case_id: str, db: aiosqlite.Connection = Depends(get_db)):
    """Retrieve all identified findings for a case."""
    cursor = await db.execute(
        "SELECT * FROM findings WHERE case_id = ? ORDER BY created_at DESC",
        (case_id,),
    )
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
