"""Case Management API Endpoints."""

import uuid
from datetime import datetime, timezone
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
import aiosqlite

from app.database import get_db
from app.models.case import Case, CaseCreate, CaseStatus, CaseUpdate
from app.utils.audit import log_action

router = APIRouter(prefix="/cases", tags=["Cases"])


@router.post("", response_model=Case, status_code=status.HTTP_201_CREATED)
async def create_case(payload: CaseCreate, db: aiosqlite.Connection = Depends(get_db)):
    """Create a new DFIR investigation case."""
    case_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    t_start = payload.time_range_start.isoformat() if payload.time_range_start else None
    t_end = payload.time_range_end.isoformat() if payload.time_range_end else None

    await db.execute(
        """
        INSERT INTO cases (
            id, name, description, status, created_at, updated_at,
            analyst, classification, time_range_start, time_range_end, notes
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            case_id,
            payload.name,
            payload.description,
            CaseStatus.OPEN.value,
            now,
            now,
            payload.analyst,
            payload.classification.value,
            t_start,
            t_end,
            payload.notes,
        ),
    )
    await db.commit()

    await log_action(
        db,
        action="create",
        user_name=payload.analyst or "analyst",
        entity_type="case",
        entity_id=case_id,
        details={"name": payload.name, "classification": payload.classification.value},
    )

    return Case(
        id=case_id,
        name=payload.name,
        description=payload.description,
        status=CaseStatus.OPEN,
        created_at=datetime.fromisoformat(now),
        updated_at=datetime.fromisoformat(now),
        analyst=payload.analyst,
        classification=payload.classification,
        time_range_start=payload.time_range_start,
        time_range_end=payload.time_range_end,
        notes=payload.notes,
        artifact_count=0,
        event_count=0,
        finding_count=0,
    )


@router.get("", response_model=list[Case])
async def list_cases(
    status_filter: Optional[CaseStatus] = Query(None, alias="status"),
    db: aiosqlite.Connection = Depends(get_db),
):
    """List all cases with summary statistics."""
    query = """
        SELECT 
            c.*,
            (SELECT COUNT(*) FROM artifacts a WHERE a.case_id = c.id) as artifact_count,
            (SELECT COUNT(*) FROM events e WHERE e.case_id = c.id) as event_count,
            (SELECT COUNT(*) FROM findings f WHERE f.case_id = c.id) as finding_count
        FROM cases c
    """
    params = []
    if status_filter:
        query += " WHERE c.status = ?"
        params.append(status_filter.value)

    query += " ORDER BY c.created_at DESC"

    cursor = await db.execute(query, params)
    rows = await cursor.fetchall()

    cases = []
    for r in rows:
        cases.append(
            Case(
                id=r["id"],
                name=r["name"],
                description=r["description"],
                status=CaseStatus(r["status"]),
                created_at=datetime.fromisoformat(r["created_at"]),
                updated_at=datetime.fromisoformat(r["updated_at"]),
                analyst=r["analyst"],
                classification=r["classification"],
                time_range_start=datetime.fromisoformat(r["time_range_start"]) if r["time_range_start"] else None,
                time_range_end=datetime.fromisoformat(r["time_range_end"]) if r["time_range_end"] else None,
                notes=r["notes"],
                artifact_count=r["artifact_count"],
                event_count=r["event_count"],
                finding_count=r["finding_count"],
            )
        )
    return cases


@router.get("/{case_id}", response_model=Case)
async def get_case(case_id: str, db: aiosqlite.Connection = Depends(get_db)):
    """Get single case details including artifact and event counts."""
    query = """
        SELECT 
            c.*,
            (SELECT COUNT(*) FROM artifacts a WHERE a.case_id = c.id) as artifact_count,
            (SELECT COUNT(*) FROM events e WHERE e.case_id = c.id) as event_count,
            (SELECT COUNT(*) FROM findings f WHERE f.case_id = c.id) as finding_count
        FROM cases c
        WHERE c.id = ?
    """
    cursor = await db.execute(query, (case_id,))
    row = await cursor.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail=f"Case {case_id} not found")

    return Case(
        id=row["id"],
        name=row["name"],
        description=row["description"],
        status=CaseStatus(row["status"]),
        created_at=datetime.fromisoformat(row["created_at"]),
        updated_at=datetime.fromisoformat(row["updated_at"]),
        analyst=row["analyst"],
        classification=row["classification"],
        time_range_start=datetime.fromisoformat(row["time_range_start"]) if row["time_range_start"] else None,
        time_range_end=datetime.fromisoformat(row["time_range_end"]) if row["time_range_end"] else None,
        notes=row["notes"],
        artifact_count=row["artifact_count"],
        event_count=row["event_count"],
        finding_count=row["finding_count"],
    )


@router.put("/{case_id}", response_model=Case)
async def update_case(
    case_id: str, payload: CaseUpdate, db: aiosqlite.Connection = Depends(get_db)
):
    """Update case metadata or status."""
    cursor = await db.execute("SELECT * FROM cases WHERE id = ?", (case_id,))
    existing = await cursor.fetchone()
    if not existing:
        raise HTTPException(status_code=404, detail=f"Case {case_id} not found")

    now = datetime.now(timezone.utc).isoformat()
    updates = ["updated_at = ?"]
    params = [now]

    if payload.name is not None:
        updates.append("name = ?")
        params.append(payload.name)
    if payload.description is not None:
        updates.append("description = ?")
        params.append(payload.description)
    if payload.status is not None:
        updates.append("status = ?")
        params.append(payload.status.value)
    if payload.analyst is not None:
        updates.append("analyst = ?")
        params.append(payload.analyst)
    if payload.classification is not None:
        updates.append("classification = ?")
        params.append(payload.classification.value)
    if payload.time_range_start is not None:
        updates.append("time_range_start = ?")
        params.append(payload.time_range_start.isoformat())
    if payload.time_range_end is not None:
        updates.append("time_range_end = ?")
        params.append(payload.time_range_end.isoformat())
    if payload.notes is not None:
        updates.append("notes = ?")
        params.append(payload.notes)

    params.append(case_id)
    query = f"UPDATE cases SET {', '.join(updates)} WHERE id = ?"
    await db.execute(query, params)
    await db.commit()

    await log_action(
        db,
        action="update",
        entity_type="case",
        entity_id=case_id,
        details=payload.model_dump(exclude_unset=True),
    )

    return await get_case(case_id, db)


@router.delete("/{case_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_case(case_id: str, db: aiosqlite.Connection = Depends(get_db)):
    """Delete case and all associated evidence, events, and findings (cascading)."""
    cursor = await db.execute("SELECT id FROM cases WHERE id = ?", (case_id,))
    if not await cursor.fetchone():
        raise HTTPException(status_code=404, detail=f"Case {case_id} not found")

    await db.execute("DELETE FROM cases WHERE id = ?", (case_id,))
    await db.commit()

    await log_action(
        db,
        action="delete",
        entity_type="case",
        entity_id=case_id,
        details={"deleted": True},
    )


@router.get("/{case_id}/stats")
async def get_case_statistics(case_id: str, db: aiosqlite.Connection = Depends(get_db)):
    """Retrieve aggregation statistics for case dashboard."""
    # Check case exists
    c = await db.execute("SELECT id, name FROM cases WHERE id = ?", (case_id,))
    if not await c.fetchone():
        raise HTTPException(status_code=404, detail=f"Case {case_id} not found")

    # Events by source type
    src_cursor = await db.execute(
        "SELECT source_type, COUNT(*) as count FROM events WHERE case_id = ? GROUP BY source_type",
        (case_id,),
    )
    events_by_source = {row["source_type"]: row["count"] for row in await src_cursor.fetchall()}

    # Events by severity
    sev_cursor = await db.execute(
        "SELECT severity, COUNT(*) as count FROM events WHERE case_id = ? GROUP BY severity",
        (case_id,),
    )
    events_by_severity = {row["severity"]: row["count"] for row in await sev_cursor.fetchall()}

    # Findings by type
    f_cursor = await db.execute(
        "SELECT finding_type, COUNT(*) as count FROM findings WHERE case_id = ? GROUP BY finding_type",
        (case_id,),
    )
    findings_by_type = {row["finding_type"]: row["count"] for row in await f_cursor.fetchall()}

    # Time boundaries of ingested events
    t_cursor = await db.execute(
        "SELECT MIN(timestamp) as earliest, MAX(timestamp) as latest, COUNT(*) as total FROM events WHERE case_id = ?",
        (case_id,),
    )
    t_row = await t_cursor.fetchone()

    return {
        "case_id": case_id,
        "total_events": t_row["total"] if t_row else 0,
        "earliest_event": t_row["earliest"] if t_row else None,
        "latest_event": t_row["latest"] if t_row else None,
        "events_by_source": events_by_source,
        "events_by_severity": events_by_severity,
        "findings_by_type": findings_by_type,
    }
