"""IOC Management API Endpoints."""

import csv
import io
import uuid
from datetime import datetime, timezone
from typing import Optional
from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile, status
from pydantic import BaseModel
import aiosqlite

from app.database import get_db
from app.models.ioc import IOC, IOCType

router = APIRouter(prefix="/iocs", tags=["IOCs"])


class IOCCreate(BaseModel):
    case_id: Optional[str] = None
    ioc_type: IOCType
    ioc_value: str
    description: Optional[str] = None
    source: Optional[str] = None
    confidence: str = "medium"


@router.post("", response_model=IOC, status_code=status.HTTP_201_CREATED)
async def create_ioc(payload: IOCCreate, db: aiosqlite.Connection = Depends(get_db)):
    """Add a single IOC (either global or tied to a specific case)."""
    ioc_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()

    try:
        await db.execute(
            """
            INSERT INTO iocs (id, case_id, ioc_type, ioc_value, description, source, confidence, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                ioc_id,
                payload.case_id,
                payload.ioc_type.value,
                payload.ioc_value.strip(),
                payload.description,
                payload.source,
                payload.confidence,
                now,
            ),
        )
        await db.commit()
    except aiosqlite.IntegrityError:
        raise HTTPException(
            status_code=409,
            detail=f"IOC {payload.ioc_type.value}:{payload.ioc_value} already exists for this scope.",
        )

    return IOC(
        id=ioc_id,
        case_id=payload.case_id,
        ioc_type=payload.ioc_type,
        ioc_value=payload.ioc_value.strip(),
        description=payload.description,
        source=payload.source,
        confidence=payload.confidence,
        created_at=datetime.fromisoformat(now),
    )


@router.post("/import")
async def import_iocs_csv(
    file: UploadFile = File(...),
    case_id: Optional[str] = None,
    db: aiosqlite.Connection = Depends(get_db),
):
    """Bulk import IOCs from a CSV file.
    
    Columns expected: type, value, description (optional), source (optional), confidence (optional)
    """
    content = await file.read()
    text = content.decode("utf-8", errors="replace")
    reader = csv.DictReader(io.StringIO(text))

    now = datetime.now(timezone.utc).isoformat()
    imported_count = 0
    errors = []

    for row in reader:
        raw_type = row.get("type", "").strip().lower()
        val = row.get("value", "").strip()
        if not val or not raw_type:
            continue

        try:
            ioc_type = IOCType(raw_type)
        except ValueError:
            errors.append(f"Invalid type '{raw_type}' for value '{val}'")
            continue

        ioc_id = str(uuid.uuid4())
        try:
            await db.execute(
                """
                INSERT OR IGNORE INTO iocs (id, case_id, ioc_type, ioc_value, description, source, confidence, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    ioc_id,
                    case_id,
                    ioc_type.value,
                    val,
                    row.get("description", ""),
                    row.get("source", "CSV Import"),
                    row.get("confidence", "medium"),
                    now,
                ),
            )
            imported_count += 1
        except Exception as e:
            errors.append(str(e))

    await db.commit()
    return {
        "imported": imported_count,
        "errors": errors,
    }


@router.get("", response_model=list[IOC])
async def list_iocs(
    case_id: Optional[str] = Query(None),
    ioc_type: Optional[IOCType] = Query(None),
    db: aiosqlite.Connection = Depends(get_db),
):
    """Retrieve IOCs, optionally filtered by scope or type."""
    query = "SELECT * FROM iocs WHERE 1=1"
    params = []

    if case_id is not None:
        query += " AND (case_id = ? OR case_id IS NULL)"
        params.append(case_id)
    if ioc_type is not None:
        query += " AND ioc_type = ?"
        params.append(ioc_type.value)

    query += " ORDER BY created_at DESC"
    cursor = await db.execute(query, params)
    rows = await cursor.fetchall()

    return [
        IOC(
            id=r["id"],
            case_id=r["case_id"],
            ioc_type=IOCType(r["ioc_type"]),
            ioc_value=r["ioc_value"],
            description=r["description"],
            source=r["source"],
            confidence=r["confidence"],
            created_at=datetime.fromisoformat(r["created_at"]),
        )
        for r in rows
    ]


@router.delete("/{ioc_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_ioc(ioc_id: str, db: aiosqlite.Connection = Depends(get_db)):
    """Delete an IOC entry."""
    cursor = await db.execute("SELECT id FROM iocs WHERE id = ?", (ioc_id,))
    if not await cursor.fetchone():
        raise HTTPException(status_code=404, detail=f"IOC {ioc_id} not found")

    await db.execute("DELETE FROM iocs WHERE id = ?", (ioc_id,))
    await db.commit()
