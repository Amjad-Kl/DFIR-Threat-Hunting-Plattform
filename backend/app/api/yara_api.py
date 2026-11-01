"""YARA Rule Management API Endpoints."""

import uuid
from datetime import datetime, timezone
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
import aiosqlite

from app.database import get_db

router = APIRouter(prefix="/yara", tags=["YARA"])


class YaraRuleCreate(BaseModel):
    name: str
    category: Optional[str] = "suspicious"
    rule_content: str
    source: Optional[str] = "custom"


@router.post("/rules", status_code=status.HTTP_201_CREATED)
async def create_yara_rule(payload: YaraRuleCreate, db: aiosqlite.Connection = Depends(get_db)):
    """Add a new YARA detection rule."""
    rule_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()

    try:
        await db.execute(
            """
            INSERT INTO yara_rules (id, name, category, rule_content, enabled, source, created_at)
            VALUES (?, ?, ?, ?, 1, ?, ?)
            """,
            (rule_id, payload.name, payload.category, payload.rule_content, payload.source, now),
        )
        await db.commit()
    except aiosqlite.IntegrityError:
        raise HTTPException(status_code=409, detail=f"Rule named '{payload.name}' already exists.")

    return {
        "id": rule_id,
        "name": payload.name,
        "category": payload.category,
        "enabled": True,
        "source": payload.source,
        "created_at": now,
    }


@router.get("/rules")
async def list_yara_rules(db: aiosqlite.Connection = Depends(get_db)):
    """List all registered YARA rules."""
    cursor = await db.execute("SELECT id, name, category, enabled, source, created_at FROM yara_rules ORDER BY created_at DESC")
    rows = await cursor.fetchall()
    return [dict(r) for r in rows]
