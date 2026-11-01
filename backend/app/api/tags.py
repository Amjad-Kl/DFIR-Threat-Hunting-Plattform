"""Tagging API Endpoints."""

import uuid
from datetime import datetime, timezone
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
import aiosqlite

from app.database import get_db
from app.models.tag import Tag, TagEntityType

router = APIRouter(prefix="/tags", tags=["Tags"])


class TagCreate(BaseModel):
    case_id: str
    entity_type: TagEntityType
    entity_id: str
    tag_name: str
    tag_color: Optional[str] = "#3b82f6"
    created_by: Optional[str] = "analyst"


@router.post("", response_model=Tag, status_code=status.HTTP_201_CREATED)
async def create_tag(payload: TagCreate, db: aiosqlite.Connection = Depends(get_db)):
    """Apply a tag to an event, artifact, or finding."""
    tag_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()

    try:
        await db.execute(
            """
            INSERT INTO tags (id, case_id, entity_type, entity_id, tag_name, tag_color, created_at, created_by)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                tag_id,
                payload.case_id,
                payload.entity_type.value,
                payload.entity_id,
                payload.tag_name.strip(),
                payload.tag_color,
                now,
                payload.created_by,
            ),
        )
        await db.commit()
    except aiosqlite.IntegrityError:
        raise HTTPException(
            status_code=409,
            detail=f"Tag '{payload.tag_name}' already exists on this entity.",
        )

    return Tag(
        id=tag_id,
        case_id=payload.case_id,
        entity_type=payload.entity_type,
        entity_id=payload.entity_id,
        tag_name=payload.tag_name.strip(),
        tag_color=payload.tag_color,
        created_at=datetime.fromisoformat(now),
        created_by=payload.created_by,
    )


@router.get("/case/{case_id}", response_model=list[Tag])
async def list_case_tags(case_id: str, db: aiosqlite.Connection = Depends(get_db)):
    """List all tags in a case."""
    cursor = await db.execute(
        "SELECT * FROM tags WHERE case_id = ? ORDER BY created_at DESC",
        (case_id,),
    )
    rows = await cursor.fetchall()
    return [
        Tag(
            id=r["id"],
            case_id=r["case_id"],
            entity_type=TagEntityType(r["entity_type"]),
            entity_id=r["entity_id"],
            tag_name=r["tag_name"],
            tag_color=r["tag_color"],
            created_at=datetime.fromisoformat(r["created_at"]),
            created_by=r["created_by"],
        )
        for r in rows
    ]


@router.delete("/{tag_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_tag(tag_id: str, db: aiosqlite.Connection = Depends(get_db)):
    """Remove a tag."""
    cursor = await db.execute("SELECT id FROM tags WHERE id = ?", (tag_id,))
    if not await cursor.fetchone():
        raise HTTPException(status_code=404, detail=f"Tag {tag_id} not found")

    await db.execute("DELETE FROM tags WHERE id = ?", (tag_id,))
    await db.commit()
