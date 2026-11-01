"""Events & Timeline API Endpoints."""

from datetime import datetime
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
import aiosqlite

from app.database import get_db
from app.models.event import EventSeverity, EventType, NormalizedEvent, SourceType

router = APIRouter(tags=["Events & Timeline"])


class SearchRequest(BaseModel):
    query: str
    limit: int = 100
    offset: int = 0


@router.get("/cases/{case_id}/events", response_model=dict)
async def list_events(
    case_id: str,
    source_type: Optional[SourceType] = None,
    event_type: Optional[EventType] = None,
    severity: Optional[EventSeverity] = None,
    is_suspicious: Optional[bool] = None,
    is_ioc_match: Optional[bool] = None,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: aiosqlite.Connection = Depends(get_db),
):
    """Retrieve normalized events with filtering and pagination."""
    where_clauses = ["case_id = ?"]
    params: list[object] = [case_id]

    if source_type:
        where_clauses.append("source_type = ?")
        params.append(source_type.value)
    if event_type:
        where_clauses.append("event_type = ?")
        params.append(event_type.value)
    if severity:
        where_clauses.append("severity = ?")
        params.append(severity.value)
    if is_suspicious is not None:
        where_clauses.append("is_suspicious = ?")
        params.append(1 if is_suspicious else 0)
    if is_ioc_match is not None:
        where_clauses.append("is_ioc_match = ?")
        params.append(1 if is_ioc_match else 0)
    if start_time:
        where_clauses.append("timestamp >= ?")
        params.append(start_time.isoformat())
    if end_time:
        where_clauses.append("timestamp <= ?")
        params.append(end_time.isoformat())

    where_sql = " AND ".join(where_clauses)

    count_cursor = await db.execute(f"SELECT COUNT(*) as count FROM events WHERE {where_sql}", params)
    total = (await count_cursor.fetchone())["count"]

    query = f"""
        SELECT * FROM events 
        WHERE {where_sql}
        ORDER BY timestamp ASC
        LIMIT ? OFFSET ?
    """
    fetch_params = list(params) + [limit, offset]
    cursor = await db.execute(query, fetch_params)
    rows = await cursor.fetchall()

    events = []
    for r in rows:
        events.append(
            NormalizedEvent(
                id=r["id"],
                case_id=r["case_id"],
                artifact_id=r["artifact_id"],
                timestamp=datetime.fromisoformat(r["timestamp"]),
                source_type=SourceType(r["source_type"]),
                event_type=EventType(r["event_type"]) if r["event_type"] else EventType.OTHER,
                severity=EventSeverity(r["severity"]),
                source_host=r["source_host"],
                source_user=r["source_user"],
                source_ip=r["source_ip"],
                dest_host=r["dest_host"],
                dest_ip=r["dest_ip"],
                dest_port=r["dest_port"],
                process_name=r["process_name"],
                process_path=r["process_path"],
                process_pid=r["process_pid"],
                parent_process=r["parent_process"],
                parent_pid=r["parent_pid"],
                command_line=r["command_line"],
                file_path=r["file_path"],
                file_hash=r["file_hash"],
                registry_key=r["registry_key"],
                registry_value=r["registry_value"],
                raw_data=r["raw_data"],
                channel=r["channel"],
                event_id=r["event_id"],
                is_suspicious=bool(r["is_suspicious"]),
                is_ioc_match=bool(r["is_ioc_match"]),
                mitre_tactic=r["mitre_tactic"],
                mitre_technique=r["mitre_technique"],
            )
        )

    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "events": events,
    }


@router.get("/events/{event_id}", response_model=NormalizedEvent)
async def get_event(event_id: str, db: aiosqlite.Connection = Depends(get_db)):
    """Fetch complete details of a single event including raw data payload."""
    cursor = await db.execute("SELECT * FROM events WHERE id = ?", (event_id,))
    r = await cursor.fetchone()
    if not r:
        raise HTTPException(status_code=404, detail=f"Event {event_id} not found")

    return NormalizedEvent(
        id=r["id"],
        case_id=r["case_id"],
        artifact_id=r["artifact_id"],
        timestamp=datetime.fromisoformat(r["timestamp"]),
        source_type=SourceType(r["source_type"]),
        event_type=EventType(r["event_type"]) if r["event_type"] else EventType.OTHER,
        severity=EventSeverity(r["severity"]),
        source_host=r["source_host"],
        source_user=r["source_user"],
        source_ip=r["source_ip"],
        dest_host=r["dest_host"],
        dest_ip=r["dest_ip"],
        dest_port=r["dest_port"],
        process_name=r["process_name"],
        process_path=r["process_path"],
        process_pid=r["process_pid"],
        parent_process=r["parent_process"],
        parent_pid=r["parent_pid"],
        command_line=r["command_line"],
        file_path=r["file_path"],
        file_hash=r["file_hash"],
        registry_key=r["registry_key"],
        registry_value=r["registry_value"],
        raw_data=r["raw_data"],
        channel=r["channel"],
        event_id=r["event_id"],
        is_suspicious=bool(r["is_suspicious"]),
        is_ioc_match=bool(r["is_ioc_match"]),
        mitre_tactic=r["mitre_tactic"],
        mitre_technique=r["mitre_technique"],
    )


@router.post("/cases/{case_id}/events/search")
async def search_events(
    case_id: str,
    payload: SearchRequest,
    db: aiosqlite.Connection = Depends(get_db),
):
    """Full-text search using SQLite FTS5."""
    clean_query = payload.query.replace('"', '""')
    sql = """
        SELECT e.* FROM events_fts fts
        JOIN events e ON fts.rowid = e.rowid
        WHERE events_fts MATCH ? AND e.case_id = ?
        ORDER BY e.timestamp ASC
        LIMIT ? OFFSET ?
    """
    cursor = await db.execute(sql, (f'"{clean_query}"', case_id, payload.limit, payload.offset))
    rows = await cursor.fetchall()
    return {
        "query": payload.query,
        "count": len(rows),
        "results": [dict(r) for r in rows],
    }


@router.get("/cases/{case_id}/timeline")
async def get_timeline_aggregations(
    case_id: str,
    interval: str = Query("hour", regex="^(hour|day)$"),
    db: aiosqlite.Connection = Depends(get_db),
):
    """Bucket events by hour or day for timeline histogram rendering."""
    date_format = "%Y-%m-%d %H:00:00" if interval == "hour" else "%Y-%m-%d"
    sql = f"""
        SELECT 
            strftime('{date_format}', timestamp) as bucket,
            source_type,
            severity,
            COUNT(*) as count
        FROM events
        WHERE case_id = ?
        GROUP BY bucket, source_type, severity
        ORDER BY bucket ASC
    """
    cursor = await db.execute(sql, (case_id,))
    rows = await cursor.fetchall()
    return {
        "case_id": case_id,
        "interval": interval,
        "buckets": [dict(r) for r in rows],
    }
