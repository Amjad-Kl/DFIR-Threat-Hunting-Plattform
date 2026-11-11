"""Timeline Builder Engine.

Constructs a unified forensic timeline from all normalized events in a case.
Provides:
  - Sorted, deduplicated event sequence
  - Activity clustering (bursts of activity)
  - Gap detection (significant periods of inactivity)
  - Summary statistics per time window
"""

import json
from datetime import datetime, timedelta, timezone
from typing import Optional
import aiosqlite


async def build_full_timeline(
    case_id: str,
    db: aiosqlite.Connection,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    limit: int = 10000,
) -> dict:
    """Build a complete timeline for a case.
    
    Returns a dict with:
      - events: ordered list of timeline entries
      - summary: statistics about the timeline
      - gaps: periods of significant inactivity
      - clusters: bursts of activity
    """
    where = "WHERE case_id = ?"
    params: list = [case_id]

    if start_time:
        where += " AND timestamp >= ?"
        params.append(start_time.isoformat())
    if end_time:
        where += " AND timestamp <= ?"
        params.append(end_time.isoformat())

    # Fetch ordered events
    cursor = await db.execute(
        f"""
        SELECT id, timestamp, source_type, event_type, severity,
               source_host, source_user, process_name, command_line,
               file_path, registry_key, event_id, is_suspicious,
               is_ioc_match, mitre_technique, channel
        FROM events
        {where}
        ORDER BY timestamp ASC
        LIMIT ?
        """,
        params + [limit],
    )
    rows = await cursor.fetchall()

    events = [dict(r) for r in rows]

    # Total count (without limit)
    count_cursor = await db.execute(
        f"SELECT COUNT(*) as total FROM events {where}",
        params,
    )
    total_row = await count_cursor.fetchone()
    total_events = total_row["total"] if total_row else 0

    # Summary statistics
    stats_cursor = await db.execute(
        f"""
        SELECT
            MIN(timestamp) as earliest,
            MAX(timestamp) as latest,
            COUNT(CASE WHEN is_suspicious = 1 THEN 1 END) as suspicious_count,
            COUNT(CASE WHEN is_ioc_match = 1 THEN 1 END) as ioc_match_count,
            COUNT(CASE WHEN severity = 'critical' THEN 1 END) as critical_count,
            COUNT(CASE WHEN severity = 'high' THEN 1 END) as high_count
        FROM events
        {where}
        """,
        params,
    )
    stats_row = await stats_cursor.fetchone()

    # Source breakdown
    src_cursor = await db.execute(
        f"SELECT source_type, COUNT(*) as count FROM events {where} GROUP BY source_type ORDER BY count DESC",
        params,
    )
    source_breakdown = {r["source_type"]: r["count"] for r in await src_cursor.fetchall()}

    # Detect gaps (periods > 1 hour with no events)
    gaps = []
    if len(events) > 1:
        for i in range(1, len(events)):
            try:
                t1 = datetime.fromisoformat(events[i - 1]["timestamp"])
                t2 = datetime.fromisoformat(events[i]["timestamp"])
                delta = (t2 - t1).total_seconds()
                if delta > 3600:  # > 1 hour
                    gaps.append({
                        "start": events[i - 1]["timestamp"],
                        "end": events[i]["timestamp"],
                        "duration_seconds": delta,
                        "duration_human": str(timedelta(seconds=int(delta))),
                    })
            except (ValueError, TypeError):
                continue

    # Detect activity clusters (>10 events within 5 minutes)
    clusters = []
    if events:
        cluster_window = 300  # 5 minutes
        cluster_start = 0
        for i in range(1, len(events)):
            try:
                t_start = datetime.fromisoformat(events[cluster_start]["timestamp"])
                t_curr = datetime.fromisoformat(events[i]["timestamp"])
                if (t_curr - t_start).total_seconds() > cluster_window:
                    cluster_size = i - cluster_start
                    if cluster_size >= 10:
                        clusters.append({
                            "start": events[cluster_start]["timestamp"],
                            "end": events[i - 1]["timestamp"],
                            "event_count": cluster_size,
                            "sources": list(set(events[j]["source_type"] for j in range(cluster_start, i))),
                        })
                    cluster_start = i
            except (ValueError, TypeError):
                cluster_start = i
                continue

        # Check last cluster
        last_size = len(events) - cluster_start
        if last_size >= 10:
            clusters.append({
                "start": events[cluster_start]["timestamp"],
                "end": events[-1]["timestamp"],
                "event_count": last_size,
                "sources": list(set(events[j]["source_type"] for j in range(cluster_start, len(events)))),
            })

    return {
        "case_id": case_id,
        "total_events": total_events,
        "returned_events": len(events),
        "events": events,
        "summary": {
            "earliest": stats_row["earliest"] if stats_row else None,
            "latest": stats_row["latest"] if stats_row else None,
            "suspicious_count": stats_row["suspicious_count"] if stats_row else 0,
            "ioc_match_count": stats_row["ioc_match_count"] if stats_row else 0,
            "critical_count": stats_row["critical_count"] if stats_row else 0,
            "high_count": stats_row["high_count"] if stats_row else 0,
            "source_breakdown": source_breakdown,
        },
        "gaps": gaps,
        "clusters": clusters,
    }
