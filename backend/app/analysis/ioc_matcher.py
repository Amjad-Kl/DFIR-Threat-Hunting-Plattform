"""IOC Matching Analysis Engine.

Scans normalized events against the IOC database (hashes, IPs, domains, command-line indicators)
and flags events while generating corresponding forensic findings.
"""

import json
import uuid
from datetime import datetime, timezone
import aiosqlite

from app.models.finding import FindingType


async def run_ioc_matching(case_id: str, db: aiosqlite.Connection) -> int:
    """Run IOC matching on all events for a given case.

    Returns the number of matches found.
    """
    # Fetch active IOCs for this case (including global IOCs)
    cursor = await db.execute(
        "SELECT ioc_type, ioc_value, confidence, description FROM iocs WHERE case_id = ? OR case_id IS NULL",
        (case_id,),
    )
    iocs = await cursor.fetchall()
    if not iocs:
        return 0

    matches_created = 0
    now = datetime.now(timezone.utc).isoformat()

    for ioc in iocs:
        ioc_type = ioc["ioc_type"]
        val = ioc["ioc_value"]

        # Formulate query based on IOC type
        if ioc_type in ["hash_md5", "hash_sha1", "hash_sha256"]:
            ev_cursor = await db.execute(
                "SELECT id, timestamp, process_name, file_path FROM events WHERE case_id = ? AND file_hash LIKE ?",
                (case_id, f"%{val}%"),
            )
        elif ioc_type == "ip":
            ev_cursor = await db.execute(
                "SELECT id, timestamp, process_name, file_path FROM events WHERE case_id = ? AND (source_ip = ? OR dest_ip = ?)",
                (case_id, val, val),
            )
        elif ioc_type == "filename":
            ev_cursor = await db.execute(
                "SELECT id, timestamp, process_name, file_path FROM events WHERE case_id = ? AND (process_name = ? OR file_path LIKE ?)",
                (case_id, val, f"%{val}"),
            )
        else:
            continue

        matched_events = await ev_cursor.fetchall()
        for ev in matched_events:
            event_id = ev["id"]

            # Flag event
            await db.execute(
                "UPDATE events SET is_ioc_match = 1, severity = 'high' WHERE id = ?",
                (event_id,),
            )

            # Insert finding
            finding_id = str(uuid.uuid4())
            await db.execute(
                """
                INSERT INTO findings (
                    id, case_id, event_id, finding_type, title, description,
                    severity, evidence, rule_name, false_positive, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)
                """,
                (
                    finding_id,
                    case_id,
                    event_id,
                    FindingType.IOC_MATCH.value,
                    f"IOC Match: {val} ({ioc_type})",
                    ioc["description"] or f"Event matched indicator {val}",
                    "high",
                    json.dumps({"ioc_type": ioc_type, "value": val, "matched_event_id": event_id}),
                    f"ioc_match_{ioc_type}",
                    now,
                ),
            )
            matches_created += 1

    await db.commit()
    return matches_created
