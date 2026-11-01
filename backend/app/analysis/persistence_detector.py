"""Persistence Detection Engine for Windows Artifacts.

Evaluates events against rules in persistence_rules.json to flag persistence mechanisms.
"""

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
import aiosqlite

from app.models.finding import FindingType


def load_persistence_rules() -> list[dict]:
    """Load default persistence rules."""
    rules_file = Path(__file__).parent.parent.parent / "data" / "persistence_rules.json"
    if not rules_file.exists():
        return []
    with open(rules_file, "r", encoding="utf-8") as f:
        data = json.load(f)
        return data.get("rules", [])


async def run_persistence_detection(case_id: str, db: aiosqlite.Connection) -> int:
    """Analyze events in case for persistence mechanisms."""
    rules = load_persistence_rules()
    if not rules:
        return 0

    findings_count = 0
    now = datetime.now(timezone.utc).isoformat()

    for rule in rules:
        rule_name = rule["name"]
        severity = rule.get("severity", "high")
        event_ids = rule.get("event_ids", [])
        reg_paths = rule.get("registry_paths", [])

        # Check by Event ID
        for eid in event_ids:
            cursor = await db.execute(
                "SELECT id, timestamp, process_name, command_line, raw_data FROM events WHERE case_id = ? AND event_id = ?",
                (case_id, eid),
            )
            for ev in await cursor.fetchall():
                event_id = ev["id"]
                await db.execute(
                    "UPDATE events SET is_suspicious = 1, mitre_technique = ? WHERE id = ?",
                    (rule.get("mitre_technique"), event_id),
                )
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
                        FindingType.PERSISTENCE.value,
                        f"Persistence Detected: {rule_name}",
                        rule.get("description"),
                        severity,
                        json.dumps({"rule_id": rule.get("id"), "event_id": eid, "command_line": ev["command_line"]}),
                        rule.get("id"),
                        now,
                    ),
                )
                findings_count += 1

        # Check by Registry path
        for rpath in reg_paths:
            cursor = await db.execute(
                "SELECT id, timestamp, registry_key, registry_value FROM events WHERE case_id = ? AND registry_key LIKE ?",
                (case_id, f"%{rpath}%"),
            )
            for ev in await cursor.fetchall():
                event_id = ev["id"]
                await db.execute(
                    "UPDATE events SET is_suspicious = 1, mitre_technique = ? WHERE id = ?",
                    (rule.get("mitre_technique"), event_id),
                )
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
                        FindingType.PERSISTENCE.value,
                        f"Persistence Registry: {rule_name}",
                        f"Registry path matched {rpath}",
                        severity,
                        json.dumps({"rule_id": rule.get("id"), "registry_key": ev["registry_key"]}),
                        rule.get("id"),
                        now,
                    ),
                )
                findings_count += 1

    await db.commit()
    return findings_count
