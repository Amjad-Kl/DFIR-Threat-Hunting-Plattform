"""Audit trail logging for Chain of Custody compliance."""

import json
from typing import Any, Optional
import aiosqlite


async def log_action(
    db: aiosqlite.Connection,
    action: str,
    user_name: Optional[str] = "analyst",
    entity_type: Optional[str] = None,
    entity_id: Optional[str] = None,
    details: Optional[dict[str, Any]] = None,
) -> None:
    """Record an action in the tamper-evident audit log table."""
    details_json = json.dumps(details) if details else None
    await db.execute(
        """
        INSERT INTO audit_log (user_name, action, entity_type, entity_id, details)
        VALUES (?, ?, ?, ?, ?)
        """,
        (user_name, action, entity_type, entity_id, details_json),
    )
    await db.commit()
