"""YARA Scanner Engine.

Scans files on disk against loaded YARA rules and creates findings
for matches. Designed for scanning forensic evidence files imported
into a case (executables, scripts, memory dumps, etc.).
"""

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
import aiosqlite

from app.models.finding import FindingType

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False


async def get_compiled_rules(db: aiosqlite.Connection) -> Optional[object]:
    """Fetch all enabled YARA rules from the database and compile them."""
    if not YARA_AVAILABLE:
        return None

    cursor = await db.execute(
        "SELECT name, rule_content FROM yara_rules WHERE enabled = 1"
    )
    rows = await cursor.fetchall()

    if not rows:
        return None

    # Combine all rules into a single source string
    sources = {}
    for row in rows:
        name = row["name"]
        content = row["rule_content"]
        # yara.compile expects a dict of namespace -> source
        sources[name] = content

    try:
        compiled = yara.compile(sources=sources)
        return compiled
    except yara.SyntaxError as e:
        # If combined compilation fails, try rules individually
        valid_sources = {}
        for name, content in sources.items():
            try:
                yara.compile(source=content)
                valid_sources[name] = content
            except yara.SyntaxError:
                continue

        if valid_sources:
            return yara.compile(sources=valid_sources)
        return None


async def run_yara_scan(case_id: str, db: aiosqlite.Connection) -> int:
    """Scan all artifact files in a case against enabled YARA rules.

    Returns number of matches found.
    """
    if not YARA_AVAILABLE:
        return 0

    compiled = await get_compiled_rules(db)
    if compiled is None:
        return 0

    # Get all artifact file paths for this case
    cursor = await db.execute(
        "SELECT id, filepath, filename FROM artifacts WHERE case_id = ?",
        (case_id,),
    )
    artifacts = await cursor.fetchall()

    matches_count = 0
    now = datetime.now(timezone.utc).isoformat()

    for artifact in artifacts:
        artifact_id = artifact["id"]
        filepath = Path(artifact["filepath"])
        filename = artifact["filename"]

        if not filepath.exists():
            continue

        try:
            matches = compiled.match(str(filepath), timeout=60)
        except yara.TimeoutError:
            continue
        except yara.Error:
            continue

        for match in matches:
            finding_id = str(uuid.uuid4())

            # Extract match metadata
            meta = {}
            if hasattr(match, "meta") and match.meta:
                meta = {k: str(v) for k, v in match.meta.items()}

            # Extract matched strings (limited)
            matched_strings = []
            if hasattr(match, "strings"):
                for s in match.strings[:10]:  # Limit to first 10
                    try:
                        matched_strings.append({
                            "offset": s.instances[0].offset if s.instances else 0,
                            "identifier": s.identifier,
                            "data": s.instances[0].matched_data[:64].hex() if s.instances else "",
                        })
                    except (AttributeError, IndexError):
                        matched_strings.append({"identifier": str(s)})

            evidence = {
                "rule_name": match.rule,
                "namespace": match.namespace,
                "file": filename,
                "artifact_id": artifact_id,
                "meta": meta,
                "matched_strings": matched_strings,
                "tags": list(match.tags) if hasattr(match, "tags") else [],
            }

            severity = meta.get("severity", "high")
            if severity not in ("info", "low", "medium", "high", "critical"):
                severity = "high"

            await db.execute(
                """
                INSERT INTO findings (
                    id, case_id, event_id, finding_type, title, description,
                    severity, evidence, rule_name, false_positive, created_at
                ) VALUES (?, ?, NULL, ?, ?, ?, ?, ?, ?, 0, ?)
                """,
                (
                    finding_id,
                    case_id,
                    FindingType.YARA_MATCH.value,
                    f"YARA Match: {match.rule} on {filename}",
                    meta.get("description", f"YARA rule '{match.rule}' matched file '{filename}'"),
                    severity,
                    json.dumps(evidence),
                    match.rule,
                    now,
                ),
            )
            matches_count += 1

    await db.commit()
    return matches_count
