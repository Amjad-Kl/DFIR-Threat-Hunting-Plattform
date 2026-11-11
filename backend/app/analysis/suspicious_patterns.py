"""Suspicious Pattern Detection Engine.

Rule-based heuristic detection for common attack patterns in normalized events.
Each pattern checks for known attacker techniques regardless of specific IOCs.

Categories:
  - Suspicious process execution (LOLBins, encoded commands, unusual parents)
  - Credential access indicators
  - Lateral movement signals
  - Defense evasion techniques
  - Data staging / exfiltration indicators
"""

import json
import re
import uuid
from datetime import datetime, timezone
from typing import Optional
import aiosqlite

from app.models.finding import FindingType

# ── Pattern Definitions ──────────────────────────────────────────────

SUSPICIOUS_PATTERNS: list[dict] = [
    # ── Encoded/Obfuscated Command Execution ──
    {
        "id": "SUS-001",
        "title": "Encoded PowerShell Command",
        "description": "PowerShell executed with base64-encoded command, commonly used to bypass detection",
        "field": "command_line",
        "regex": r"(?i)(powershell|pwsh).*(-enc|-encodedcommand|-e\s+[A-Za-z0-9+/=]{20,})",
        "severity": "high",
        "mitre": "T1059.001",
    },
    {
        "id": "SUS-002",
        "title": "PowerShell Download Cradle",
        "description": "PowerShell downloading and executing content from network",
        "field": "command_line",
        "regex": r"(?i)(invoke-webrequest|iwr|wget|curl|downloadstring|downloadfile|invoke-expression|iex|net\.webclient|start-bitstransfer)",
        "severity": "high",
        "mitre": "T1105",
    },
    {
        "id": "SUS-003",
        "title": "Certutil Abuse for Download/Decode",
        "description": "Certutil used to download or decode files, a known LOLBin technique",
        "field": "command_line",
        "regex": r"(?i)certutil.*(-urlcache|-decode|-encode|-decodehex)",
        "severity": "high",
        "mitre": "T1140",
    },
    {
        "id": "SUS-004",
        "title": "WMIC Process Creation",
        "description": "WMIC used to create remote processes, common for lateral movement",
        "field": "command_line",
        "regex": r"(?i)wmic.*process\s+call\s+create",
        "severity": "high",
        "mitre": "T1047",
    },
    {
        "id": "SUS-005",
        "title": "Mshta Script Execution",
        "description": "MSHTA used to execute scripts, a living-off-the-land binary technique",
        "field": "command_line",
        "regex": r"(?i)mshta\s+(vbscript|javascript|http|about)",
        "severity": "high",
        "mitre": "T1218.005",
    },
    {
        "id": "SUS-006",
        "title": "Rundll32 Script Proxy Execution",
        "description": "Rundll32 executing JavaScript or VBScript",
        "field": "command_line",
        "regex": r"(?i)rundll32.*javascript|rundll32.*vbscript|rundll32.*mshtml",
        "severity": "high",
        "mitre": "T1218.011",
    },
    {
        "id": "SUS-007",
        "title": "Regsvr32 AppLocker Bypass",
        "description": "Regsvr32 used with /s /n /u /i to bypass AppLocker",
        "field": "command_line",
        "regex": r"(?i)regsvr32.*/s.*/n.*/u.*/i",
        "severity": "high",
        "mitre": "T1218.010",
    },
    # ── Credential Access ──
    {
        "id": "SUS-008",
        "title": "LSASS Memory Access",
        "description": "Potential credential dumping targeting LSASS process",
        "field": "command_line",
        "regex": r"(?i)(lsass|procdump.*lsass|mimikatz|sekurlsa|comsvcs.*minidump|comsvcs.*MiniDump|rundll32.*comsvcs)",
        "severity": "critical",
        "mitre": "T1003.001",
    },
    {
        "id": "SUS-009",
        "title": "SAM/SYSTEM Hive Copy",
        "description": "Copying SAM or SYSTEM hives for offline credential extraction",
        "field": "command_line",
        "regex": r"(?i)(reg\s+save.*\\sam|reg\s+save.*\\system|reg\s+save.*\\security|vssadmin.*shadow.*copy|ntdsutil)",
        "severity": "critical",
        "mitre": "T1003.002",
    },
    # ── Suspicious Spawning Patterns ──
    {
        "id": "SUS-010",
        "title": "Suspicious Parent-Child Relationship",
        "description": "Unusual process spawning pattern (e.g., Office spawning cmd/powershell)",
        "field": "parent_process",
        "regex": r"(?i)(winword|excel|powerpnt|outlook|onenote)\.exe",
        "child_field": "process_name",
        "child_regex": r"(?i)(cmd|powershell|pwsh|wscript|cscript|mshta|certutil|bitsadmin)\.exe",
        "severity": "critical",
        "mitre": "T1204.002",
    },
    # ── Defense Evasion ──
    {
        "id": "SUS-011",
        "title": "Windows Event Log Cleared",
        "description": "Audit log was cleared, potential evidence destruction",
        "field": "event_id",
        "value_match": [1102, 104],
        "severity": "critical",
        "mitre": "T1070.001",
    },
    {
        "id": "SUS-012",
        "title": "Timestomping Indicator",
        "description": "Sysmon Event 2: File creation time was changed, potential anti-forensics",
        "field": "event_id",
        "value_match": [2],
        "channel_match": "sysmon",
        "severity": "medium",
        "mitre": "T1070.006",
    },
    {
        "id": "SUS-013",
        "title": "AMSI Bypass Attempt",
        "description": "Command attempting to disable AMSI (Anti-Malware Scan Interface)",
        "field": "command_line",
        "regex": r"(?i)(amsiutils|amsiinitfailed|amsi\.dll|amsicontext|disable-amsi|set-mppreference.*-disablerealtimemonitoring)",
        "severity": "high",
        "mitre": "T1562.001",
    },
    # ── Execution from suspicious paths ──
    {
        "id": "SUS-014",
        "title": "Execution from Temp/Public Directory",
        "description": "Process executed from temporary or world-writable directory",
        "field": "process_path",
        "regex": r"(?i)(\\temp\\|\\tmp\\|\\public\\|\\perflogs\\|\\appdata\\local\\temp).*\.(exe|dll|scr|bat|ps1|vbs|js)",
        "severity": "medium",
        "mitre": "T1204",
    },
    # ── Lateral Movement ──
    {
        "id": "SUS-015",
        "title": "PsExec Usage",
        "description": "PsExec or similar remote execution tool detected",
        "field": "command_line",
        "regex": r"(?i)(psexec|psexesvc|paexec|remcom|csexec)",
        "severity": "high",
        "mitre": "T1570",
    },
    {
        "id": "SUS-016",
        "title": "Suspicious Scheduled Task Command",
        "description": "Scheduled task created via command line",
        "field": "command_line",
        "regex": r"(?i)schtasks\s+/create",
        "severity": "medium",
        "mitre": "T1053.005",
    },
    {
        "id": "SUS-017",
        "title": "BITSAdmin Transfer",
        "description": "BITSAdmin used for file download, a known LOLBin technique",
        "field": "command_line",
        "regex": r"(?i)bitsadmin.*/transfer",
        "severity": "medium",
        "mitre": "T1197",
    },
]


async def run_suspicious_pattern_detection(case_id: str, db: aiosqlite.Connection) -> int:
    """Evaluate all events against suspicious pattern rules.
    
    Returns the number of new findings created.
    """
    findings_count = 0
    now = datetime.now(timezone.utc).isoformat()

    for pattern in SUSPICIOUS_PATTERNS:
        pattern_id = pattern["id"]
        title = pattern["title"]
        desc = pattern["description"]
        severity = pattern["severity"]
        mitre = pattern.get("mitre")
        field = pattern["field"]

        # ── Value-match patterns (Event ID based) ──
        if "value_match" in pattern:
            for val in pattern["value_match"]:
                sql = f"SELECT id, timestamp, command_line, process_name, channel FROM events WHERE case_id = ? AND {field} = ?"
                params: list = [case_id, val]

                # Optional channel filter
                if "channel_match" in pattern:
                    sql += " AND LOWER(channel) LIKE ?"
                    params.append(f"%{pattern['channel_match']}%")

                cursor = await db.execute(sql, params)
                for ev in await cursor.fetchall():
                    await _create_finding(db, case_id, ev["id"], pattern_id, title, desc, severity, mitre, now, {
                        "matched_field": field,
                        "matched_value": val,
                    })
                    findings_count += 1
            continue

        # ── Regex patterns on text fields ──
        if "regex" not in pattern:
            continue

        compiled_re = re.compile(pattern["regex"])

        # Fetch all events that have data in the target field
        cursor = await db.execute(
            f"SELECT id, timestamp, {field}, command_line, process_name, parent_process FROM events WHERE case_id = ? AND {field} IS NOT NULL AND {field} != ''",
            (case_id,),
        )
        rows = await cursor.fetchall()

        for ev in rows:
            field_value = ev[field] or ""
            if not compiled_re.search(field_value):
                continue

            # For parent-child patterns, also check child field
            if "child_field" in pattern and "child_regex" in pattern:
                child_val = ev.get(pattern["child_field"]) or ""
                if not re.search(pattern["child_regex"], child_val):
                    continue

            await _create_finding(db, case_id, ev["id"], pattern_id, title, desc, severity, mitre, now, {
                "matched_field": field,
                "matched_value": field_value[:500],
            })
            findings_count += 1

    await db.commit()
    return findings_count


async def _create_finding(
    db: aiosqlite.Connection,
    case_id: str,
    event_id: str,
    rule_id: str,
    title: str,
    description: str,
    severity: str,
    mitre: Optional[str],
    now: str,
    evidence_data: dict,
) -> None:
    """Insert a suspicious pattern finding and flag the source event."""
    finding_id = str(uuid.uuid4())

    await db.execute(
        "UPDATE events SET is_suspicious = 1, severity = ?, mitre_technique = COALESCE(mitre_technique, ?) WHERE id = ?",
        (severity if severity in ("high", "critical") else "medium", mitre, event_id),
    )

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
            FindingType.SUSPICIOUS_PATTERN.value,
            title,
            description,
            severity,
            json.dumps(evidence_data),
            rule_id,
            now,
        ),
    )
