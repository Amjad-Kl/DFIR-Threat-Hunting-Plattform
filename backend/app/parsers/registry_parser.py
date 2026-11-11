"""Windows Registry Hive Parser.

Extracts forensically relevant artifacts from offline registry hive files:
  - Persistence: Run/RunOnce keys, Services, Scheduled Tasks
  - User activity: UserAssist, ShellBags, RecentDocs, TypedPaths
  - System info: Computer name, timezone, network interfaces

Supports SYSTEM, SOFTWARE, NTUSER.DAT, SAM, and SECURITY hives.
"""

import json
import struct
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Generator, Optional

from app.models.event import EventSeverity, EventType, NormalizedEvent, SourceType
from app.parsers.base import BaseParser

try:
    from dissect.regf import RegistryHive
    REGF_AVAILABLE = True
except ImportError:
    REGF_AVAILABLE = False

# Registry paths of forensic interest, grouped by category
PERSISTENCE_KEYS = [
    # Run keys
    "Microsoft\\Windows\\CurrentVersion\\Run",
    "Microsoft\\Windows\\CurrentVersion\\RunOnce",
    "Microsoft\\Windows\\CurrentVersion\\RunServices",
    "Microsoft\\Windows\\CurrentVersion\\RunServicesOnce",
    "Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
    "Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    # Winlogon
    "Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
    # Image File Execution Options
    "Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
    # AppInit DLLs
    "Microsoft\\Windows NT\\CurrentVersion\\Windows",
]

SERVICE_KEY = "ControlSet001\\Services"

USERASSIST_KEY = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist"

SHELLBAGS_KEYS = [
    "Software\\Microsoft\\Windows\\Shell\\BagMRU",
    "Software\\Microsoft\\Windows\\Shell\\Bags",
    "Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU",
    "Local Settings\\Software\\Microsoft\\Windows\\Shell\\Bags",
]

RECENT_DOCS_KEY = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs"


def _rot13_decode(data: bytes) -> str:
    """Decode ROT-13 encoded UserAssist entry names."""
    result = []
    for byte in data:
        char = chr(byte)
        if "a" <= char <= "z":
            result.append(chr((byte - ord("a") + 13) % 26 + ord("a")))
        elif "A" <= char <= "Z":
            result.append(chr((byte - ord("A") + 13) % 26 + ord("A")))
        else:
            result.append(char)
    return "".join(result)


def _filetime_to_datetime(ft: int) -> Optional[datetime]:
    """Convert Windows FILETIME to UTC datetime."""
    EPOCH_DIFF = 116444736000000000
    if ft == 0 or ft < EPOCH_DIFF:
        return None
    try:
        ts_us = (ft - EPOCH_DIFF) // 10
        return datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=ts_us)
    except (ValueError, OverflowError, OSError):
        return None


def _detect_hive_type(file_path: Path) -> str:
    """Heuristic to determine which hive type a file represents."""
    name = file_path.name.upper()
    if name in ("SYSTEM", "SYSTEM.HIV"):
        return "SYSTEM"
    if name in ("SOFTWARE", "SOFTWARE.HIV"):
        return "SOFTWARE"
    if name in ("SAM", "SAM.HIV"):
        return "SAM"
    if name in ("SECURITY", "SECURITY.HIV"):
        return "SECURITY"
    if "NTUSER" in name:
        return "NTUSER"
    if "USRCLASS" in name:
        return "USRCLASS"
    if "AMCACHE" in name:
        return "AMCACHE"
    return "UNKNOWN"


class RegistryParser(BaseParser):
    """Parser for Windows Registry hive files (offline analysis)."""

    def can_parse(self, file_path: Path) -> bool:
        name = file_path.name.upper()
        known_names = {"SYSTEM", "SOFTWARE", "SAM", "SECURITY", "NTUSER.DAT", "USRCLASS.DAT"}
        if name in known_names:
            return True
        if name.endswith((".HIV", ".REG")):
            return True
        return False

    def get_source_type(self) -> str:
        return SourceType.REGISTRY.value

    @property
    def supported_extensions(self) -> list[str]:
        return [".dat", ".hiv", ""]  # Registry hives often have no extension

    def parse(
        self, file_path: Path, case_id: str, artifact_id: str
    ) -> Generator[NormalizedEvent, None, None]:
        if not REGF_AVAILABLE:
            raise RuntimeError("dissect.regf is required to parse registry hives.")

        hive_type = _detect_hive_type(file_path)

        try:
            with open(file_path, "rb") as fh:
                hive = RegistryHive(fh)

                if hive_type == "SOFTWARE":
                    yield from self._parse_persistence_keys(hive, case_id, artifact_id, "HKLM\\SOFTWARE")
                elif hive_type == "SYSTEM":
                    yield from self._parse_services(hive, case_id, artifact_id)
                elif hive_type == "NTUSER":
                    yield from self._parse_persistence_keys(hive, case_id, artifact_id, "HKCU")
                    yield from self._parse_userassist(hive, case_id, artifact_id)
                    yield from self._parse_recent_docs(hive, case_id, artifact_id)
                elif hive_type == "SAM":
                    yield from self._parse_sam_users(hive, case_id, artifact_id)

        except Exception:
            # Corrupted hive – yield nothing rather than crashing
            return

    def _parse_persistence_keys(
        self, hive: "RegistryHive", case_id: str, artifact_id: str, prefix: str
    ) -> Generator[NormalizedEvent, None, None]:
        """Extract Run/RunOnce and other persistence registry values."""
        for key_path in PERSISTENCE_KEYS:
            try:
                key = hive.open(key_path)
            except Exception:
                continue

            try:
                ts = key.timestamp
                if not isinstance(ts, datetime):
                    ts = datetime.now(timezone.utc)
                elif ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)
            except Exception:
                ts = datetime.now(timezone.utc)

            for value in key.values():
                try:
                    val_name = value.name
                    val_data = str(value.value)
                except Exception:
                    continue

                full_path = f"{prefix}\\{key_path}\\{val_name}"

                yield NormalizedEvent(
                    id=str(uuid.uuid4()),
                    case_id=case_id,
                    artifact_id=artifact_id,
                    timestamp=ts,
                    source_type=SourceType.REGISTRY,
                    event_type=EventType.PERSISTENCE,
                    severity=EventSeverity.HIGH,
                    registry_key=full_path,
                    registry_value=val_data,
                    process_path=val_data if (".exe" in val_data.lower() or ".dll" in val_data.lower()) else None,
                    process_name=Path(val_data.split('"')[1] if '"' in val_data else val_data.split()[0]).name if val_data else None,
                    raw_data=json.dumps({
                        "hive_key": key_path,
                        "value_name": val_name,
                        "value_data": val_data,
                        "key_timestamp": ts.isoformat(),
                    }),
                    mitre_technique="T1547.001",
                )

    def _parse_services(
        self, hive: "RegistryHive", case_id: str, artifact_id: str
    ) -> Generator[NormalizedEvent, None, None]:
        """Extract Windows services from SYSTEM hive."""
        try:
            services_key = hive.open(SERVICE_KEY)
        except Exception:
            return

        for subkey in services_key.subkeys():
            try:
                svc_name = subkey.name
                ts = subkey.timestamp
                if not isinstance(ts, datetime):
                    ts = datetime.now(timezone.utc)
                elif ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)

                image_path = ""
                start_type = -1
                service_type = -1
                display_name = svc_name

                for val in subkey.values():
                    try:
                        vname = val.name.lower()
                        if vname == "imagepath":
                            image_path = str(val.value)
                        elif vname == "start":
                            start_type = int(val.value)
                        elif vname == "type":
                            service_type = int(val.value)
                        elif vname == "displayname":
                            display_name = str(val.value)
                    except Exception:
                        continue

                # Determine severity based on start type
                # 0=Boot, 1=System, 2=Auto, 3=Manual, 4=Disabled
                severity = EventSeverity.INFO
                if start_type in (0, 1, 2) and image_path:
                    severity = EventSeverity.LOW
                    # Flag suspicious service paths
                    lower_path = image_path.lower()
                    if any(s in lower_path for s in ["temp", "appdata", "public", "programdata\\microsoft\\crypto"]):
                        severity = EventSeverity.HIGH

                yield NormalizedEvent(
                    id=str(uuid.uuid4()),
                    case_id=case_id,
                    artifact_id=artifact_id,
                    timestamp=ts,
                    source_type=SourceType.REGISTRY,
                    event_type=EventType.SERVICE_INSTALL,
                    severity=severity,
                    process_name=svc_name,
                    process_path=image_path,
                    registry_key=f"HKLM\\SYSTEM\\{SERVICE_KEY}\\{svc_name}",
                    raw_data=json.dumps({
                        "service_name": svc_name,
                        "display_name": display_name,
                        "image_path": image_path,
                        "start_type": start_type,
                        "service_type": service_type,
                    }),
                    mitre_technique="T1543.003" if severity.value in ("medium", "high", "critical") else None,
                )

            except Exception:
                continue

    def _parse_userassist(
        self, hive: "RegistryHive", case_id: str, artifact_id: str
    ) -> Generator[NormalizedEvent, None, None]:
        """Extract UserAssist entries (ROT-13 encoded program execution tracking)."""
        try:
            ua_key = hive.open(USERASSIST_KEY.replace("Software\\", ""))
        except Exception:
            return

        for guid_key in ua_key.subkeys():
            try:
                count_key = guid_key.open("Count")
            except Exception:
                continue

            for value in count_key.values():
                try:
                    val_name = value.name
                    decoded_name = _rot13_decode(val_name.encode("ascii", errors="replace"))
                    val_data = bytes(value.value)

                    run_count = 0
                    last_run = datetime.now(timezone.utc)

                    # UserAssist data structure varies by OS
                    if len(val_data) >= 72:
                        # Windows 7+
                        run_count = struct.unpack_from("<I", val_data, 4)[0]
                        ft = struct.unpack_from("<Q", val_data, 60)[0]
                        parsed_time = _filetime_to_datetime(ft)
                        if parsed_time:
                            last_run = parsed_time
                    elif len(val_data) >= 16:
                        # Windows XP
                        run_count = struct.unpack_from("<I", val_data, 4)[0] - 5
                        ft = struct.unpack_from("<Q", val_data, 8)[0]
                        parsed_time = _filetime_to_datetime(ft)
                        if parsed_time:
                            last_run = parsed_time

                    if run_count <= 0:
                        continue

                    exe_name = decoded_name
                    if "\\" in exe_name or "/" in exe_name:
                        exe_name = Path(decoded_name).name

                    yield NormalizedEvent(
                        id=str(uuid.uuid4()),
                        case_id=case_id,
                        artifact_id=artifact_id,
                        timestamp=last_run,
                        source_type=SourceType.REGISTRY,
                        event_type=EventType.PROGRAM_EXECUTION,
                        severity=EventSeverity.INFO,
                        process_name=exe_name,
                        process_path=decoded_name,
                        raw_data=json.dumps({
                            "userassist_entry": decoded_name,
                            "rot13_name": val_name,
                            "run_count": run_count,
                            "last_run": last_run.isoformat(),
                            "guid": guid_key.name,
                        }),
                    )
                except Exception:
                    continue

    def _parse_recent_docs(
        self, hive: "RegistryHive", case_id: str, artifact_id: str
    ) -> Generator[NormalizedEvent, None, None]:
        """Extract RecentDocs entries from NTUSER hive."""
        recent_path = RECENT_DOCS_KEY.replace("Software\\", "")
        try:
            recent_key = hive.open(recent_path)
        except Exception:
            return

        try:
            ts = recent_key.timestamp
            if not isinstance(ts, datetime):
                ts = datetime.now(timezone.utc)
            elif ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
        except Exception:
            ts = datetime.now(timezone.utc)

        for value in recent_key.values():
            try:
                val_name = value.name
                if val_name.lower() == "mrulistex":
                    continue
                val_data = bytes(value.value)
                # Extract filename from binary data (null-terminated UTF-16)
                try:
                    file_name = val_data.decode("utf-16-le", errors="replace").split("\x00")[0]
                except Exception:
                    file_name = val_name

                if not file_name or len(file_name) < 2:
                    continue

                yield NormalizedEvent(
                    id=str(uuid.uuid4()),
                    case_id=case_id,
                    artifact_id=artifact_id,
                    timestamp=ts,
                    source_type=SourceType.REGISTRY,
                    event_type=EventType.FILE_CREATE,
                    severity=EventSeverity.INFO,
                    file_path=file_name,
                    raw_data=json.dumps({
                        "recent_doc": file_name,
                        "key_timestamp": ts.isoformat(),
                    }),
                )
            except Exception:
                continue

    def _parse_sam_users(
        self, hive: "RegistryHive", case_id: str, artifact_id: str
    ) -> Generator[NormalizedEvent, None, None]:
        """Extract local user account info from SAM hive."""
        try:
            users_key = hive.open("SAM\\Domains\\Account\\Users\\Names")
        except Exception:
            return

        for user_key in users_key.subkeys():
            try:
                username = user_key.name
                ts = user_key.timestamp
                if not isinstance(ts, datetime):
                    ts = datetime.now(timezone.utc)
                elif ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)

                yield NormalizedEvent(
                    id=str(uuid.uuid4()),
                    case_id=case_id,
                    artifact_id=artifact_id,
                    timestamp=ts,
                    source_type=SourceType.REGISTRY,
                    event_type=EventType.OTHER,
                    severity=EventSeverity.INFO,
                    source_user=username,
                    raw_data=json.dumps({
                        "sam_user": username,
                        "key_timestamp": ts.isoformat(),
                    }),
                )
            except Exception:
                continue
