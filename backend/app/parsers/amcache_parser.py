"""Amcache.hve Parser.

Extracts program execution and driver installation evidence from the
Windows Amcache registry hive (C:\\Windows\\appcompat\\Programs\\Amcache.hve).

Key forensic artifacts:
  - InventoryApplicationFile: programs with SHA-1 hashes and install paths
  - InventoryDriverBinary: loaded drivers with hashes
  - File entries (legacy format): execution evidence pre-Win10

The Amcache proves that a binary *existed* on the system and was catalogued
by the Application Compatibility subsystem, even if the binary has been deleted.
"""

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Generator, Optional

from app.models.event import EventSeverity, EventType, NormalizedEvent, SourceType
from app.parsers.base import BaseParser

try:
    from dissect.regf import RegistryHive
    REGF_AVAILABLE = True
except ImportError:
    REGF_AVAILABLE = False

# Modern Amcache paths (Windows 10+)
INVENTORY_APP_FILE = "Root\\InventoryApplicationFile"
INVENTORY_DRIVER = "Root\\InventoryDriverBinary"
# Legacy Amcache paths (Windows 7/8)
LEGACY_FILE_PATH = "Root\\File"


class AmcacheParser(BaseParser):
    """Parser for Windows Amcache.hve registry hive."""

    def can_parse(self, file_path: Path) -> bool:
        return "amcache" in file_path.name.lower()

    def get_source_type(self) -> str:
        return SourceType.AMCACHE.value

    @property
    def supported_extensions(self) -> list[str]:
        return [".hve", ""]

    def parse(
        self, file_path: Path, case_id: str, artifact_id: str
    ) -> Generator[NormalizedEvent, None, None]:
        if not REGF_AVAILABLE:
            raise RuntimeError("dissect.regf is required to parse Amcache hives.")

        try:
            with open(file_path, "rb") as fh:
                hive = RegistryHive(fh)
                yield from self._parse_inventory_app(hive, case_id, artifact_id)
                yield from self._parse_inventory_drivers(hive, case_id, artifact_id)
                yield from self._parse_legacy_files(hive, case_id, artifact_id)
        except Exception:
            return

    def _get_value_safe(self, key, name: str, default=None):
        """Safely retrieve a registry value by name."""
        try:
            for v in key.values():
                if v.name.lower() == name.lower():
                    return v.value
        except Exception:
            pass
        return default

    def _parse_ts(self, key) -> datetime:
        """Extract timestamp from registry key, with fallback."""
        try:
            ts = key.timestamp
            if isinstance(ts, datetime):
                if ts.tzinfo is None:
                    return ts.replace(tzinfo=timezone.utc)
                return ts
        except Exception:
            pass
        return datetime.now(timezone.utc)

    def _parse_inventory_app(
        self, hive: "RegistryHive", case_id: str, artifact_id: str
    ) -> Generator[NormalizedEvent, None, None]:
        """Parse InventoryApplicationFile entries (Win10+ format)."""
        try:
            inv_key = hive.open(INVENTORY_APP_FILE)
        except Exception:
            return

        for entry in inv_key.subkeys():
            try:
                ts = self._parse_ts(entry)
                name = self._get_value_safe(entry, "Name", "")
                lower_path = self._get_value_safe(entry, "LowerCaseLongPath", "")
                publisher = self._get_value_safe(entry, "Publisher", "")
                version = self._get_value_safe(entry, "Version", "")
                sha1 = self._get_value_safe(entry, "FileId", "")
                product_name = self._get_value_safe(entry, "ProductName", "")
                program_id = self._get_value_safe(entry, "ProgramId", "")
                size = self._get_value_safe(entry, "Size", 0)
                link_date = self._get_value_safe(entry, "LinkDate", "")
                bin_type = self._get_value_safe(entry, "BinFileVersion", "")

                # Clean up SHA-1 (often prefixed with "0000")
                if sha1 and isinstance(sha1, str) and sha1.startswith("0000"):
                    sha1 = sha1[4:]

                severity = EventSeverity.INFO
                # Flag executables from suspicious locations
                if lower_path:
                    lp = str(lower_path).lower()
                    if any(s in lp for s in ["\\temp\\", "\\appdata\\local\\temp", "\\public\\", "\\downloads\\"]):
                        severity = EventSeverity.MEDIUM

                yield NormalizedEvent(
                    id=str(uuid.uuid4()),
                    case_id=case_id,
                    artifact_id=artifact_id,
                    timestamp=ts,
                    source_type=SourceType.AMCACHE,
                    event_type=EventType.PROGRAM_EXECUTION,
                    severity=severity,
                    process_name=str(name) if name else None,
                    process_path=str(lower_path) if lower_path else None,
                    file_hash=str(sha1) if sha1 else None,
                    raw_data=json.dumps({
                        "name": str(name),
                        "path": str(lower_path),
                        "publisher": str(publisher),
                        "version": str(version),
                        "sha1": str(sha1),
                        "product_name": str(product_name),
                        "program_id": str(program_id),
                        "size": size,
                        "link_date": str(link_date),
                        "bin_version": str(bin_type),
                        "entry_key": entry.name,
                    }),
                )
            except Exception:
                continue

    def _parse_inventory_drivers(
        self, hive: "RegistryHive", case_id: str, artifact_id: str
    ) -> Generator[NormalizedEvent, None, None]:
        """Parse InventoryDriverBinary entries."""
        try:
            drv_key = hive.open(INVENTORY_DRIVER)
        except Exception:
            return

        for entry in drv_key.subkeys():
            try:
                ts = self._parse_ts(entry)
                driver_name = self._get_value_safe(entry, "DriverName", entry.name)
                driver_path = entry.name  # Key name is often the path
                driver_company = self._get_value_safe(entry, "DriverCompany", "")
                driver_signed = self._get_value_safe(entry, "DriverSigned", "")
                driver_version = self._get_value_safe(entry, "DriverVersion", "")

                severity = EventSeverity.INFO
                if not driver_signed or str(driver_signed) == "0":
                    severity = EventSeverity.HIGH

                yield NormalizedEvent(
                    id=str(uuid.uuid4()),
                    case_id=case_id,
                    artifact_id=artifact_id,
                    timestamp=ts,
                    source_type=SourceType.AMCACHE,
                    event_type=EventType.DRIVER_LOAD,
                    severity=severity,
                    process_name=str(driver_name),
                    process_path=str(driver_path),
                    raw_data=json.dumps({
                        "driver_name": str(driver_name),
                        "driver_path": str(driver_path),
                        "company": str(driver_company),
                        "signed": str(driver_signed),
                        "version": str(driver_version),
                    }),
                )
            except Exception:
                continue

    def _parse_legacy_files(
        self, hive: "RegistryHive", case_id: str, artifact_id: str
    ) -> Generator[NormalizedEvent, None, None]:
        """Parse legacy Root\\File entries (pre-Win10 Amcache format)."""
        try:
            file_key = hive.open(LEGACY_FILE_PATH)
        except Exception:
            return

        for vol_key in file_key.subkeys():
            for entry in vol_key.subkeys():
                try:
                    ts = self._parse_ts(entry)
                    # Legacy format uses numbered value names
                    name = self._get_value_safe(entry, "15", "")       # FullPath
                    sha1 = self._get_value_safe(entry, "101", "")      # SHA-1
                    product = self._get_value_safe(entry, "0", "")     # Product Name
                    company = self._get_value_safe(entry, "1", "")     # Company Name
                    size = self._get_value_safe(entry, "6", 0)         # File Size

                    if sha1 and isinstance(sha1, str) and sha1.startswith("0000"):
                        sha1 = sha1[4:]

                    if not name:
                        continue

                    yield NormalizedEvent(
                        id=str(uuid.uuid4()),
                        case_id=case_id,
                        artifact_id=artifact_id,
                        timestamp=ts,
                        source_type=SourceType.AMCACHE,
                        event_type=EventType.PROGRAM_EXECUTION,
                        severity=EventSeverity.INFO,
                        process_name=Path(str(name)).name if name else None,
                        process_path=str(name),
                        file_hash=str(sha1) if sha1 else None,
                        raw_data=json.dumps({
                            "path": str(name),
                            "sha1": str(sha1),
                            "product": str(product),
                            "company": str(company),
                            "size": size,
                        }),
                    )
                except Exception:
                    continue
