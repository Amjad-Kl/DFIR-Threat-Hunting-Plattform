"""Windows Prefetch File Parser.

Extracts program execution evidence from Windows Prefetch (.pf) files.
Prefetch files record:
  - Executable name and path
  - Run count
  - Last execution timestamps (up to 8 on Win10+)
  - Referenced files/directories loaded during execution

Forensic value: proves that an executable was run on the system.
"""

import json
import struct
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Generator, Optional

from app.models.event import EventSeverity, EventType, NormalizedEvent, SourceType
from app.parsers.base import BaseParser

# Windows FILETIME epoch offset (1601-01-01 to 1970-01-01 in 100ns intervals)
FILETIME_EPOCH_DIFF = 116444736000000000


def filetime_to_datetime(ft: int) -> Optional[datetime]:
    """Convert a Windows FILETIME (100-nanosecond intervals since 1601-01-01) to datetime."""
    if ft == 0 or ft < FILETIME_EPOCH_DIFF:
        return None
    try:
        timestamp_us = (ft - FILETIME_EPOCH_DIFF) // 10  # to microseconds
        return datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=timestamp_us)
    except (ValueError, OverflowError, OSError):
        return None


class PrefetchParser(BaseParser):
    """Parser for Windows Prefetch (.pf) files.

    Supports Prefetch format versions:
      - 17 (Windows XP)
      - 23 (Windows Vista/7)
      - 26 (Windows 8.1)
      - 30 (Windows 10+, MAM compressed)

    Compressed (MAM) Prefetch files (v30) are detected but require
    decompression before parsing; this parser handles uncompressed files
    and falls back gracefully for compressed ones.
    """

    def can_parse(self, file_path: Path) -> bool:
        return file_path.suffix.lower() == ".pf"

    def get_source_type(self) -> str:
        return SourceType.PREFETCH.value

    @property
    def supported_extensions(self) -> list[str]:
        return [".pf"]

    def parse(
        self, file_path: Path, case_id: str, artifact_id: str
    ) -> Generator[NormalizedEvent, None, None]:
        """Parse a Prefetch file and yield execution events."""
        try:
            data = file_path.read_bytes()
        except OSError:
            return

        if len(data) < 84:
            return

        # Check for MAM compression header (Windows 10+)
        if data[:4] == b"MAM\x04":
            # Attempt decompression via Windows API if available
            decompressed = self._try_decompress_mam(data)
            if decompressed is None:
                # Yield a single event noting that file is compressed
                yield NormalizedEvent(
                    id=str(uuid.uuid4()),
                    case_id=case_id,
                    artifact_id=artifact_id,
                    timestamp=datetime.now(timezone.utc),
                    source_type=SourceType.PREFETCH,
                    event_type=EventType.PROGRAM_EXECUTION,
                    severity=EventSeverity.INFO,
                    process_name=file_path.stem.rsplit("-", 1)[0] if "-" in file_path.stem else file_path.stem,
                    raw_data=json.dumps({"note": "MAM-compressed prefetch, decompression unavailable", "filename": file_path.name}),
                )
                return
            data = decompressed

        # Parse the prefetch header
        try:
            version = struct.unpack_from("<I", data, 0)[0]
            # Signature "SCCA" at offset 4
            signature = data[4:8]
            if signature != b"SCCA":
                return

            # File size at offset 12
            # Executable name at offset 16 (60 bytes, UTF-16LE, null terminated)
            exe_name_raw = data[16:76]
            exe_name = exe_name_raw.decode("utf-16-le", errors="replace").split("\x00")[0]

            # Hash at offset 76
            pf_hash = struct.unpack_from("<I", data, 76)[0]

            # Run count and last run timestamps vary by version
            run_count = 0
            last_run_times: list[datetime] = []

            if version == 17:
                # XP: run count at 90, last run at 120
                run_count = struct.unpack_from("<I", data, 90)[0]
                ft = struct.unpack_from("<Q", data, 120)[0]
                ts = filetime_to_datetime(ft)
                if ts:
                    last_run_times.append(ts)

            elif version == 23:
                # Vista/7: run count at 152, last run at 128
                run_count = struct.unpack_from("<I", data, 152)[0]
                ft = struct.unpack_from("<Q", data, 128)[0]
                ts = filetime_to_datetime(ft)
                if ts:
                    last_run_times.append(ts)

            elif version == 26:
                # Win8.1: run count at 208, last run at 128
                run_count = struct.unpack_from("<I", data, 208)[0]
                ft = struct.unpack_from("<Q", data, 128)[0]
                ts = filetime_to_datetime(ft)
                if ts:
                    last_run_times.append(ts)

            elif version == 30:
                # Win10+: run count at 208, 8 last run times at 128
                run_count = struct.unpack_from("<I", data, 208)[0]
                for i in range(8):
                    offset = 128 + (i * 8)
                    if offset + 8 <= len(data):
                        ft = struct.unpack_from("<Q", data, offset)[0]
                        ts = filetime_to_datetime(ft)
                        if ts:
                            last_run_times.append(ts)
            else:
                # Unknown version, try to extract whatever we can
                run_count = 1
                last_run_times.append(datetime.now(timezone.utc))

        except (struct.error, IndexError):
            return

        if not last_run_times:
            last_run_times.append(datetime.now(timezone.utc))

        # Extract referenced file paths (volume info section)
        referenced_files = self._extract_file_references(data, version)

        # Yield one event per recorded execution timestamp
        for i, run_time in enumerate(last_run_times):
            yield NormalizedEvent(
                id=str(uuid.uuid4()),
                case_id=case_id,
                artifact_id=artifact_id,
                timestamp=run_time,
                source_type=SourceType.PREFETCH,
                event_type=EventType.PROGRAM_EXECUTION,
                severity=EventSeverity.LOW,
                process_name=exe_name,
                raw_data=json.dumps({
                    "prefetch_version": version,
                    "run_count": run_count,
                    "pf_hash": f"{pf_hash:08X}",
                    "execution_index": i,
                    "total_timestamps": len(last_run_times),
                    "source_file": file_path.name,
                    "referenced_files_count": len(referenced_files),
                    "referenced_files_sample": referenced_files[:20],
                }),
            )

    def _extract_file_references(self, data: bytes, version: int) -> list[str]:
        """Extract the filename strings section from prefetch data."""
        refs: list[str] = []
        try:
            if version == 17:
                fn_offset = struct.unpack_from("<I", data, 100)[0]
                fn_size = struct.unpack_from("<I", data, 104)[0]
            elif version in (23, 26, 30):
                fn_offset = struct.unpack_from("<I", data, 100)[0]
                fn_size = struct.unpack_from("<I", data, 104)[0]
            else:
                return refs

            if fn_offset + fn_size > len(data):
                return refs

            fn_data = data[fn_offset:fn_offset + fn_size]
            raw_str = fn_data.decode("utf-16-le", errors="replace")
            refs = [s.strip() for s in raw_str.split("\x00") if s.strip()]
        except (struct.error, IndexError):
            pass
        return refs

    def _try_decompress_mam(self, data: bytes) -> Optional[bytes]:
        """Attempt to decompress MAM-compressed (LZXPRESS Huffman) prefetch data.
        
        Uses ctypes to call RtlDecompressBufferEx on Windows.
        Returns None if decompression is not available or fails.
        """
        try:
            import ctypes
            import ctypes.wintypes

            ntdll = ctypes.WinDLL("ntdll")

            COMPRESSION_FORMAT_XPRESS_HUFF = 0x0004

            # Uncompressed size is stored at offset 4 as a uint32
            uncompressed_size = struct.unpack_from("<I", data, 4)[0]
            compressed_data = data[8:]

            output_buffer = ctypes.create_string_buffer(uncompressed_size)
            final_size = ctypes.wintypes.DWORD(0)

            # Workspace size query
            workspace_size = ctypes.wintypes.DWORD(0)
            workspace_fragment_size = ctypes.wintypes.DWORD(0)
            ntdll.RtlGetCompressionWorkSpaceSize(
                ctypes.wintypes.USHORT(COMPRESSION_FORMAT_XPRESS_HUFF),
                ctypes.byref(workspace_size),
                ctypes.byref(workspace_fragment_size),
            )

            workspace = ctypes.create_string_buffer(workspace_size.value)

            status = ntdll.RtlDecompressBufferEx(
                ctypes.wintypes.USHORT(COMPRESSION_FORMAT_XPRESS_HUFF),
                output_buffer,
                ctypes.wintypes.DWORD(uncompressed_size),
                ctypes.c_char_p(compressed_data),
                ctypes.wintypes.DWORD(len(compressed_data)),
                ctypes.byref(final_size),
                workspace,
            )

            if status == 0:  # STATUS_SUCCESS
                return output_buffer.raw[:final_size.value]
            return None

        except (OSError, AttributeError, ImportError):
            return None
