"""Windows Event Log (EVTX) Parser.

Extracts Security, System, Application, and Sysmon events into NormalizedEvent.
Handles XML schema extraction and missing/corrupt records gracefully.
"""

import json
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Generator, Optional

try:
    import Evtx.Evtx as evtx
    EVTX_AVAILABLE = True
except ImportError:
    EVTX_AVAILABLE = False

from app.models.event import EventSeverity, EventType, NormalizedEvent, SourceType
from app.parsers.base import BaseParser

# Windows Security Event IDs of interest
SECURITY_EVENT_MAP: dict[int, tuple[EventType, EventSeverity]] = {
    4624: (EventType.LOGON, EventSeverity.INFO),
    4625: (EventType.LOGON_FAILED, EventSeverity.MEDIUM),
    4634: (EventType.LOGOFF, EventSeverity.INFO),
    4688: (EventType.PROCESS_CREATE, EventSeverity.LOW),
    4689: (EventType.PROCESS_TERMINATE, EventSeverity.INFO),
    4697: (EventType.SERVICE_INSTALL, EventSeverity.HIGH),
    4698: (EventType.SCHEDULED_TASK, EventSeverity.HIGH),
    4720: (EventType.OTHER, EventSeverity.MEDIUM),  # User created
    4738: (EventType.OTHER, EventSeverity.LOW),     # User modified
}

# Sysmon Event IDs
SYSMON_EVENT_MAP: dict[int, tuple[EventType, EventSeverity]] = {
    1: (EventType.PROCESS_CREATE, EventSeverity.LOW),
    2: (EventType.OTHER, EventSeverity.INFO),            # File creation time changed
    3: (EventType.NETWORK_CONNECTION, EventSeverity.LOW),
    5: (EventType.PROCESS_TERMINATE, EventSeverity.INFO),
    6: (EventType.DRIVER_LOAD, EventSeverity.MEDIUM),
    7: (EventType.IMAGE_LOAD, EventSeverity.INFO),
    8: (EventType.OTHER, EventSeverity.HIGH),            # CreateRemoteThread
    11: (EventType.FILE_CREATE, EventSeverity.INFO),
    12: (EventType.REGISTRY_MODIFY, EventSeverity.LOW),  # Registry Event (Object create/delete)
    13: (EventType.REGISTRY_MODIFY, EventSeverity.LOW),  # Registry Event (Value Set)
    17: (EventType.PIPE_CREATE, EventSeverity.INFO),
    19: (EventType.WMI_EVENT, EventSeverity.HIGH),       # WmiEvent (WmiEventFilter)
    20: (EventType.WMI_EVENT, EventSeverity.HIGH),       # WmiEvent (WmiEventConsumer)
    21: (EventType.WMI_EVENT, EventSeverity.HIGH),       # WmiEvent (WmiEventConsumerToFilter)
    22: (EventType.DNS_QUERY, EventSeverity.INFO),
    23: (EventType.FILE_DELETE, EventSeverity.INFO),
}


class EvtxParser(BaseParser):
    """Parser for Windows Event Log (.evtx) files."""

    def can_parse(self, file_path: Path) -> bool:
        return file_path.suffix.lower() == ".evtx"

    def get_source_type(self) -> str:
        return SourceType.EVTX.value

    @property
    def supported_extensions(self) -> list[str]:
        return [".evtx"]

    def _strip_ns(self, tag: str) -> str:
        return tag.split("}")[-1] if "}" in tag else tag

    def _extract_data_fields(self, root: ET.Element) -> dict[str, str]:
        fields: dict[str, str] = {}
        for elem in root.iter():
            tag = self._strip_ns(elem.tag)
            if tag == "Data":
                name = elem.attrib.get("Name")
                text = (elem.text or "").strip()
                if name:
                    fields[name] = text
        return fields

    def parse(
        self, file_path: Path, case_id: str, artifact_id: str
    ) -> Generator[NormalizedEvent, None, None]:
        """Streamingly yield NormalizedEvent instances from an EVTX file."""
        if not EVTX_AVAILABLE:
            raise RuntimeError("python-evtx library is required to parse EVTX files.")

        with evtx.Evtx(str(file_path)) as log:
            for record in log.records():
                try:
                    xml_str = record.xml()
                    root = ET.fromstring(xml_str)
                except Exception:
                    # Skip corrupt records without halting the entire triage ingestion
                    continue

                event_id: Optional[int] = None
                channel: Optional[str] = None
                timestamp: Optional[datetime] = None
                computer: Optional[str] = None

                # Parse System header
                for elem in root.iter():
                    tag = self._strip_ns(elem.tag)
                    if tag == "EventID":
                        try:
                            event_id = int((elem.text or "").strip())
                        except ValueError:
                            pass
                    elif tag == "Channel":
                        channel = (elem.text or "").strip()
                    elif tag == "Computer":
                        computer = (elem.text or "").strip()
                    elif tag == "TimeCreated":
                        raw_time = elem.attrib.get("SystemTime")
                        if raw_time:
                            try:
                                timestamp = datetime.fromisoformat(raw_time.replace("Z", "+00:00"))
                            except ValueError:
                                pass

                if not timestamp:
                    timestamp = datetime.now(timezone.utc)

                data_fields = self._extract_data_fields(root)

                # Determine source and event mappings
                is_sysmon = channel and "sysmon" in channel.lower()
                source_type = SourceType.SYSMON if is_sysmon else SourceType.EVTX

                if is_sysmon and event_id in SYSMON_EVENT_MAP:
                    ev_type, default_sev = SYSMON_EVENT_MAP[event_id]
                elif not is_sysmon and event_id in SECURITY_EVENT_MAP:
                    ev_type, default_sev = SECURITY_EVENT_MAP[event_id]
                else:
                    ev_type, default_sev = EventType.OTHER, EventSeverity.INFO

                # Extract context fields based on common event structures
                proc_name = data_fields.get("Image") or data_fields.get("NewProcessName") or data_fields.get("ProcessName")
                proc_path = proc_name
                if proc_name and ("\\" in proc_name or "/" in proc_name):
                    proc_name = Path(proc_name).name

                cmdline = data_fields.get("CommandLine")
                parent_proc = data_fields.get("ParentImage") or data_fields.get("ParentProcessName")
                user = data_fields.get("User") or data_fields.get("TargetUserName") or data_fields.get("SubjectUserName")
                src_ip = data_fields.get("SourceIp") or data_fields.get("IpAddress")
                dest_ip = data_fields.get("DestinationIp")
                dest_port_raw = data_fields.get("DestinationPort")
                dest_port = int(dest_port_raw) if dest_port_raw and dest_port_raw.isdigit() else None
                file_target = data_fields.get("TargetFilename") or data_fields.get("FilePath")
                file_hash = data_fields.get("Hashes")
                reg_target = data_fields.get("TargetObject")

                yield NormalizedEvent(
                    id=str(uuid.uuid4()),
                    case_id=case_id,
                    artifact_id=artifact_id,
                    timestamp=timestamp,
                    source_type=source_type,
                    event_type=ev_type,
                    severity=default_sev,
                    source_host=computer,
                    source_user=user,
                    source_ip=src_ip,
                    dest_ip=dest_ip,
                    dest_port=dest_port,
                    process_name=proc_name,
                    process_path=proc_path,
                    parent_process=parent_proc,
                    command_line=cmdline,
                    file_path=file_target,
                    file_hash=file_hash,
                    registry_key=reg_target,
                    raw_data=json.dumps(data_fields),
                    channel=channel,
                    event_id=event_id,
                )
