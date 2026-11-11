"""Normalized event model - the core data structure of the platform.

All parsers normalize their output into this format.
This ensures consistent timeline generation, searching, and correlation.
"""

from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field


class EventSeverity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SourceType(str, Enum):
    EVTX = "evtx"
    SYSMON = "sysmon"
    REGISTRY = "registry"
    PREFETCH = "prefetch"
    AMCACHE = "amcache"


class EventType(str, Enum):
    PROCESS_CREATE = "process_create"
    PROCESS_TERMINATE = "process_terminate"
    NETWORK_CONNECTION = "network_connection"
    FILE_CREATE = "file_create"
    FILE_DELETE = "file_delete"
    REGISTRY_MODIFY = "registry_modify"
    LOGON = "logon"
    LOGON_FAILED = "logon_failed"
    LOGOFF = "logoff"
    SERVICE_INSTALL = "service_install"
    SCHEDULED_TASK = "scheduled_task"
    PERSISTENCE = "persistence"
    PROGRAM_EXECUTION = "program_execution"
    DRIVER_LOAD = "driver_load"
    DNS_QUERY = "dns_query"
    IMAGE_LOAD = "image_load"
    PIPE_CREATE = "pipe_create"
    WMI_EVENT = "wmi_event"
    OTHER = "other"


class NormalizedEvent(BaseModel):
    """The normalized event format used across all parsers and analysis engines.

    This is the single most important data structure in the platform.
    Every parser converts its raw output into this format.
    """

    id: str = Field(description="Unique event ID (UUID)")
    case_id: str
    artifact_id: str
    timestamp: datetime
    source_type: SourceType
    event_type: EventType = EventType.OTHER
    severity: EventSeverity = EventSeverity.INFO

    # Host & User context
    source_host: Optional[str] = None
    source_user: Optional[str] = None
    source_ip: Optional[str] = None
    dest_host: Optional[str] = None
    dest_ip: Optional[str] = None
    dest_port: Optional[int] = None

    # Process context
    process_name: Optional[str] = None
    process_path: Optional[str] = None
    process_pid: Optional[int] = None
    parent_process: Optional[str] = None
    parent_pid: Optional[int] = None
    command_line: Optional[str] = None

    # File context
    file_path: Optional[str] = None
    file_hash: Optional[str] = None

    # Registry context
    registry_key: Optional[str] = None
    registry_value: Optional[str] = None

    # Raw data
    raw_data: Optional[str] = None  # Original content as JSON
    channel: Optional[str] = None  # e.g., Security, System, Sysmon
    event_id: Optional[int] = None  # Windows Event ID

    # Analysis flags
    is_suspicious: bool = False
    is_ioc_match: bool = False

    # ATT&CK (prepared for v2, populated later)
    mitre_tactic: Optional[str] = None
    mitre_technique: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)
