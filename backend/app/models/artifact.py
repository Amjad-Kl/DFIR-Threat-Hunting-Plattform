"""Artifact model."""

from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class ArtifactType(str, Enum):
    EVTX = "evtx"
    REGISTRY = "registry"
    PREFETCH = "prefetch"
    AMCACHE = "amcache"
    YARA_TARGET = "yara_target"  # File to scan with YARA


class ParsingStatus(str, Enum):
    PENDING = "pending"
    PARSING = "parsing"
    DONE = "done"
    ERROR = "error"


class Artifact(BaseModel):
    """Imported artifact metadata."""

    id: str
    case_id: str
    filename: str
    filepath: str
    artifact_type: ArtifactType
    file_size: Optional[int] = None
    sha256: str
    import_time: datetime
    imported_by: Optional[str] = None
    source_host: Optional[str] = None
    parsing_status: ParsingStatus = ParsingStatus.PENDING
    parsing_error: Optional[str] = None
    event_count: int = 0
