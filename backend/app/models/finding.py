"""Finding model - results of analysis runs."""

from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel


class FindingType(str, Enum):
    IOC_MATCH = "ioc_match"
    PERSISTENCE = "persistence"
    SUSPICIOUS_PATTERN = "suspicious_pattern"
    YARA_MATCH = "yara_match"


class Finding(BaseModel):
    """An analysis finding linked to a case and optionally an event."""

    id: str
    case_id: str
    event_id: Optional[str] = None
    finding_type: FindingType
    title: str
    description: Optional[str] = None
    severity: str = "medium"
    evidence: Optional[str] = None  # JSON with supporting evidence
    rule_name: Optional[str] = None
    false_positive: bool = False
    analyst_notes: Optional[str] = None
    created_at: datetime
