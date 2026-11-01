"""Case model."""

from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class CaseStatus(str, Enum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    CLOSED = "closed"


class CaseClassification(str, Enum):
    INCIDENT = "incident"
    INVESTIGATION = "investigation"
    EXERCISE = "exercise"
    THREAT_HUNT = "threat_hunt"


class CaseCreate(BaseModel):
    """Schema for creating a new case."""

    name: str = Field(min_length=1, max_length=255)
    description: Optional[str] = None
    analyst: Optional[str] = None
    classification: CaseClassification = CaseClassification.INVESTIGATION
    time_range_start: Optional[datetime] = None
    time_range_end: Optional[datetime] = None
    notes: Optional[str] = None


class CaseUpdate(BaseModel):
    """Schema for updating a case."""

    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = None
    status: Optional[CaseStatus] = None
    analyst: Optional[str] = None
    classification: Optional[CaseClassification] = None
    time_range_start: Optional[datetime] = None
    time_range_end: Optional[datetime] = None
    notes: Optional[str] = None


class Case(BaseModel):
    """Full case representation."""

    id: str
    name: str
    description: Optional[str] = None
    status: CaseStatus = CaseStatus.OPEN
    created_at: datetime
    updated_at: datetime
    analyst: Optional[str] = None
    classification: CaseClassification = CaseClassification.INVESTIGATION
    time_range_start: Optional[datetime] = None
    time_range_end: Optional[datetime] = None
    notes: Optional[str] = None
    artifact_count: int = 0
    event_count: int = 0
    finding_count: int = 0
