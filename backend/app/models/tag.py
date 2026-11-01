"""Tag model."""

from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel


class TagEntityType(str, Enum):
    EVENT = "event"
    ARTIFACT = "artifact"
    FINDING = "finding"


class Tag(BaseModel):
    """A tag attached to an event, artifact, or finding."""

    id: str
    case_id: str
    entity_type: TagEntityType
    entity_id: str
    tag_name: str
    tag_color: Optional[str] = None
    created_at: datetime
    created_by: Optional[str] = None
