"""IOC model."""

from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel


class IOCType(str, Enum):
    HASH_MD5 = "hash_md5"
    HASH_SHA1 = "hash_sha1"
    HASH_SHA256 = "hash_sha256"
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    FILENAME = "filename"
    EMAIL = "email"
    REGISTRY_KEY = "registry_key"


class IOC(BaseModel):
    """Indicator of Compromise."""

    id: str
    case_id: Optional[str] = None  # None = global IOC
    ioc_type: IOCType
    ioc_value: str
    description: Optional[str] = None
    source: Optional[str] = None
    confidence: str = "medium"
    created_at: datetime
