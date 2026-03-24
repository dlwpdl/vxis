from __future__ import annotations
import hashlib
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field, model_validator


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class EvidenceType(str, Enum):
    HTTP_EXCHANGE = "http_exchange"
    MISCONFIGURATION = "misconfiguration"
    SECRET = "secret"
    CODE_FINDING = "code_finding"
    NETWORK = "network"
    OSINT = "osint"
    EXPLOIT = "exploit"
    OTHER = "other"


class Evidence(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    agent_id: str
    title: str
    severity: Severity
    evidence_type: EvidenceType
    description: str
    request: Optional[str] = None
    response: Optional[str] = None
    cvss_score: Optional[float] = None
    chained_from: Optional[str] = None
    poc_script: Optional[str] = None
    tags: list[str] = []
    hash: str = ""

    @model_validator(mode="after")
    def compute_hash(self) -> "Evidence":
        content = (
            f"{self.agent_id}:{self.title}:{self.severity}:"
            f"{self.description}:{self.request}:{self.response}"
        )
        self.hash = hashlib.sha256(content.encode()).hexdigest()
        return self
