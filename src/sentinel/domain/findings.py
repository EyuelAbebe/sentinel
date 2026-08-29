from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, Field

from sentinel.domain.enums import FindingStatus, Severity


class FindingReason(BaseModel):
    signal: str
    description: str


class Finding(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    severity: Severity
    title: str
    status: FindingStatus = FindingStatus.OPEN
    subject: str
    reasons: list[FindingReason] = Field(default_factory=list)
    evidence_refs: list[str] = Field(default_factory=list)
    first_seen: datetime = Field(default_factory=datetime.utcnow)
    last_seen: datetime = Field(default_factory=datetime.utcnow)
    acknowledged: bool = False
    expected: bool = False
