from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

from sentinel.domain.enums import IdentityStatus, PrivacyCategory


class ClassificationEvidence(BaseModel):
    subject_type: str
    subject: str
    identity_status: IdentityStatus = IdentityStatus.UNKNOWN
    organization: str | None = None
    category: PrivacyCategory | None = None
    reputation: str | None = None
    source: str = "local"
    source_version: str = "0"
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    observed_at: datetime = Field(default_factory=datetime.utcnow)
