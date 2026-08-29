from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from sentinel.domain.enums import EventType

PAYLOAD_VERSION = 1


class Event(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    event_type: EventType
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    source: str
    process_instance_id: str | None = None
    entity_id: str | None = None
    payload_version: int = PAYLOAD_VERSION
    payload: dict[str, Any] = Field(default_factory=dict)

    def model_dump_versioned(self) -> dict[str, Any]:
        """Serialization that always includes version for forward compatibility."""
        d = self.model_dump(mode="json")
        d["payload_version"] = self.payload_version
        return d
