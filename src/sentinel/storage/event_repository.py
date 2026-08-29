from __future__ import annotations

import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from sentinel.domain.events import Event
from sentinel.storage.models import EventRecord


class EventRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def write(self, event: Event) -> EventRecord:
        record = EventRecord(
            event_type=event.event_type.value,
            instance_id=event.process_instance_id or event.entity_id or "",
            occurred_at=event.timestamp,
            payload=event.payload,
            payload_version=event.payload_version,
        )
        self._session.add(record)
        self._session.flush()
        return record

    def write_many(self, events: list[Event]) -> list[EventRecord]:
        return [self.write(e) for e in events]

    def query_recent(
        self,
        *,
        since: datetime.datetime | None = None,
        event_type: str | None = None,
        limit: int = 200,
    ) -> list[EventRecord]:
        stmt = select(EventRecord).order_by(EventRecord.occurred_at.desc())
        if since is not None:
            stmt = stmt.where(EventRecord.occurred_at >= since)
        if event_type is not None:
            stmt = stmt.where(EventRecord.event_type == event_type)
        stmt = stmt.limit(limit)
        return list(self._session.scalars(stmt))

    def count(self) -> int:
        from sqlalchemy import func

        return self._session.scalar(select(func.count()).select_from(EventRecord)) or 0
