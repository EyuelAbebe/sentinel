from __future__ import annotations

import datetime
from datetime import UTC

from sqlalchemy import select
from sqlalchemy.orm import Session

from sentinel.storage.models import BaselineEntry


class BaselineRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def write(
        self,
        subject_type: str,
        subject: str,
        reason: str = "",
        added_by: str = "user",
    ) -> BaselineEntry:
        existing = self._session.scalar(
            select(BaselineEntry).where(
                BaselineEntry.subject_type == subject_type,
                BaselineEntry.subject == subject,
            )
        )
        if existing:
            existing.reason = reason
            self._session.flush()
            return existing

        entry = BaselineEntry(
            subject_type=subject_type,
            subject=subject,
            reason=reason,
            added_at=datetime.datetime.now(UTC),
            added_by=added_by,
        )
        self._session.add(entry)
        self._session.flush()
        return entry

    def delete(self, entry_id: int) -> bool:
        entry = self._session.get(BaselineEntry, entry_id)
        if entry is None:
            return False
        self._session.delete(entry)
        self._session.flush()
        return True

    def query_all(self) -> list[BaselineEntry]:
        stmt = select(BaselineEntry).order_by(BaselineEntry.added_at.desc())
        return list(self._session.scalars(stmt))

    def find_by_subject(self, subject_type: str, subject: str) -> BaselineEntry | None:
        return self._session.scalar(
            select(BaselineEntry).where(
                BaselineEntry.subject_type == subject_type,
                BaselineEntry.subject == subject,
            )
        )

    def count(self) -> int:
        from sqlalchemy import func

        return self._session.scalar(select(func.count()).select_from(BaselineEntry)) or 0
