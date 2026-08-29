from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from sentinel.domain.findings import Finding
from sentinel.storage.models import FindingRecord


class FindingRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def write(self, finding: Finding) -> FindingRecord:
        existing = self._session.scalar(
            select(FindingRecord).where(FindingRecord.finding_id == finding.id)
        )
        if existing:
            existing.severity = finding.severity.value
            existing.status = finding.status.value
            existing.reasons = [r.description for r in finding.reasons]
            self._session.flush()
            return existing

        record = FindingRecord(
            finding_id=finding.id,
            title=finding.title,
            severity=finding.severity.value,
            subject=finding.subject,
            reasons=[r.description for r in finding.reasons],
            occurred_at=finding.first_seen,
            status=finding.status.value,
        )
        self._session.add(record)
        self._session.flush()
        return record

    def write_many(self, findings: list[Finding]) -> list[FindingRecord]:
        return [self.write(f) for f in findings]

    def query_active(self, *, limit: int = 100) -> list[FindingRecord]:
        stmt = (
            select(FindingRecord)
            .where(FindingRecord.status == "open")
            .order_by(FindingRecord.occurred_at.desc())
            .limit(limit)
        )
        return list(self._session.scalars(stmt))

    def query_all(self, *, limit: int = 500) -> list[FindingRecord]:
        stmt = select(FindingRecord).order_by(FindingRecord.occurred_at.desc()).limit(limit)
        return list(self._session.scalars(stmt))

    def count_active(self) -> int:
        from sqlalchemy import func

        return (
            self._session.scalar(
                select(func.count())
                .select_from(FindingRecord)
                .where(FindingRecord.status == "open")
            )
            or 0
        )
