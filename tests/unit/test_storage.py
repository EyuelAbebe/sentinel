"""Unit tests for the storage layer — run against an in-memory SQLite database."""

from __future__ import annotations

import datetime
from datetime import UTC

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from sentinel.domain.enums import EventType, FindingStatus, Severity
from sentinel.domain.events import Event
from sentinel.domain.findings import Finding, FindingReason
from sentinel.storage.event_repository import EventRepository
from sentinel.storage.finding_repository import FindingRepository
from sentinel.storage.models import Base


@pytest.fixture()
def session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    s = factory()
    try:
        yield s
        s.commit()
    finally:
        s.close()


def _make_event(event_type: EventType = EventType.PROCESS_STARTED) -> Event:
    return Event(
        event_type=event_type,
        source="test",
        process_instance_id="abc-123",
        payload={"name": "test_proc"},
    )


def _make_finding(severity: Severity = Severity.HIGH) -> Finding:
    return Finding(
        severity=severity,
        title="Test finding",
        subject="test_proc",
        reasons=[FindingReason(signal="test_signal", description="Running from /tmp")],
    )


# ── EventRepository ──────────────────────────────────────────────────────────


class TestEventRepository:
    def test_write_returns_record(self, session):
        repo = EventRepository(session)
        event = _make_event()
        record = repo.write(event)
        assert record.id is not None
        assert record.event_type == EventType.PROCESS_STARTED.value
        assert record.instance_id == "abc-123"

    def test_write_many(self, session):
        repo = EventRepository(session)
        events = [_make_event(EventType.PROCESS_STARTED), _make_event(EventType.PORT_OPENED)]
        records = repo.write_many(events)
        assert len(records) == 2
        assert repo.count() == 2

    def test_query_recent_returns_newest_first(self, session):
        repo = EventRepository(session)
        now = datetime.datetime.now(UTC)
        e1 = Event(
            event_type=EventType.PROCESS_STARTED,
            source="test",
            payload={},
        )
        e1.timestamp = now - datetime.timedelta(seconds=10)
        e2 = Event(
            event_type=EventType.PORT_OPENED,
            source="test",
            payload={},
        )
        e2.timestamp = now
        repo.write(e1)
        repo.write(e2)
        results = repo.query_recent()
        assert results[0].event_type == EventType.PORT_OPENED.value

    def test_query_recent_filters_by_event_type(self, session):
        repo = EventRepository(session)
        repo.write(_make_event(EventType.PROCESS_STARTED))
        repo.write(_make_event(EventType.PORT_OPENED))
        results = repo.query_recent(event_type=EventType.PROCESS_STARTED.value)
        assert len(results) == 1
        assert results[0].event_type == EventType.PROCESS_STARTED.value

    def test_query_recent_respects_limit(self, session):
        repo = EventRepository(session)
        for _ in range(10):
            repo.write(_make_event())
        results = repo.query_recent(limit=3)
        assert len(results) == 3

    def test_count_empty(self, session):
        assert EventRepository(session).count() == 0

    def test_benign_no_writes_count_zero(self, session):
        repo = EventRepository(session)
        assert repo.count() == 0
        assert repo.query_recent() == []


# ── FindingRepository ─────────────────────────────────────────────────────────


class TestFindingRepository:
    def test_write_returns_record(self, session):
        repo = FindingRepository(session)
        finding = _make_finding()
        record = repo.write(finding)
        assert record.id is not None
        assert record.severity == Severity.HIGH.value
        assert record.title == "Test finding"
        assert record.subject == "test_proc"
        assert "Running from /tmp" in record.reasons

    def test_write_many(self, session):
        repo = FindingRepository(session)
        findings = [_make_finding(Severity.HIGH), _make_finding(Severity.MEDIUM)]
        repo.write_many(findings)
        assert repo.count_active() == 2

    def test_query_active_only_returns_open(self, session):
        repo = FindingRepository(session)
        open_finding = _make_finding()
        closed_finding = _make_finding()
        closed_finding.status = FindingStatus.RESOLVED
        repo.write(open_finding)
        repo.write(closed_finding)
        active = repo.query_active()
        assert len(active) == 1
        assert active[0].status == "open"

    def test_query_all_returns_everything(self, session):
        repo = FindingRepository(session)
        f = _make_finding()
        f2 = _make_finding()
        f2.status = FindingStatus.RESOLVED
        repo.write(f)
        repo.write(f2)
        assert len(repo.query_all()) == 2

    def test_write_is_idempotent_on_same_finding_id(self, session):
        repo = FindingRepository(session)
        finding = _make_finding()
        repo.write(finding)
        repo.write(finding)
        assert repo.count_active() == 1

    def test_benign_no_findings_count_zero(self, session):
        repo = FindingRepository(session)
        assert repo.count_active() == 0
        assert repo.query_active() == []
