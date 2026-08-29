"""Unit tests for BaselineRepository, BaselineService, and FindingEngine baseline integration."""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from sentinel.application.baseline_service import BaselineService
from sentinel.application.correlation import CorrelatedProcess
from sentinel.application.finding_engine import FindingEngine
from sentinel.domain.enums import ExposureLevel, FindingStatus, Protocol, SocketState
from sentinel.domain.models import (
    NetworkEndpoint,
    ProcessIdentity,
    ProcessObservation,
    SocketObservation,
)
from sentinel.storage.baseline_repository import BaselineRepository
from sentinel.storage.models import Base

# ── fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture
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


@pytest.fixture
def repo(session):
    return BaselineRepository(session)


@pytest.fixture
def svc(repo):
    return BaselineService(repo)


# ── helpers ───────────────────────────────────────────────────────────────────


def _proc(name: str = "test", pid: int = 1) -> CorrelatedProcess:
    identity = ProcessIdentity(
        pid=pid,
        name=name,
        executable_path=f"/usr/bin/{name}",
        command_line=[f"/usr/bin/{name}"],
        user="user",
        parent_pid=1,
        start_time=float(pid * 1_000),
    )
    return CorrelatedProcess(observation=ProcessObservation(identity=identity))


def _listener(
    port: int = 8080, exposure: ExposureLevel = ExposureLevel.ALL_INTERFACES
) -> SocketObservation:
    return SocketObservation(
        pid=1,
        local_endpoint=NetworkEndpoint(address="0.0.0.0", port=port, protocol=Protocol.TCP),
        socket_state=SocketState.LISTEN,
        listening=True,
        exposure=exposure,
    )


# ── BaselineRepository ────────────────────────────────────────────────────────


class TestBaselineRepository:
    def test_write_and_find(self, repo):
        entry = repo.write("process", "Slack")
        assert entry.id is not None
        found = repo.find_by_subject("process", "Slack")
        assert found is not None
        assert found.subject == "Slack"

    def test_write_is_idempotent(self, repo):
        repo.write("port", "5432", reason="postgres")
        repo.write("port", "5432", reason="updated reason")
        assert repo.count() == 1

    def test_delete_returns_true(self, repo):
        entry = repo.write("domain", "example.com")
        assert repo.delete(entry.id) is True
        assert repo.find_by_subject("domain", "example.com") is None

    def test_delete_nonexistent_returns_false(self, repo):
        assert repo.delete(9999) is False

    def test_query_all(self, repo):
        repo.write("process", "Safari")
        repo.write("port", "443")
        entries = repo.query_all()
        assert len(entries) == 2


# ── BaselineService ───────────────────────────────────────────────────────────


class TestBaselineService:
    def test_is_process_expected_true(self, svc):
        svc.add_process("Safari")
        assert svc.is_process_expected("Safari")

    def test_is_process_expected_false(self, svc):
        assert not svc.is_process_expected("unknown-proc")

    def test_is_port_expected(self, svc):
        svc.add_port(5432, reason="postgres")
        assert svc.is_port_expected(5432)
        assert not svc.is_port_expected(5433)

    def test_is_domain_expected(self, svc):
        svc.add_domain("apple.com")
        assert svc.is_domain_expected("apple.com")
        assert not svc.is_domain_expected("other.com")

    def test_remove(self, svc):
        entry = svc.add_process("Chrome")
        assert svc.remove(entry.id)
        assert not svc.is_process_expected("Chrome")


# ── FindingEngine + baseline ──────────────────────────────────────────────────


class TestFindingEngineWithBaseline:
    def test_finding_marked_expected_for_baseline_process(self, svc):
        cp = _proc("Safari")
        cp.listeners.append(_listener(port=443))
        engine = FindingEngine(baseline=svc)
        svc.add_process("Safari")
        findings = engine.evaluate([cp])
        assert findings[0].status == FindingStatus.EXPECTED
        assert findings[0].expected is True

    def test_finding_open_without_baseline(self):
        cp = _proc("Safari")
        cp.listeners.append(_listener(port=443))
        engine = FindingEngine()
        findings = engine.evaluate([cp])
        assert findings[0].status == FindingStatus.OPEN

    def test_baseline_port_suppresses_listener_signal(self, svc):
        cp = _proc("postgres")
        cp.listeners.append(_listener(port=5432))
        engine = FindingEngine(baseline=svc)
        svc.add_port(5432, reason="expected postgres")
        findings = engine.evaluate([cp])
        assert findings == []

    def test_non_baseline_port_still_fires(self, svc):
        cp = _proc("suspicious")
        cp.listeners.append(_listener(port=1337))
        engine = FindingEngine(baseline=svc)
        svc.add_port(5432)
        findings = engine.evaluate([cp])
        assert len(findings) == 1
