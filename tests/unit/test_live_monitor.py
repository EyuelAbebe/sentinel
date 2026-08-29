"""Unit tests for LiveMonitorService."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from sentinel.application.event_bus import EventBus
from sentinel.application.live_monitor import LiveMonitorService
from sentinel.domain.enums import EventType
from sentinel.domain.models import ProcessIdentity, ProcessObservation
from sentinel.storage.event_repository import EventRepository
from sentinel.storage.models import Base

# ── helpers ──────────────────────────────────────────────────────────────────


def _proc(pid: int, name: str) -> ProcessObservation:
    identity = ProcessIdentity(
        pid=pid,
        name=name,
        executable_path=f"/usr/bin/{name}",
        command_line=[f"/usr/bin/{name}"],
        user="user",
        parent_pid=1,
        start_time=float(pid * 1_000),
    )
    return ProcessObservation(identity=identity)


# ── fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture
def bus():
    return EventBus()


@pytest.fixture
def collectors():
    procs = AsyncMock()
    nets = AsyncMock()
    procs.snapshot.return_value = []
    nets.snapshot.return_value = []
    return procs, nets


@pytest.fixture
def mem_engine():
    eng = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(eng)
    return eng


# ── lifecycle ─────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_start_sets_running(collectors, bus):
    procs, nets = collectors
    svc = LiveMonitorService(procs, nets, bus, poll_interval=60.0)
    assert not svc.is_running
    await svc.start()
    assert svc.is_running
    await svc.stop()


@pytest.mark.asyncio
async def test_stop_clears_running(collectors, bus):
    procs, nets = collectors
    svc = LiveMonitorService(procs, nets, bus, poll_interval=60.0)
    await svc.start()
    await svc.stop()
    assert not svc.is_running


@pytest.mark.asyncio
async def test_double_start_is_noop(collectors, bus):
    procs, nets = collectors
    svc = LiveMonitorService(procs, nets, bus, poll_interval=60.0)
    await svc.start()
    original_task = svc._task
    await svc.start()
    assert svc._task is original_task
    await svc.stop()


# ── event emission ────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_tick_emits_process_started(collectors, bus):
    procs, nets = collectors
    procs.snapshot.return_value = [_proc(42, "foo")]
    received: list = []

    async def capture(e):
        received.append(e)

    bus.subscribe(EventType.PROCESS_STARTED, capture)
    svc = LiveMonitorService(procs, nets, bus, poll_interval=60.0)
    await svc._tick()

    assert len(received) == 1
    assert received[0].payload["pid"] == 42
    assert received[0].payload["name"] == "foo"


@pytest.mark.asyncio
async def test_tick_emits_process_stopped(collectors, bus):
    procs, nets = collectors
    procs.snapshot.return_value = [_proc(42, "foo")]
    svc = LiveMonitorService(procs, nets, bus, poll_interval=60.0)
    await svc._tick()  # baseline

    procs.snapshot.return_value = []
    stopped: list = []

    async def capture(e):
        stopped.append(e)

    bus.subscribe(EventType.PROCESS_STOPPED, capture)
    await svc._tick()

    assert len(stopped) == 1
    assert stopped[0].payload["name"] == "foo"


@pytest.mark.asyncio
async def test_tick_no_events_when_state_unchanged(collectors, bus):
    procs, nets = collectors
    procs.snapshot.return_value = [_proc(1, "stable")]
    received: list = []

    async def capture(e):
        received.append(e)

    bus.subscribe_all(capture)
    svc = LiveMonitorService(procs, nets, bus, poll_interval=60.0)
    await svc._tick()  # first tick — emits PROCESS_STARTED
    received.clear()
    await svc._tick()  # same state — no events
    assert received == []


# ── graceful degradation ──────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_tick_collector_failure_is_graceful(collectors, bus):
    procs, nets = collectors
    procs.snapshot.side_effect = RuntimeError("boom")
    nets.snapshot.side_effect = RuntimeError("boom")
    svc = LiveMonitorService(procs, nets, bus, poll_interval=60.0)
    await svc._tick()  # must not raise


# ── persistence ───────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_tick_persists_events_when_engine_given(collectors, bus, mem_engine):
    procs, nets = collectors
    procs.snapshot.return_value = [_proc(7, "bar")]
    svc = LiveMonitorService(procs, nets, bus, engine=mem_engine, poll_interval=60.0)
    await svc._tick()

    with Session(mem_engine) as session:
        count = EventRepository(session).count()
    assert count == 1


@pytest.mark.asyncio
async def test_tick_no_persist_without_engine(collectors, bus):
    procs, nets = collectors
    procs.snapshot.return_value = [_proc(7, "bar")]
    svc = LiveMonitorService(procs, nets, bus, poll_interval=60.0)
    await svc._tick()  # must not raise without engine
