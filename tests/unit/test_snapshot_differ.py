from __future__ import annotations

from datetime import UTC, datetime

from sentinel.application.snapshot_differ import SnapshotDiffer
from sentinel.domain.enums import EventType, ExposureLevel, Protocol, SocketState
from sentinel.domain.models import (
    NetworkEndpoint,
    ProcessIdentity,
    ProcessObservation,
    SocketObservation,
)


def _proc(pid: int, start_time: float = 1000.0) -> ProcessObservation:
    return ProcessObservation(
        identity=ProcessIdentity(pid=pid, name=f"proc-{pid}", start_time=start_time),
        observed_at=datetime.now(UTC),
    )


def _listener(pid: int, port: int) -> SocketObservation:
    return SocketObservation(
        pid=pid,
        local_endpoint=NetworkEndpoint(address="0.0.0.0", port=port, protocol=Protocol.TCP),
        socket_state=SocketState.LISTEN,
        listening=True,
        exposure=ExposureLevel.ALL_INTERFACES,
    )


differ = SnapshotDiffer()


def test_process_started() -> None:
    prev: list[ProcessObservation] = []
    curr = [_proc(100)]
    events = differ.diff_processes(prev, curr)
    assert len(events) == 1
    assert events[0].event_type == EventType.PROCESS_STARTED
    assert events[0].payload["pid"] == 100


def test_process_stopped() -> None:
    prev = [_proc(200)]
    curr: list[ProcessObservation] = []
    events = differ.diff_processes(prev, curr)
    assert len(events) == 1
    assert events[0].event_type == EventType.PROCESS_STOPPED


def test_no_event_for_unchanged_process() -> None:
    p = _proc(300)
    events = differ.diff_processes([p], [p])
    assert events == []


def test_pid_reuse_generates_stop_and_start() -> None:
    old = _proc(pid=400, start_time=1000.0)
    new = _proc(pid=400, start_time=2000.0)
    events = differ.diff_processes([old], [new])
    types = {e.event_type for e in events}
    assert EventType.PROCESS_STARTED in types
    assert EventType.PROCESS_STOPPED in types


def test_port_opened() -> None:
    prev: list[SocketObservation] = []
    curr = [_listener(100, 8080)]
    events = differ.diff_sockets(prev, curr)
    assert any(e.event_type == EventType.PORT_OPENED for e in events)


def test_port_closed() -> None:
    prev = [_listener(100, 8080)]
    curr: list[SocketObservation] = []
    events = differ.diff_sockets(prev, curr)
    assert any(e.event_type == EventType.PORT_CLOSED for e in events)


def test_unchanged_listener_no_event() -> None:
    sock = _listener(100, 9090)
    events = differ.diff_sockets([sock], [sock])
    assert events == []
