from __future__ import annotations

import json

from sentinel.domain.events import Event
from sentinel.domain.enums import EventType
from sentinel.domain.models import ProcessIdentity, SocketObservation, NetworkEndpoint
from sentinel.domain.enums import ExposureLevel, Protocol, SocketState


def test_process_instance_id_stable_across_instantiations() -> None:
    a = ProcessIdentity(pid=1234, name="foo", start_time=1000.0)
    b = ProcessIdentity(pid=1234, name="foo", start_time=1000.0)
    assert a.instance_id == b.instance_id


def test_process_instance_id_differs_on_pid_reuse() -> None:
    """Same PID, different start_time => different instance."""
    a = ProcessIdentity(pid=1234, name="foo", start_time=1000.0)
    b = ProcessIdentity(pid=1234, name="bar", start_time=2000.0)
    assert a.instance_id != b.instance_id


def test_is_in_suspicious_location_downloads() -> None:
    p = ProcessIdentity(pid=1, name="x", start_time=1.0, executable_path="/Users/me/Downloads/evil")
    assert p.is_in_suspicious_location()


def test_is_not_in_suspicious_location_usr_bin() -> None:
    p = ProcessIdentity(pid=1, name="x", start_time=1.0, executable_path="/usr/bin/python3")
    assert not p.is_in_suspicious_location()


def test_event_versioned_serialization() -> None:
    event = Event(event_type=EventType.PROCESS_STARTED, source="test", payload={"pid": 1})
    d = event.model_dump_versioned()
    assert d["payload_version"] == 1
    assert d["event_type"] == EventType.PROCESS_STARTED
    # Must be JSON-serializable
    json.dumps(d)


def test_socket_key_uniqueness() -> None:
    ep_a = NetworkEndpoint(address="127.0.0.1", port=8080, protocol=Protocol.TCP)
    ep_b = NetworkEndpoint(address="127.0.0.1", port=9090, protocol=Protocol.TCP)
    s_a = SocketObservation(local_endpoint=ep_a, listening=True, exposure=ExposureLevel.LOOPBACK, pid=100)
    s_b = SocketObservation(local_endpoint=ep_b, listening=True, exposure=ExposureLevel.LOOPBACK, pid=100)
    assert s_a.socket_key != s_b.socket_key
