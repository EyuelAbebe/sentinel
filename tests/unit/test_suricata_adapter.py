"""Unit tests for the Suricata eve.json adapter."""

from __future__ import annotations

import json

import pytest

from sentinel.adapters.suricata_adapter import SuricataAdapter, _parse_line
from sentinel.domain.enums import EventType, Protocol

# ── _parse_line ────────────────────────────────────────────────────────────────


def test_parse_line_returns_none_for_empty() -> None:
    assert _parse_line("") is None
    assert _parse_line("   ") is None


def test_parse_line_returns_none_for_invalid_json() -> None:
    assert _parse_line("not json at all") is None
    assert _parse_line("{bad json}") is None


def test_parse_line_returns_none_for_unknown_event_type() -> None:
    record = {"event_type": "dns", "timestamp": "2024-01-01T00:00:00Z"}
    assert _parse_line(json.dumps(record)) is None


def test_parse_flow_record_tcp() -> None:
    record = {
        "timestamp": "2024-01-15T10:00:00.000000+0000",
        "event_type": "flow",
        "src_ip": "192.168.1.10",
        "src_port": 54321,
        "dest_ip": "93.184.216.34",
        "dest_port": 443,
        "proto": "TCP",
        "app_proto": "tls",
        "flow": {"bytes_toserver": 1024, "bytes_toclient": 4096},
    }
    event = _parse_line(json.dumps(record))
    assert event is not None
    assert event.event_type == EventType.CONNECTION_OPENED
    assert event.source == "suricata"
    assert event.payload["src_ip"] == "192.168.1.10"
    assert event.payload["dst_ip"] == "93.184.216.34"
    assert event.payload["dst_port"] == 443
    assert event.payload["proto"] == Protocol.TCP
    assert event.payload["service"] == "tls"
    assert event.payload["bytes_toserver"] == 1024


def test_parse_flow_record_udp() -> None:
    record = {
        "timestamp": "2024-01-15T10:00:01Z",
        "event_type": "flow",
        "src_ip": "10.0.0.1",
        "src_port": 5353,
        "dest_ip": "224.0.0.251",
        "dest_port": 5353,
        "proto": "UDP",
        "flow": {},
    }
    event = _parse_line(json.dumps(record))
    assert event is not None
    assert event.payload["proto"] == Protocol.UDP


def test_parse_alert_record() -> None:
    record = {
        "timestamp": "2024-01-15T10:00:02+0000",
        "event_type": "alert",
        "src_ip": "10.0.0.5",
        "dest_ip": "185.220.101.1",
        "dest_port": 9001,
        "proto": "TCP",
        "alert": {
            "signature": "ET TOR Known Tor Exit Node Traffic",
            "category": "Misc Attack",
            "severity": 2,
            "gid": 1,
            "signature_id": 2520004,
        },
    }
    event = _parse_line(json.dumps(record))
    assert event is not None
    assert event.event_type == EventType.FINDING_CREATED
    assert event.payload["signature"] == "ET TOR Known Tor Exit Node Traffic"
    assert event.payload["severity"] == 2
    assert event.payload["signature_id"] == 2520004


def test_parse_flow_unknown_proto() -> None:
    record = {
        "timestamp": "2024-01-15T10:00:03Z",
        "event_type": "flow",
        "src_ip": "1.2.3.4",
        "dest_ip": "5.6.7.8",
        "dest_port": 0,
        "proto": "ICMP",
        "flow": {},
    }
    event = _parse_line(json.dumps(record))
    assert event is not None
    assert event.payload["proto"] == Protocol.UNKNOWN


# ── SuricataAdapter.read_file ──────────────────────────────────────────────────


@pytest.fixture
def eve_json(tmp_path: pytest.TempPathFactory) -> str:
    records = [
        {
            "timestamp": "2024-01-15T10:00:00+0000",
            "event_type": "flow",
            "src_ip": "192.168.1.10",
            "src_port": 54321,
            "dest_ip": "93.184.216.34",
            "dest_port": 443,
            "proto": "TCP",
            "flow": {"bytes_toserver": 500},
        },
        {
            "timestamp": "2024-01-15T10:00:01+0000",
            "event_type": "alert",
            "src_ip": "10.0.0.5",
            "dest_ip": "1.2.3.4",
            "dest_port": 4444,
            "proto": "TCP",
            "alert": {
                "signature": "MALWARE test",
                "severity": 1,
                "category": "Malware",
                "gid": 1,
                "signature_id": 12345,
            },
        },
        # dns event should be ignored
        {"timestamp": "2024-01-15T10:00:02+0000", "event_type": "dns"},
        {
            "timestamp": "2024-01-15T10:00:03+0000",
            "event_type": "flow",
            "src_ip": "10.0.0.1",
            "src_port": 1024,
            "dest_ip": "8.8.8.8",
            "dest_port": 53,
            "proto": "UDP",
            "flow": {},
        },
    ]
    content = "\n".join(json.dumps(r) for r in records) + "\n"
    p = tmp_path / "eve.json"
    p.write_text(content)
    return str(p)


@pytest.mark.asyncio
async def test_read_file_parses_flow_and_alert(eve_json: str) -> None:
    adapter = SuricataAdapter(eve_json)
    events = await adapter.read_file()
    # 2 flows + 1 alert = 3 events; dns is ignored
    assert len(events) == 3


@pytest.mark.asyncio
async def test_read_file_event_types(eve_json: str) -> None:
    adapter = SuricataAdapter(eve_json)
    events = await adapter.read_file()
    event_types = {e.event_type for e in events}
    assert EventType.CONNECTION_OPENED in event_types
    assert EventType.FINDING_CREATED in event_types


@pytest.mark.asyncio
async def test_read_file_missing_file_returns_empty(tmp_path: pytest.TempPathFactory) -> None:
    adapter = SuricataAdapter(tmp_path / "no_such_file.json")
    events = await adapter.read_file()
    assert events == []


# ── SuricataAdapter.available ─────────────────────────────────────────────────


def test_available_true_when_file_exists(eve_json: str) -> None:
    assert SuricataAdapter(eve_json).available is True


def test_available_false_when_file_missing(tmp_path: pytest.TempPathFactory) -> None:
    assert SuricataAdapter(tmp_path / "missing.json").available is False
