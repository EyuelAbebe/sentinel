"""Unit tests for the Zeek conn.log adapter."""

from __future__ import annotations

import textwrap

import pytest

from sentinel.adapters.zeek_adapter import ZeekAdapter, _parse_line
from sentinel.domain.enums import EventType, Protocol

# ── _parse_line ────────────────────────────────────────────────────────────────


def test_parse_line_returns_none_for_comment() -> None:
    assert _parse_line("#fields\tts\tuid\tid.orig_h") is None


def test_parse_line_returns_none_for_empty() -> None:
    assert _parse_line("") is None
    assert _parse_line("   ") is None


def test_parse_line_returns_none_for_too_few_columns() -> None:
    assert _parse_line("1234567890.0\tuid\t192.168.1.1") is None


def test_parse_line_parses_tcp_connection() -> None:
    line = "1700000000.000000\tCabc123\t192.168.1.10\t54321\t93.184.216.34\t443\ttcp\tssl"
    event = _parse_line(line)
    assert event is not None
    assert event.event_type == EventType.CONNECTION_OPENED
    assert event.source == "zeek"
    assert event.payload["src_ip"] == "192.168.1.10"
    assert event.payload["dst_ip"] == "93.184.216.34"
    assert event.payload["dst_port"] == 443
    assert event.payload["proto"] == Protocol.TCP
    assert event.payload["service"] == "ssl"


def test_parse_line_parses_udp_connection() -> None:
    line = "1700000001.000000\tCxyz456\t10.0.0.5\t1024\t8.8.8.8\t53\tudp\tdns"
    event = _parse_line(line)
    assert event is not None
    assert event.payload["proto"] == Protocol.UDP
    assert event.payload["dst_port"] == 53


def test_parse_line_unknown_proto() -> None:
    line = "1700000002.000000\tCdef789\t10.0.0.1\t0\t10.0.0.2\t0\ticmp\t-"
    event = _parse_line(line)
    assert event is not None
    assert event.payload["proto"] == Protocol.UNKNOWN


def test_parse_line_service_dash_becomes_none() -> None:
    line = "1700000003.000000\tCghi012\t192.168.1.1\t12345\t1.2.3.4\t80\ttcp\t-"
    event = _parse_line(line)
    assert event is not None
    assert event.payload["service"] is None


def test_parse_line_bad_timestamp_fallback() -> None:
    line = "not-a-timestamp\tCxxx\t1.1.1.1\t1\t2.2.2.2\t80\ttcp\t-"
    event = _parse_line(line)
    assert event is not None  # Should not raise


# ── ZeekAdapter.read_file ──────────────────────────────────────────────────────


@pytest.fixture
def zeek_log(tmp_path: pytest.TempPathFactory) -> str:
    content = textwrap.dedent("""\
        #separator \\x09
        #set_separator ,
        #empty_field (empty)
        #unset_field -
        #path conn
        #fields ts uid id.orig_h id.orig_p id.resp_h id.resp_p proto service
        1700000010.000000\tCabc1\t192.168.1.5\t51234\t93.184.216.34\t443\ttcp\tssl
        1700000011.000000\tCabc2\t192.168.1.5\t51235\t8.8.8.8\t53\tudp\tdns
        1700000012.000000\tCabc3\t192.168.1.5\t51236\t10.0.0.1\t22\ttcp\tssh
    """)
    p = tmp_path / "conn.log"
    p.write_text(content)
    return str(p)


@pytest.mark.asyncio
async def test_read_file_parses_all_data_lines(zeek_log: str) -> None:
    adapter = ZeekAdapter(zeek_log)
    events = await adapter.read_file()
    assert len(events) == 3
    assert all(e.event_type == EventType.CONNECTION_OPENED for e in events)


@pytest.mark.asyncio
async def test_read_file_skips_comment_lines(zeek_log: str) -> None:
    adapter = ZeekAdapter(zeek_log)
    events = await adapter.read_file()
    # 3 data lines, 6 comment/header lines → only 3 events
    assert len(events) == 3


@pytest.mark.asyncio
async def test_read_file_missing_file_returns_empty(tmp_path: pytest.TempPathFactory) -> None:
    adapter = ZeekAdapter(tmp_path / "nonexistent.log")
    events = await adapter.read_file()
    assert events == []


@pytest.mark.asyncio
async def test_read_file_ports_parsed_correctly(zeek_log: str) -> None:
    adapter = ZeekAdapter(zeek_log)
    events = await adapter.read_file()
    ports = [e.payload["dst_port"] for e in events]
    assert 443 in ports
    assert 53 in ports
    assert 22 in ports


# ── ZeekAdapter.available ─────────────────────────────────────────────────────


def test_available_true_when_file_exists(zeek_log: str) -> None:
    assert ZeekAdapter(zeek_log).available is True


def test_available_false_when_file_missing(tmp_path: pytest.TempPathFactory) -> None:
    assert ZeekAdapter(tmp_path / "missing.log").available is False
