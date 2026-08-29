"""Suricata eve.json adapter — tail an eve.json file and emit domain Events.

Suricata's unified2 JSON output (`eve.json`) contains one JSON object per line.
This adapter handles `event_type: flow` and `event_type: alert` records.

Usage:
    adapter = SuricataAdapter("/var/log/suricata/eve.json")
    async for event in adapter.tail():
        await bus.publish(event)
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sentinel.domain.enums import EventType, Protocol
from sentinel.domain.events import Event
from sentinel.log import get_logger

logger = get_logger("adapters.suricata")

_SOURCE = "suricata"
_POLL_INTERVAL = 0.5


def _parse_proto(value: str) -> str:
    mapping = {"tcp": Protocol.TCP, "udp": Protocol.UDP}
    return mapping.get(value.lower(), Protocol.UNKNOWN)


def _ts_to_datetime(ts_str: str) -> datetime:
    """Parse Suricata timestamp string to datetime."""
    try:
        # Suricata format: "2024-01-15T10:30:00.123456+0000"
        # Python 3.11+ handles this directly; strip trailing timezone offset for older
        ts_str = ts_str.replace("+0000", "+00:00").replace("Z", "+00:00")
        return datetime.fromisoformat(ts_str)
    except (ValueError, AttributeError):
        return datetime.now(UTC)


def _parse_flow_record(record: dict[str, Any]) -> Event | None:
    """Parse a Suricata flow record into a CONNECTION_OPENED Event."""
    flow = record.get("flow", {})
    src_ip = record.get("src_ip", "-")
    src_port = record.get("src_port", 0)
    dest_ip = record.get("dest_ip", "-")
    dest_port = record.get("dest_port", 0)
    proto_str = record.get("proto", "unknown")
    ts = _ts_to_datetime(record.get("timestamp", ""))
    app_proto = record.get("app_proto") or flow.get("app_proto")

    return Event(
        event_type=EventType.CONNECTION_OPENED,
        timestamp=ts,
        source=_SOURCE,
        payload={
            "src_ip": src_ip,
            "src_port": src_port,
            "dst_ip": dest_ip,
            "dst_port": dest_port,
            "proto": _parse_proto(proto_str),
            "service": app_proto,
            "bytes_toserver": flow.get("bytes_toserver"),
            "bytes_toclient": flow.get("bytes_toclient"),
        },
    )


def _parse_alert_record(record: dict[str, Any]) -> Event | None:
    """Parse a Suricata alert record into a FINDING_CREATED Event."""
    alert = record.get("alert", {})
    src_ip = record.get("src_ip", "-")
    dest_ip = record.get("dest_ip", "-")
    dest_port = record.get("dest_port", 0)
    ts = _ts_to_datetime(record.get("timestamp", ""))
    signature = alert.get("signature", "unknown")
    severity = alert.get("severity", 3)
    category = alert.get("category", "")

    return Event(
        event_type=EventType.FINDING_CREATED,
        timestamp=ts,
        source=_SOURCE,
        payload={
            "src_ip": src_ip,
            "dst_ip": dest_ip,
            "dst_port": dest_port,
            "signature": signature,
            "severity": severity,
            "category": category,
            "gid": alert.get("gid"),
            "signature_id": alert.get("signature_id"),
        },
    )


def _parse_line(line: str) -> Event | None:
    """Parse one JSON line from eve.json into an Event."""
    line = line.strip()
    if not line:
        return None
    try:
        record = json.loads(line)
    except json.JSONDecodeError:
        return None

    event_type = record.get("event_type", "")
    if event_type == "flow":
        return _parse_flow_record(record)
    if event_type == "alert":
        return _parse_alert_record(record)
    return None


class SuricataAdapter:
    """Tail a Suricata eve.json and emit CONNECTION_OPENED / FINDING_CREATED events.

    Handles log rotation by re-opening when the file shrinks.
    """

    def __init__(self, log_path: str | Path, poll_interval: float = _POLL_INTERVAL) -> None:
        self._path = Path(log_path)
        self._poll_interval = poll_interval

    @property
    def available(self) -> bool:
        return self._path.exists()

    async def tail(self) -> AsyncIterator[Event]:
        """Yield Events as new lines arrive. Runs until cancelled."""
        offset = 0
        while True:
            try:
                size = self._path.stat().st_size
                if size < offset:
                    offset = 0
                if size > offset:
                    with self._path.open("r", errors="replace") as fh:
                        fh.seek(offset)
                        for line in fh:
                            event = _parse_line(line)
                            if event is not None:
                                yield event
                        offset = fh.tell()
            except FileNotFoundError:
                pass
            except Exception as exc:  # pragma: no cover
                logger.warning("suricata tail error: %s", exc)
            await asyncio.sleep(self._poll_interval)

    async def read_file(self, path: str | Path | None = None) -> list[Event]:
        """Parse an entire eve.json file (non-streaming; useful for testing)."""
        target = Path(path) if path else self._path
        events: list[Event] = []
        try:
            with target.open("r", errors="replace") as fh:
                for line in fh:
                    event = _parse_line(line)
                    if event is not None:
                        events.append(event)
        except FileNotFoundError:
            pass
        except Exception as exc:
            logger.warning("suricata read error: %s", exc)
        return events
