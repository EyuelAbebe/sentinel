"""Zeek conn.log adapter — tail a Zeek connection log and emit domain Events.

Zeek TSV conn.log format (subset of fields used here):
  ts  uid  id.orig_h  id.orig_p  id.resp_h  id.resp_p  proto  service  duration  ...

Usage:
    adapter = ZeekAdapter("/opt/zeek/logs/current/conn.log")
    async for event in adapter.tail():
        await bus.publish(event)
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path

from sentinel.domain.enums import EventType, Protocol
from sentinel.domain.events import Event
from sentinel.log import get_logger

logger = get_logger("adapters.zeek")

_SOURCE = "zeek"

# Column indices in a standard Zeek conn.log TSV (after stripping the comment header)
_COL_TS = 0
_COL_UID = 1
_COL_ORIG_H = 2
_COL_ORIG_P = 3
_COL_RESP_H = 4
_COL_RESP_P = 5
_COL_PROTO = 6
_COL_SERVICE = 7

_POLL_INTERVAL = 0.5  # seconds between tail polls


def _parse_proto(value: str) -> str:
    mapping = {"tcp": Protocol.TCP, "udp": Protocol.UDP}
    return mapping.get(value.lower(), Protocol.UNKNOWN)


def _parse_line(line: str) -> Event | None:
    """Parse one Zeek TSV conn.log line into a CONNECTION_OPENED Event."""
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    parts = line.split("\t")
    if len(parts) < 8:
        return None
    try:
        ts_float = float(parts[_COL_TS])
        ts = datetime.fromtimestamp(ts_float, tz=UTC)
    except (ValueError, OSError):
        ts = datetime.now(UTC)

    orig_h = parts[_COL_ORIG_H] if len(parts) > _COL_ORIG_H else "-"
    orig_p = parts[_COL_ORIG_P] if len(parts) > _COL_ORIG_P else "-"
    resp_h = parts[_COL_RESP_H] if len(parts) > _COL_RESP_H else "-"
    resp_p = parts[_COL_RESP_P] if len(parts) > _COL_RESP_P else "-"
    proto_str = parts[_COL_PROTO] if len(parts) > _COL_PROTO else "unknown"
    service = parts[_COL_SERVICE] if len(parts) > _COL_SERVICE else "-"

    try:
        resp_port = int(resp_p)
    except ValueError:
        resp_port = 0

    return Event(
        event_type=EventType.CONNECTION_OPENED,
        timestamp=ts,
        source=_SOURCE,
        payload={
            "src_ip": orig_h,
            "src_port": orig_p,
            "dst_ip": resp_h,
            "dst_port": resp_port,
            "proto": _parse_proto(proto_str),
            "service": service if service != "-" else None,
        },
    )


class ZeekAdapter:
    """Tail a Zeek conn.log and emit CONNECTION_OPENED events.

    Handles log rotation by re-opening the file when it shrinks.
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
                    # Log rotated
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
                logger.warning("zeek tail error: %s", exc)
            await asyncio.sleep(self._poll_interval)

    async def read_file(self, path: str | Path | None = None) -> list[Event]:
        """Parse an entire log file (non-streaming; useful for testing)."""
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
            logger.warning("zeek read error: %s", exc)
        return events
