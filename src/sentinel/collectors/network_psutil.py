from __future__ import annotations

import contextlib
import ipaddress
from datetime import UTC, datetime
from typing import Any

import psutil

from sentinel.domain.enums import ExposureLevel, Protocol, SocketState
from sentinel.domain.models import NetworkEndpoint, SocketObservation
from sentinel.log import get_logger

logger = get_logger("collectors.network")

_STATE_MAP: dict[str, SocketState] = {
    "LISTEN": SocketState.LISTEN,
    "ESTABLISHED": SocketState.ESTABLISHED,
    "SYN_SENT": SocketState.SYN_SENT,
    "SYN_RECV": SocketState.SYN_RECV,
    "FIN_WAIT1": SocketState.FIN_WAIT1,
    "FIN_WAIT2": SocketState.FIN_WAIT2,
    "TIME_WAIT": SocketState.TIME_WAIT,
    "CLOSE": SocketState.CLOSE,
    "CLOSE_WAIT": SocketState.CLOSE_WAIT,
    "LAST_ACK": SocketState.LAST_ACK,
    "CLOSING": SocketState.CLOSING,
    "NONE": SocketState.NONE,
}


class PsutilNetworkCollector:
    async def snapshot(self) -> list[SocketObservation]:
        now = datetime.now(UTC)
        observations: list[SocketObservation] = []

        try:
            conns = psutil.net_connections(kind="inet")
        except psutil.AccessDenied:
            logger.warning("Global net_connections denied — falling back to per-process")
            conns = _collect_per_process()
        except Exception as exc:
            logger.warning("net_connections failed: %s", exc)
            conns = _collect_per_process()

        for conn in conns:
            try:
                obs = _connection_to_observation(conn, now)
                if obs is not None:
                    observations.append(obs)
            except Exception as exc:
                logger.debug("Skipping connection: %s", exc)

        return observations


def _collect_per_process() -> list[Any]:
    """Collect connections per-process — works for the current user without root."""
    conns: list[Any] = []
    for proc in psutil.process_iter():
        with contextlib.suppress(psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
            proc_conns = proc.net_connections(kind="inet")
            conns.extend(proc_conns)
    return conns


def _connection_to_observation(
    conn: Any,
    now: datetime,
) -> SocketObservation | None:
    laddr = conn.laddr
    if not laddr:
        return None

    proto = Protocol.TCP if conn.type == 1 else Protocol.UDP
    state_str = conn.status if conn.status else "NONE"
    state = _STATE_MAP.get(state_str.upper(), SocketState.UNKNOWN)
    listening = state == SocketState.LISTEN

    local_ep = NetworkEndpoint(
        address=laddr.ip,
        port=laddr.port,
        protocol=proto,
    )

    remote_ep: NetworkEndpoint | None = None
    if conn.raddr:
        remote_ep = NetworkEndpoint(
            address=conn.raddr.ip,
            port=conn.raddr.port,
            protocol=proto,
        )

    exposure = _classify_exposure(laddr.ip, listening)

    return SocketObservation(
        pid=conn.pid,
        local_endpoint=local_ep,
        remote_endpoint=remote_ep,
        socket_state=state,
        listening=listening,
        exposure=exposure,
        observed_at=now,
    )


def _classify_exposure(address: str, listening: bool) -> ExposureLevel:
    if not listening:
        return ExposureLevel.LOOPBACK

    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return ExposureLevel.ALL_INTERFACES

    if ip.is_loopback:
        return ExposureLevel.LOOPBACK
    if address in ("0.0.0.0", "::"):
        return ExposureLevel.ALL_INTERFACES
    return ExposureLevel.LOCAL_NETWORK
