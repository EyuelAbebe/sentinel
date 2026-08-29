"""Integration tests — spawn real controlled processes/sockets and verify collectors.

NOTE: On macOS, psutil.net_connections() requires elevated privileges or specific
entitlements to read all connections. Tests skip automatically when access is denied.
This is a documented platform limitation (see docs/permissions.md).
"""
from __future__ import annotations

import socket

import psutil
import pytest

from sentinel.collectors.network_psutil import PsutilNetworkCollector
from sentinel.domain.enums import ExposureLevel


def _can_read_connections() -> bool:
    try:
        psutil.net_connections(kind="inet")
        return True
    except psutil.AccessDenied:
        return False


_SKIP_NO_ACCESS = pytest.mark.skipif(
    not _can_read_connections(),
    reason="psutil.net_connections() requires elevated privileges on this system",
)


def _bind_socket(address: str) -> tuple[socket.socket, int]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((address, 0))
    sock.listen(1)
    return sock, sock.getsockname()[1]


@_SKIP_NO_ACCESS
@pytest.mark.asyncio
async def test_loopback_listener_classified_loopback() -> None:
    sock, port = _bind_socket("127.0.0.1")
    try:
        collector = PsutilNetworkCollector()
        observations = await collector.snapshot()
        loopback_ports = {
            obs.local_endpoint.port
            for obs in observations
            if obs.listening and obs.exposure == ExposureLevel.LOOPBACK
        }
        assert port in loopback_ports, (
            f"Port {port} bound on 127.0.0.1 not classified as LOOPBACK. "
            f"Found loopback ports: {loopback_ports}"
        )
    finally:
        sock.close()


@_SKIP_NO_ACCESS
@pytest.mark.asyncio
async def test_all_interface_listener_classified_all_interfaces() -> None:
    sock, port = _bind_socket("0.0.0.0")
    try:
        collector = PsutilNetworkCollector()
        observations = await collector.snapshot()
        all_if_ports = {
            obs.local_endpoint.port
            for obs in observations
            if obs.listening and obs.exposure == ExposureLevel.ALL_INTERFACES
        }
        assert port in all_if_ports, (
            f"Port {port} bound on 0.0.0.0 not classified as ALL_INTERFACES. "
            f"Found all-interface ports: {all_if_ports}"
        )
    finally:
        sock.close()
