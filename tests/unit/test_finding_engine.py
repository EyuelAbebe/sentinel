from __future__ import annotations

from datetime import datetime, timezone

from sentinel.application.correlation import CorrelatedProcess
from sentinel.application.finding_engine import FindingEngine
from sentinel.domain.enums import ExposureLevel, Protocol, Severity, SocketState
from sentinel.domain.models import (
    NetworkEndpoint,
    ProcessIdentity,
    ProcessObservation,
    SocketObservation,
)

engine = FindingEngine()


def _cp(name: str, exe: str | None = None) -> CorrelatedProcess:
    return CorrelatedProcess(
        observation=ProcessObservation(
            identity=ProcessIdentity(
                pid=1,
                name=name,
                start_time=1000.0,
                executable_path=exe,
            ),
            observed_at=datetime.now(timezone.utc),
        )
    )


def _listener(exposure: ExposureLevel, port: int = 8080) -> SocketObservation:
    return SocketObservation(
        local_endpoint=NetworkEndpoint(address="0.0.0.0", port=port, protocol=Protocol.TCP),
        socket_state=SocketState.LISTEN,
        listening=True,
        exposure=exposure,
    )


def test_no_finding_for_benign_process() -> None:
    cp = _cp("chrome", "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")
    findings = engine.evaluate([cp])
    assert findings == []


def test_finding_for_all_interface_listener() -> None:
    cp = _cp("myserver")
    cp.listeners.append(_listener(ExposureLevel.ALL_INTERFACES))
    findings = engine.evaluate([cp])
    assert len(findings) == 1
    signals = {r.signal for r in findings[0].reasons}
    assert "all_interface_listener" in signals


def test_finding_for_suspicious_location() -> None:
    cp = _cp("badtool", "/Users/me/Downloads/badtool")
    findings = engine.evaluate([cp])
    assert len(findings) == 1
    signals = {r.signal for r in findings[0].reasons}
    assert "suspicious_location" in signals


def test_severity_escalates_with_combined_signals() -> None:
    cp = _cp("evil", "/Users/me/Downloads/evil")
    cp.listeners.append(_listener(ExposureLevel.ALL_INTERFACES))
    findings = engine.evaluate([cp])
    assert findings[0].severity == Severity.HIGH


def test_loopback_listener_no_finding() -> None:
    cp = _cp("devserver")
    cp.listeners.append(_listener(ExposureLevel.LOOPBACK))
    findings = engine.evaluate([cp])
    assert findings == []
