"""Unit tests for ClassificationService and the known_tracker_connection signal."""

from __future__ import annotations

from sentinel.application.classification_service import ClassificationService
from sentinel.application.correlation import CorrelatedProcess
from sentinel.application.finding_engine import FindingEngine
from sentinel.domain.enums import (
    ExposureLevel,
    IdentityStatus,
    PrivacyCategory,
    Protocol,
    SocketState,
)
from sentinel.domain.models import (
    NetworkEndpoint,
    ProcessIdentity,
    ProcessObservation,
    SocketObservation,
)

# ── helpers ───────────────────────────────────────────────────────────────────


def _proc(pid: int = 1, name: str = "test") -> CorrelatedProcess:
    identity = ProcessIdentity(
        pid=pid,
        name=name,
        executable_path=f"/usr/bin/{name}",
        command_line=[f"/usr/bin/{name}"],
        user="user",
        parent_pid=1,
        start_time=float(pid * 1_000),
    )
    return CorrelatedProcess(observation=ProcessObservation(identity=identity))


def _connection_to(
    address: str = "1.2.3.4",
    port: int = 443,
    hostname: str | None = None,
    organization: str | None = None,
    category: PrivacyCategory = PrivacyCategory.UNKNOWN,
) -> SocketObservation:
    return SocketObservation(
        pid=1,
        local_endpoint=NetworkEndpoint(address="192.168.1.1", port=54321, protocol=Protocol.TCP),
        remote_endpoint=NetworkEndpoint(
            address=address,
            port=port,
            protocol=Protocol.TCP,
            hostname=hostname,
            organization=organization,
            category=category,
        ),
        socket_state=SocketState.ESTABLISHED,
        listening=False,
        exposure=ExposureLevel.LOOPBACK,
    )


# ── ClassificationService ─────────────────────────────────────────────────────


class TestClassificationService:
    def setup_method(self) -> None:
        self.svc = ClassificationService()

    def test_exact_domain_match(self) -> None:
        ev = self.svc.classify("google-analytics.com")
        assert ev.identity_status == IdentityStatus.KNOWN
        assert ev.organization == "Google"
        assert ev.category == PrivacyCategory.ANALYTICS
        assert ev.confidence == 1.0

    def test_subdomain_match(self) -> None:
        ev = self.svc.classify("www.google-analytics.com")
        assert ev.identity_status == IdentityStatus.KNOWN
        assert ev.category == PrivacyCategory.ANALYTICS

    def test_deep_subdomain_match(self) -> None:
        ev = self.svc.classify("data.collector.doubleclick.net")
        assert ev.identity_status == IdentityStatus.KNOWN
        assert ev.category == PrivacyCategory.ADVERTISING

    def test_unknown_domain_returns_unknown(self) -> None:
        ev = self.svc.classify("example.com")
        assert ev.identity_status == IdentityStatus.UNKNOWN
        assert ev.category == PrivacyCategory.UNKNOWN
        assert ev.confidence == 0.0

    def test_source_and_version_set(self) -> None:
        ev = self.svc.classify("mixpanel.com")
        assert ev.source == "local"
        assert ev.source_version != ""

    def test_is_privacy_risk_tracking(self) -> None:
        ev = self.svc.classify("appsflyer.com")
        assert ev.category == PrivacyCategory.TRACKING
        assert self.svc.is_privacy_risk(ev)

    def test_is_privacy_risk_advertising(self) -> None:
        ev = self.svc.classify("doubleclick.net")
        assert self.svc.is_privacy_risk(ev)

    def test_is_not_privacy_risk_cdn(self) -> None:
        ev = self.svc.classify("cloudflare.com")
        assert ev.category == PrivacyCategory.CDN
        assert not self.svc.is_privacy_risk(ev)

    def test_is_not_privacy_risk_unknown(self) -> None:
        ev = self.svc.classify("example.com")
        assert not self.svc.is_privacy_risk(ev)

    def test_case_insensitive(self) -> None:
        ev = self.svc.classify("MIXPANEL.COM")
        assert ev.identity_status == IdentityStatus.KNOWN


# ── FindingEngine: known_tracker_connection signal ────────────────────────────


class TestTrackerConnectionSignal:
    def setup_method(self) -> None:
        self.engine = FindingEngine()

    def test_no_finding_for_benign_connection(self) -> None:
        cp = _proc()
        cp.connections.append(_connection_to(category=PrivacyCategory.UNKNOWN))
        assert self.engine.evaluate([cp]) == []

    def test_finding_for_tracking_connection(self) -> None:
        cp = _proc()
        cp.connections.append(
            _connection_to(
                organization="AppsFlyer",
                category=PrivacyCategory.TRACKING,
            )
        )
        findings = self.engine.evaluate([cp])
        assert len(findings) == 1
        assert any(r.signal == "known_tracker_connection" for r in findings[0].reasons)

    def test_finding_for_advertising_connection(self) -> None:
        cp = _proc()
        cp.connections.append(
            _connection_to(
                organization="DoubleClick",
                category=PrivacyCategory.ADVERTISING,
            )
        )
        findings = self.engine.evaluate([cp])
        assert len(findings) == 1

    def test_no_finding_for_cdn_connection(self) -> None:
        cp = _proc()
        cp.connections.append(_connection_to(category=PrivacyCategory.CDN))
        assert self.engine.evaluate([cp]) == []

    def test_tracker_connection_severity_is_low(self) -> None:
        cp = _proc()
        cp.connections.append(_connection_to(category=PrivacyCategory.TRACKING))
        findings = self.engine.evaluate([cp])
        from sentinel.domain.enums import Severity

        assert findings[0].severity == Severity.LOW
