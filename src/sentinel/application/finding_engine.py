from __future__ import annotations

from sentinel.application.correlation import CorrelatedProcess
from sentinel.domain.enums import ExposureLevel, PrivacyCategory, Severity
from sentinel.domain.findings import Finding, FindingReason


class FindingEngine:
    """Evaluates signals against correlated process data to produce findings."""

    def evaluate(self, correlated: list[CorrelatedProcess]) -> list[Finding]:
        findings: list[Finding] = []
        for cp in correlated:
            reasons = self._collect_reasons(cp)
            if reasons:
                severity = self._derive_severity(reasons)
                finding = Finding(
                    severity=severity,
                    title=cp.name,
                    subject=cp.name,
                    reasons=reasons,
                    evidence_refs=[cp.instance_id],
                )
                findings.append(finding)
        return findings

    def _collect_reasons(self, cp: CorrelatedProcess) -> list[FindingReason]:
        reasons: list[FindingReason] = []
        identity = cp.observation.identity

        if identity.is_in_suspicious_location():
            reasons.append(
                FindingReason(
                    signal="suspicious_location",
                    description=f"Running from {identity.executable_path}",
                )
            )

        if not identity.executable_exists and identity.executable_path:
            reasons.append(
                FindingReason(
                    signal="executable_missing",
                    description="Executable no longer exists on disk",
                )
            )

        for listener in cp.listeners:
            if listener.exposure == ExposureLevel.ALL_INTERFACES:
                reasons.append(
                    FindingReason(
                        signal="all_interface_listener",
                        description=(
                            f"Listening on :{listener.local_endpoint.port} "
                            f"({listener.local_endpoint.protocol.upper()}) — "
                            "accessible from all network interfaces"
                        ),
                    )
                )
            elif listener.exposure == ExposureLevel.LOCAL_NETWORK:
                reasons.append(
                    FindingReason(
                        signal="local_network_listener",
                        description=(
                            f"Listening on {listener.local_endpoint.address}:"
                            f"{listener.local_endpoint.port} — "
                            "accessible from local network"
                        ),
                    )
                )

        for conn in cp.connections:
            ep = conn.remote_endpoint
            if ep and ep.category in (PrivacyCategory.TRACKING, PrivacyCategory.ADVERTISING):
                label = ep.organization or ep.hostname or ep.address
                reasons.append(
                    FindingReason(
                        signal="known_tracker_connection",
                        description=f"Connected to {label} ({ep.category})",
                    )
                )

        return reasons

    def _derive_severity(self, reasons: list[FindingReason]) -> Severity:
        signals = {r.signal for r in reasons}
        if "executable_missing" in signals:
            return Severity.HIGH
        if "all_interface_listener" in signals and "suspicious_location" in signals:
            return Severity.HIGH
        if "all_interface_listener" in signals:
            return Severity.MEDIUM
        if "suspicious_location" in signals:
            return Severity.MEDIUM
        if "known_tracker_connection" in signals:
            return Severity.LOW
        return Severity.LOW
