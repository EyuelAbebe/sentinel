from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from sentinel.application.correlation import CorrelatedProcess, CorrelationService
from sentinel.application.finding_engine import FindingEngine
from sentinel.collectors.base import NetworkCollector, ProcessCollector
from sentinel.domain.findings import Finding
from sentinel.log import get_logger

logger = get_logger("scan_service")


@dataclass
class ScanResult:
    correlated: list[CorrelatedProcess] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    scan_time: datetime = field(default_factory=datetime.utcnow)
    errors: list[str] = field(default_factory=list)

    @property
    def process_count(self) -> int:
        return sum(1 for cp in self.correlated if cp.pid != 0)

    @property
    def listener_count(self) -> int:
        return sum(len(cp.listeners) for cp in self.correlated)

    @property
    def connection_count(self) -> int:
        return sum(len(cp.connections) for cp in self.correlated)

    @property
    def attention_count(self) -> int:
        return len(self.findings)


class QuickScanService:
    def __init__(
        self,
        process_collector: ProcessCollector,
        network_collector: NetworkCollector,
    ) -> None:
        self._procs = process_collector
        self._nets = network_collector
        self._correlator = CorrelationService()
        self._finder = FindingEngine()

    async def run(self) -> ScanResult:
        errors: list[str] = []

        try:
            proc_obs = await self._procs.snapshot()
        except Exception as exc:
            logger.error("Process collection failed: %s", exc)
            proc_obs = []
            errors.append(f"Process collection: {exc}")

        try:
            sock_obs = await self._nets.snapshot()
        except Exception as exc:
            logger.error("Network collection failed: %s", exc)
            sock_obs = []
            errors.append(f"Network collection: {exc}")

        correlated = self._correlator.correlate(proc_obs, sock_obs)
        findings = self._finder.evaluate(correlated)

        return ScanResult(
            correlated=correlated,
            findings=findings,
            errors=errors,
        )
