"""DeepScanService — extends QuickScanService with hash integrity and YARA scanning."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING

from sentinel.application.correlation import CorrelatedProcess
from sentinel.application.scan_service import QuickScanService, ScanResult
from sentinel.collectors.base import NetworkCollector, ProcessCollector
from sentinel.domain.enums import Severity
from sentinel.domain.findings import Finding, FindingReason
from sentinel.log import get_logger

if TYPE_CHECKING:
    from sqlalchemy.engine import Engine

logger = get_logger("deep_scan")


@dataclass
class DeepScanResult:
    quick: ScanResult
    hash_findings: list[Finding] = field(default_factory=list)
    yara_findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    scan_time: datetime = field(default_factory=datetime.utcnow)

    @property
    def all_findings(self) -> list[Finding]:
        return self.quick.findings + self.hash_findings + self.yara_findings

    @property
    def finding_count(self) -> int:
        return len(self.all_findings)


class DeepScanService:
    """Runs a quick scan then enriches with hash integrity and YARA checks."""

    def __init__(
        self,
        process_collector: ProcessCollector,
        network_collector: NetworkCollector,
        engine: Engine | None = None,
    ) -> None:
        self._quick = QuickScanService(
            process_collector=process_collector,
            network_collector=network_collector,
        )
        self._engine = engine
        from sentinel.adapters.yara_scanner import YaraScanner

        self._yara = YaraScanner()

    async def run(self) -> DeepScanResult:
        quick = await self._quick.run()
        result = DeepScanResult(quick=quick)

        if self._engine is not None:
            result.hash_findings = self._check_hashes(quick.correlated, result.errors)

        result.yara_findings = self._yara_scan(quick.correlated, result.errors)

        return result

    def _check_hashes(
        self,
        correlated: list[CorrelatedProcess],
        errors: list[str],
    ) -> list[Finding]:
        from sqlalchemy.orm import Session

        from sentinel.application.hash_cache_service import HashCacheService
        from sentinel.storage.database import init_db

        assert self._engine is not None
        init_db(self._engine)
        findings: list[Finding] = []

        with Session(self._engine) as session:
            svc = HashCacheService(session)
            for cp in correlated:
                path = cp.observation.identity.executable_path
                if not path:
                    continue
                try:
                    if svc.has_changed(path):
                        findings.append(
                            Finding(
                                severity=Severity.HIGH,
                                title=cp.name,
                                subject=path,
                                reasons=[
                                    FindingReason(
                                        signal="executable_hash_changed",
                                        description=f"Executable hash changed since last scan: {path}",
                                    )
                                ],
                                evidence_refs=[cp.instance_id],
                            )
                        )
                    else:
                        svc.check(path)
                except Exception as exc:
                    logger.debug("hash check failed for %s: %s", path, exc)
                    errors.append(f"Hash check: {path}: {exc}")
            session.commit()

        return findings

    def _yara_scan(
        self,
        correlated: list[CorrelatedProcess],
        errors: list[str],
    ) -> list[Finding]:
        if not self._yara.available:
            return []

        findings: list[Finding] = []
        for cp in correlated:
            path = cp.observation.identity.executable_path
            if not path:
                continue
            try:
                matches = self._yara.scan_file(path)
                if matches:
                    findings.append(
                        Finding(
                            severity=Severity.HIGH,
                            title=cp.name,
                            subject=path,
                            reasons=[
                                FindingReason(
                                    signal="yara_match",
                                    description=f"YARA rule matched: {', '.join(matches)}",
                                )
                            ],
                            evidence_refs=[cp.instance_id],
                        )
                    )
            except Exception as exc:
                logger.debug("YARA scan failed for %s: %s", path, exc)
                errors.append(f"YARA: {path}: {exc}")

        return findings
