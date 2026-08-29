from __future__ import annotations

import asyncio
import contextlib
from typing import TYPE_CHECKING

from sqlalchemy.orm import Session

from sentinel.application.correlation import CorrelationService
from sentinel.application.event_bus import EventBus
from sentinel.application.finding_engine import FindingEngine
from sentinel.application.snapshot_differ import SnapshotDiffer
from sentinel.application.state_registry import CurrentStateRegistry
from sentinel.collectors.base import NetworkCollector, ProcessCollector
from sentinel.log import get_logger

if TYPE_CHECKING:
    from sqlalchemy.engine import Engine

logger = get_logger("live_monitor")


class LiveMonitorService:
    """Background polling loop — diffs state, persists events/findings, emits on EventBus."""

    def __init__(
        self,
        process_collector: ProcessCollector,
        network_collector: NetworkCollector,
        event_bus: EventBus,
        *,
        engine: Engine | None = None,
        poll_interval: float = 10.0,
    ) -> None:
        self._procs = process_collector
        self._nets = network_collector
        self._bus = event_bus
        self._engine = engine
        self._interval = poll_interval
        self._registry = CurrentStateRegistry()
        self._differ = SnapshotDiffer()
        self._correlator = CorrelationService()
        self._finder = FindingEngine()
        self._running = False
        self._task: asyncio.Task[None] | None = None

    @property
    def is_running(self) -> bool:
        return self._running

    async def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._poll_loop())
        logger.info("LiveMonitorService started (interval=%.1fs)", self._interval)

    async def stop(self) -> None:
        self._running = False
        if self._task is not None:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
            self._task = None
        logger.info("LiveMonitorService stopped")

    async def _poll_loop(self) -> None:
        while self._running:
            try:
                await self._tick()
            except Exception as exc:
                logger.error("tick error: %s", exc)
            await asyncio.sleep(self._interval)

    async def _tick(self) -> None:
        try:
            proc_obs = await self._procs.snapshot()
        except Exception as exc:
            logger.warning("process collection failed: %s", exc)
            proc_obs = []

        try:
            sock_obs = await self._nets.snapshot()
        except Exception as exc:
            logger.warning("network collection failed: %s", exc)
            sock_obs = []

        events = self._differ.diff_processes(self._registry.get_processes(), proc_obs)
        events += self._differ.diff_sockets(self._registry.get_sockets(), sock_obs)

        self._registry.update_processes(proc_obs)
        self._registry.update_sockets(sock_obs)

        correlated = self._correlator.correlate(proc_obs, sock_obs)
        findings = self._finder.evaluate(correlated)

        if self._engine is not None and (events or findings):
            with Session(self._engine) as session:
                if events:
                    from sentinel.storage.event_repository import EventRepository

                    EventRepository(session).write_many(events)
                if findings:
                    from sentinel.storage.finding_repository import FindingRepository

                    FindingRepository(session).write_many(findings)
                session.commit()

        if events:
            await self._bus.publish_many(events)
