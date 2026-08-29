from __future__ import annotations

from typing import Protocol, runtime_checkable

from sentinel.domain.models import ProcessObservation, SocketObservation


@runtime_checkable
class ProcessCollector(Protocol):
    async def snapshot(self) -> list[ProcessObservation]: ...


@runtime_checkable
class NetworkCollector(Protocol):
    async def snapshot(self) -> list[SocketObservation]: ...
