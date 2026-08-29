from __future__ import annotations

from sentinel.domain.models import ProcessObservation, SocketObservation


class CurrentStateRegistry:
    """In-memory store of the most recent observed state."""

    def __init__(self) -> None:
        self._processes: dict[str, ProcessObservation] = {}
        self._sockets: dict[str, SocketObservation] = {}

    # --- processes ---

    def get_processes(self) -> list[ProcessObservation]:
        return list(self._processes.values())

    def update_processes(self, observations: list[ProcessObservation]) -> None:
        self._processes = {obs.identity.instance_id: obs for obs in observations}

    def get_process(self, instance_id: str) -> ProcessObservation | None:
        return self._processes.get(instance_id)

    # --- sockets ---

    def get_sockets(self) -> list[SocketObservation]:
        return list(self._sockets.values())

    def update_sockets(self, observations: list[SocketObservation]) -> None:
        self._sockets = {obs.socket_key: obs for obs in observations}

    def get_socket(self, key: str) -> SocketObservation | None:
        return self._sockets.get(key)

    def clear(self) -> None:
        self._processes.clear()
        self._sockets.clear()
