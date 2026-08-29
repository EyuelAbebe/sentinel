from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC

from sentinel.domain.models import ProcessObservation, SocketObservation


@dataclass
class CorrelatedProcess:
    observation: ProcessObservation
    listeners: list[SocketObservation] = field(default_factory=list)
    connections: list[SocketObservation] = field(default_factory=list)

    @property
    def name(self) -> str:
        return self.observation.identity.name

    @property
    def pid(self) -> int:
        return self.observation.identity.pid

    @property
    def instance_id(self) -> str:
        return self.observation.identity.instance_id


class CorrelationService:
    def correlate(
        self,
        processes: list[ProcessObservation],
        sockets: list[SocketObservation],
    ) -> list[CorrelatedProcess]:
        by_pid: dict[int, CorrelatedProcess] = {}
        for proc_obs in processes:
            by_pid[proc_obs.identity.pid] = CorrelatedProcess(observation=proc_obs)

        orphan_listeners: list[SocketObservation] = []
        orphan_connections: list[SocketObservation] = []

        for sock in sockets:
            if sock.pid is not None and sock.pid in by_pid:
                cp = by_pid[sock.pid]
                if sock.listening:
                    cp.listeners.append(sock)
                else:
                    cp.connections.append(sock)
            elif sock.listening:
                orphan_listeners.append(sock)
            else:
                orphan_connections.append(sock)

        result = list(by_pid.values())

        if orphan_listeners or orphan_connections:
            from datetime import datetime

            from sentinel.domain.models import ProcessIdentity

            ghost = CorrelatedProcess(
                observation=ProcessObservation(
                    identity=ProcessIdentity(
                        pid=0,
                        name="(unknown)",
                        start_time=0.0,
                    ),
                    observed_at=datetime.now(UTC),
                ),
                listeners=orphan_listeners,
                connections=orphan_connections,
            )
            result.append(ghost)

        return result
