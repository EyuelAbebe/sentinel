from __future__ import annotations

from datetime import UTC, datetime

from sentinel.domain.enums import EventType
from sentinel.domain.events import Event
from sentinel.domain.models import ProcessObservation, SocketObservation

SOURCE = "snapshot_differ"


class SnapshotDiffer:
    """Computes meaningful events by diffing consecutive snapshots."""

    def diff_processes(
        self,
        previous: list[ProcessObservation],
        current: list[ProcessObservation],
    ) -> list[Event]:
        prev_map = {obs.identity.instance_id: obs for obs in previous}
        curr_map = {obs.identity.instance_id: obs for obs in current}

        events: list[Event] = []
        now = datetime.now(UTC)

        for iid, obs in curr_map.items():
            if iid not in prev_map:
                events.append(
                    Event(
                        event_type=EventType.PROCESS_STARTED,
                        timestamp=now,
                        source=SOURCE,
                        process_instance_id=iid,
                        payload={
                            "pid": obs.identity.pid,
                            "name": obs.identity.name,
                            "executable_path": obs.identity.executable_path,
                        },
                    )
                )

        for iid, obs in prev_map.items():
            if iid not in curr_map:
                events.append(
                    Event(
                        event_type=EventType.PROCESS_STOPPED,
                        timestamp=now,
                        source=SOURCE,
                        process_instance_id=iid,
                        payload={
                            "pid": obs.identity.pid,
                            "name": obs.identity.name,
                        },
                    )
                )

        return events

    def diff_sockets(
        self,
        previous: list[SocketObservation],
        current: list[SocketObservation],
    ) -> list[Event]:
        prev_map = {obs.socket_key: obs for obs in previous}
        curr_map = {obs.socket_key: obs for obs in current}

        events: list[Event] = []
        now = datetime.now(UTC)

        for key, obs in curr_map.items():
            if key not in prev_map:
                event_type = EventType.PORT_OPENED if obs.listening else EventType.CONNECTION_OPENED
                events.append(
                    Event(
                        event_type=event_type,
                        timestamp=now,
                        source=SOURCE,
                        process_instance_id=obs.process_instance_id,
                        entity_id=key,
                        payload={
                            "local_address": obs.local_endpoint.address,
                            "local_port": obs.local_endpoint.port,
                            "protocol": obs.local_endpoint.protocol,
                            "exposure": obs.exposure,
                            "pid": obs.pid,
                        },
                    )
                )

        for key, obs in prev_map.items():
            if key not in curr_map:
                event_type = EventType.PORT_CLOSED if obs.listening else EventType.CONNECTION_CLOSED
                events.append(
                    Event(
                        event_type=event_type,
                        timestamp=now,
                        source=SOURCE,
                        process_instance_id=obs.process_instance_id,
                        entity_id=key,
                        payload={
                            "local_address": obs.local_endpoint.address,
                            "local_port": obs.local_endpoint.port,
                            "protocol": obs.local_endpoint.protocol,
                        },
                    )
                )

        return events
