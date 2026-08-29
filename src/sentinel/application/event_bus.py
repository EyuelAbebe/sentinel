from __future__ import annotations

import asyncio
from collections import defaultdict
from collections.abc import Awaitable, Callable

from sentinel.domain.enums import EventType
from sentinel.domain.events import Event

Handler = Callable[[Event], Awaitable[None]]


class EventBus:
    """In-memory async pub/sub bus for domain events."""

    def __init__(self) -> None:
        self._handlers: dict[EventType, list[Handler]] = defaultdict(list)
        self._catch_all: list[Handler] = []

    def subscribe(self, event_type: EventType, handler: Handler) -> None:
        self._handlers[event_type].append(handler)

    def subscribe_all(self, handler: Handler) -> None:
        self._catch_all.append(handler)

    async def publish(self, event: Event) -> None:
        tasks: list[asyncio.Task[None]] = []
        for handler in self._handlers.get(event.event_type, []):
            tasks.append(asyncio.create_task(handler(event)))
        for handler in self._catch_all:
            tasks.append(asyncio.create_task(handler(event)))
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def publish_many(self, events: list[Event]) -> None:
        for event in events:
            await self.publish(event)
