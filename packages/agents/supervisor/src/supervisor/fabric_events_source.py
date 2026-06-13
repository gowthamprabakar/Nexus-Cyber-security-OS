"""Fabric events source — bridges F.7 ``events.>`` into the heartbeat (Phase C SS1).

The supervisor heartbeat pulls triggers once per tick; the F.7 ``JetStreamClient`` delivers
``events.>`` messages via a **push** callback. This adapter bridges the two: production registers
``push_event`` as the subscribe callback (the client feeds each message's routing keys in), and
each heartbeat tick drains the buffer for the current customer, converts via the fence-validated
``EventBusListener``, and returns ``IncomingTask`` envelopes. It matches the heartbeat's
``EventsSource`` shape, so wiring it is just passing it as ``events_source=`` (default stays no-op).

Fence (WI-O10 / ADR-012): the underlying ``EventBusListener`` rejects any ``claims.>`` subscription
at construction, and the ``JetStreamClient`` subscriber-ACL rejects it again at subscribe time —
the supervisor only ever consumes ``events.>``. Routing keys only, never the OCSF body (WI-4).
"""

from __future__ import annotations

from collections import deque
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from typing import Any

from supervisor.schemas import IncomingTask
from supervisor.triggers.event_bus import EventBusListener


def _utc_now() -> datetime:
    return datetime.now(UTC)


class FabricEventsSource:
    """Push-to-buffer / pull-per-tick adapter from F.7 ``events.>`` to heartbeat triggers."""

    def __init__(
        self,
        listener: EventBusListener,
        *,
        now_fn: Callable[[], datetime] = _utc_now,
    ) -> None:
        self._listener = listener
        self._now_fn = now_fn
        self._buffer: deque[Mapping[str, Any]] = deque()

    @property
    def subscriptions(self) -> tuple[str, ...]:
        """The fence-validated ``events.>`` subjects this source consumes."""
        return self._listener.subscriptions

    def push_event(self, event: Mapping[str, Any]) -> None:
        """Buffer one received event's routing keys — wired as the JetStream push callback."""
        self._buffer.append(dict(event))

    async def __call__(self, customer_id: str) -> list[IncomingTask]:
        """Drain buffered events for ``customer_id`` into IncomingTasks (other tenants retained)."""
        now = self._now_fn()
        tasks: list[IncomingTask] = []
        retained: deque[Mapping[str, Any]] = deque()
        while self._buffer:
            event = self._buffer.popleft()
            if str(event.get("customer_id")) != customer_id:
                retained.append(event)
                continue
            tasks.append(self._listener.ingest(event, now=now))
        self._buffer = retained
        return tasks
