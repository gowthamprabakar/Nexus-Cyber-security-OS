"""Tracee real-time kernel-event subscription (D.3 v0.2 Task 5).

Subscribes to a **push** Tracee event stream (the Tracee event pipe / gRPC in
production) and consumes it with backpressure + graceful shutdown. Per **Q2** Tracee is
in scope at v0.2, **alongside** Falco and the heartbeat path (`tracee_alerts_read`
stays for the offline/eval path).

The real-time consumer machinery (bounded-queue backpressure + graceful shutdown) is
**sensor-agnostic** — introduced in Task 2 as `FalcoRealtimeSubscriber` (Falco was simply
the first sensor). Tracee reuses it over a `TraceeEventStream`; no duplication.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any, Protocol

from runtime_threat.tools.falco_realtime import (
    EventHandler,
    FalcoRealtimeSubscriber,
    StreamStats,
)

__all__ = ["EventHandler", "StreamStats", "TraceeEventStream", "TraceeRealtimeSubscriber"]


class TraceeEventStream(Protocol):
    """The push source D.3 subscribes to for Tracee — the event pipe/gRPC client in
    prod, a fake in tests."""

    def subscribe(self) -> AsyncIterator[dict[str, Any]]: ...


class TraceeRealtimeSubscriber(FalcoRealtimeSubscriber):
    """Tracee kernel-event subscriber — reuses the Task-2 sensor-agnostic real-time
    consumer (push stream → bounded queue → handler, with backpressure + graceful
    shutdown) over a `TraceeEventStream`."""

    def __init__(
        self,
        stream: TraceeEventStream,
        handler: EventHandler,
        *,
        queue_maxsize: int = 1000,
        drop_on_full: bool = False,
    ) -> None:
        super().__init__(stream, handler, queue_maxsize=queue_maxsize, drop_on_full=drop_on_full)
