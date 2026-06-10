"""Zeek conn.log + dns.log real-time subscription (D.4 v0.2 Task 5).

Subscribes to a **push** Zeek log stream (the Broker API / a log-streaming socket in
production) and consumes it with backpressure + graceful shutdown. Per **Q2** Zeek is
sensor #2 at v0.2, **alongside** Suricata and the heartbeat path (the offline readers
stay for the offline/eval path).

The real-time consumer machinery is **sensor-agnostic** — introduced in Task 2 as
`SuricataRealtimeSubscriber`. Zeek reuses it over a `ZeekEventStream`; no duplication
(mirrors D.3's Tracee-subclasses-Falco precedent).
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any, Protocol

from network_threat.tools.suricata_realtime import (
    EventHandler,
    StreamStats,
    SuricataRealtimeSubscriber,
)

__all__ = ["EventHandler", "StreamStats", "ZeekEventStream", "ZeekRealtimeSubscriber"]


class ZeekEventStream(Protocol):
    """The push source D.4 subscribes to for Zeek — the Broker/log socket in prod, a fake
    in tests. Yields parsed Zeek log records (conn / dns) as dicts."""

    def subscribe(self) -> AsyncIterator[dict[str, Any]]: ...


class ZeekRealtimeSubscriber(SuricataRealtimeSubscriber):
    """Zeek log subscriber — reuses the Task-2 sensor-agnostic real-time consumer (push
    stream → bounded queue → handler, with backpressure + graceful shutdown) over a
    `ZeekEventStream`."""

    def __init__(
        self,
        stream: ZeekEventStream,
        handler: EventHandler,
        *,
        queue_maxsize: int = 1000,
        drop_on_full: bool = False,
    ) -> None:
        super().__init__(stream, handler, queue_maxsize=queue_maxsize, drop_on_full=drop_on_full)
