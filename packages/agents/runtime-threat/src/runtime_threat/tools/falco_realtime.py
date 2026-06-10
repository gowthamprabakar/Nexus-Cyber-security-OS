"""Falco real-time event subscription framework (D.3 v0.2 Task 2).

The v0.2 **real-time** mode: subscribe to a **push** Falco event stream (the gRPC
outputs service in production) and consume it into a bounded queue with backpressure +
graceful shutdown, dispatching each event to a handler. This is **push-based** — distinct
from D.8's pull-based continuous ingestion (the sensor pushes; we don't poll). Per **Q1**
real-time runs **alongside** the heartbeat path (`falco_alerts_read` stays for the
offline/eval path); it does **not** preempt the heartbeat (that is v0.3, WI-R11).

WI-R2: this real-time-event-stream pattern is documented here for a future ADR-007
third-consumer hoist evaluation — D.3 is consumer #1 (D.4 Network Threat, Cycle 7, is
the likely #2). Not hoisted this cycle; no charter touch.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass
from typing import Any, Protocol


class FalcoEventStream(Protocol):
    """The push source D.3 subscribes to — the gRPC client in prod, a fake in tests."""

    def subscribe(self) -> AsyncIterator[dict[str, Any]]: ...


#: A handler consumes exactly one received event.
EventHandler = Callable[[dict[str, Any]], Awaitable[None]]


@dataclass
class StreamStats:
    """Per-run counters — secret-free, suitable for structured logging."""

    received: int = 0
    handled: int = 0
    dropped: int = 0
    errors: int = 0


class FalcoRealtimeSubscriber:
    """Consumes a push Falco event stream into a bounded queue with backpressure and
    graceful shutdown, dispatching each event to a handler.

    - **Backpressure:** a bounded `asyncio.Queue`. Default = block the producer when full
      (lossless); `drop_on_full=True` sheds the newest events + counts them (for
      real-time load spikes).
    - **Graceful shutdown:** `request_stop()` stops the producer; the consumer drains what
      is already queued, then returns.
    """

    def __init__(
        self,
        stream: FalcoEventStream,
        handler: EventHandler,
        *,
        queue_maxsize: int = 1000,
        drop_on_full: bool = False,
    ) -> None:
        self._stream = stream
        self._handler = handler
        self._queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=queue_maxsize)
        self._drop_on_full = drop_on_full
        self._stats = StreamStats()
        self._stop = asyncio.Event()

    @property
    def stats(self) -> StreamStats:
        return self._stats

    def request_stop(self) -> None:
        """Signal the producer + consumer to wind down (graceful)."""
        self._stop.set()

    async def _produce(self) -> None:
        try:
            async for event in self._stream.subscribe():
                if self._stop.is_set():
                    break
                self._stats.received += 1
                if self._drop_on_full and self._queue.full():
                    self._stats.dropped += 1
                    continue
                await self._queue.put(event)
        except asyncio.CancelledError:
            raise
        except Exception:  # a stream hiccup must not kill the run (resilience)
            self._stats.errors += 1

    async def _consume(self) -> None:
        while not (self._stop.is_set() and self._queue.empty()):
            try:
                event = await asyncio.wait_for(self._queue.get(), timeout=0.05)
            except TimeoutError:
                continue
            try:
                await self._handler(event)
                self._stats.handled += 1
            except Exception:  # a bad event must not kill the consumer
                self._stats.errors += 1
            finally:
                self._queue.task_done()

    async def run(self) -> StreamStats:
        """Consume the stream to exhaustion (or until `request_stop()`), drain, return."""
        consumer = asyncio.create_task(self._consume())
        await self._produce()
        await self._queue.join()
        self._stop.set()
        await consumer
        return self._stats
