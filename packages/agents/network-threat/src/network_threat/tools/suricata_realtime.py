"""Suricata real-time eve.json subscription framework (D.4 v0.2 Task 2).

The v0.2 **real-time** mode: subscribe to a **push** Suricata ``eve.json`` event stream
(unix socket / named pipe in production) and consume it into a bounded queue with
backpressure + graceful shutdown, dispatching each event to a handler. Per **Q1**
real-time runs **alongside** the heartbeat path (`suricata_reader` stays for the
offline/eval path); it does **not** preempt the heartbeat (v0.3).

**Group A precedent (WI-N2).** This mirrors D.3's `FalcoRealtimeSubscriber` — D.4 is
real-time-event-stream **consumer #2** (D.3 was #1). The pattern is documented for the
ADR-007 third-consumer hoist (now LIVE for a future consumer #3); it is **not** hoisted
this cycle, so D.4 keeps its own copy. No charter touch.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass
from typing import Any, Protocol


class SuricataEventStream(Protocol):
    """The push source D.4 subscribes to — the eve.json socket/pipe in prod, fake in tests."""

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


class SuricataRealtimeSubscriber:
    """Consumes a push Suricata eve.json stream into a bounded queue with backpressure and
    graceful shutdown, dispatching each event to a handler.

    - **Backpressure:** a bounded `asyncio.Queue`. Default = block the producer when full
      (lossless); `drop_on_full=True` sheds the newest events + counts them.
    - **Graceful shutdown:** `request_stop()` stops the producer; the consumer drains what
      is already queued, then returns.
    """

    def __init__(
        self,
        stream: SuricataEventStream,
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
