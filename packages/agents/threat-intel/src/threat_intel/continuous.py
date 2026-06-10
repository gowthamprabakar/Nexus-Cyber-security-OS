"""Continuous-ingestion framework (D.8 v0.2 Task 2).

The v0.2 **continuous mode**: instead of a heartbeat file-snapshot read, the agent
subscribes to feed sources and ingests their items continuously into a **bounded
queue** with **backpressure** + **graceful shutdown**, dispatching each item to a
per-feed handler. Heartbeat mode (`agent.run`) remains for back-compat.

This framework is D.8-specific for now. Per **WI-T2** the continuous-ingestion pattern
is documented here for a future ADR-007 third-consumer hoist evaluation — it does
**not** hoist this cycle (D.8 is the only consumer; the likely 2nd is D.4 Network
Threat). No charter touch.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

#: A feed source is an async generator yielding raw items (already normalized to dicts).
FeedSource = Callable[[], AsyncIterator[dict[str, Any]]]
#: A handler consumes exactly one ingested item.
ItemHandler = Callable[[dict[str, Any]], Awaitable[None]]


@dataclass(frozen=True, slots=True)
class Subscription:
    """A named feed subscription: a source (async generator) + an item handler."""

    name: str
    source: FeedSource
    handler: ItemHandler


@dataclass
class IngestStats:
    """Per-run counters — secret-free, suitable for structured logging (WI-T8)."""

    ingested: int = 0
    dropped: int = 0
    errors: int = 0
    per_feed: dict[str, int] = field(default_factory=dict)


class SubscriptionManager:
    """Registers feed subscriptions (name → source + handler). No duplicates."""

    def __init__(self) -> None:
        self._subs: dict[str, Subscription] = {}

    def register(self, name: str, source: FeedSource, handler: ItemHandler) -> None:
        if name in self._subs:
            raise ValueError(f"duplicate subscription: {name!r}")
        self._subs[name] = Subscription(name=name, source=source, handler=handler)

    def get(self, name: str) -> Subscription:
        return self._subs[name]

    def all(self) -> tuple[Subscription, ...]:
        return tuple(self._subs.values())

    @property
    def names(self) -> tuple[str, ...]:
        return tuple(self._subs)


class ContinuousIngestor:
    """Runs the registered subscriptions concurrently into a bounded queue with
    backpressure, dispatching each item to its handler.

    - **Backpressure:** a bounded `asyncio.Queue`. Default = block the producer when
      full (lossless); `drop_on_full=True` drops + counts instead (lossy, for
      best-effort feeds).
    - **Graceful shutdown:** `stop()` signals producers to stop, the consumer drains
      what is already queued, then returns.
    """

    def __init__(
        self,
        manager: SubscriptionManager,
        *,
        queue_maxsize: int = 1000,
        drop_on_full: bool = False,
    ) -> None:
        self._manager = manager
        self._queue: asyncio.Queue[tuple[str, dict[str, Any]]] = asyncio.Queue(
            maxsize=queue_maxsize
        )
        self._drop_on_full = drop_on_full
        self._stats = IngestStats()
        self._stop = asyncio.Event()

    @property
    def stats(self) -> IngestStats:
        return self._stats

    def request_stop(self) -> None:
        """Signal producers + consumer to wind down (graceful)."""
        self._stop.set()

    async def _produce(self, sub: Subscription) -> None:
        try:
            async for item in sub.source():
                if self._stop.is_set():
                    break
                if self._drop_on_full and self._queue.full():
                    self._stats.dropped += 1
                    continue
                await self._queue.put((sub.name, item))
        except asyncio.CancelledError:
            raise
        except Exception:  # a feed source failing must not kill the run (WI-T9)
            self._stats.errors += 1

    async def _consume(self) -> None:
        # Drain until stopped AND empty, so in-flight items are not lost on shutdown.
        while not (self._stop.is_set() and self._queue.empty()):
            try:
                name, item = await asyncio.wait_for(self._queue.get(), timeout=0.05)
            except TimeoutError:
                continue
            try:
                await self._manager.get(name).handler(item)
                self._stats.ingested += 1
                self._stats.per_feed[name] = self._stats.per_feed.get(name, 0) + 1
            except Exception:  # a bad item must not kill the consumer
                self._stats.errors += 1
            finally:
                self._queue.task_done()

    async def run_until_drained(self) -> IngestStats:
        """Run every producer to exhaustion, then drain the queue and return stats.

        For **finite** sources (one-shot polls, tests). Long-running continuous
        sources use `run()` + `request_stop()`.
        """
        consumer = asyncio.create_task(self._consume())
        await asyncio.gather(*(self._produce(s) for s in self._manager.all()))
        await self._queue.join()
        self._stop.set()
        await consumer
        return self._stats

    async def run(self) -> IngestStats:
        """Run producers + consumer until `request_stop()` is called (continuous mode)."""
        consumer = asyncio.create_task(self._consume())
        producers = asyncio.gather(*(self._produce(s) for s in self._manager.all()))
        await producers
        await self._queue.join()
        self._stop.set()
        await consumer
        return self._stats
