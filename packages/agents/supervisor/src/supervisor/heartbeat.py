"""Heartbeat outer loop — 60-second tick (default), single-threaded per customer.

Per Q5: ``fcntl.flock`` on ``<workspace_root>/.supervisor/locks/<customer_id>.lock``
protects against concurrent Supervisor processes for the same
customer. A second process trying to acquire the lock blocks until
the first releases it.

**Injectable interval.** ``tick_interval_seconds`` defaults to
``60.0``; tests pass ``0.01`` to exercise the loop quickly.

**Bounded by ``max_ticks``.** When set, the loop exits after the
Nth tick. Production passes ``None`` (run until interrupt); tests
pass small integers.

**Stage 1 INGEST trigger sources** (per Q5 / plan):

- ``events.>`` bus subscriber — DI-passed via ``events_source``
  callable. Production wires this to the real
  ``shared.fabric.JetStreamClient`` subscriber; v0.1 default is
  a no-op (no live broker assumed).
- Scheduled-task queue — file-backed; drained per-tick via
  ``supervisor.scheduled_queue.drain``.
- Operator-CLI invocations are not handled by the heartbeat loop
  itself; the CLI's ``heartbeat-once`` subcommand invokes
  ``agent.run`` directly with operator-supplied triggers.

**Q-ARCH-1 enforced.** The heartbeat does not subscribe to
``claims.>``. Smoke test source-grep guard catches any regression.
"""

from __future__ import annotations

import asyncio
import fcntl
import logging
from collections.abc import Sequence
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Protocol

import ulid

from supervisor.agent import run as agent_run
from supervisor.dispatch import DelegationInvoker
from supervisor.scheduled_queue import drain as drain_scheduled_queue
from supervisor.schemas import IncomingTask, RoutingRule, SupervisorReport

_LOG = logging.getLogger(__name__)

DEFAULT_TICK_INTERVAL_SECONDS = 60.0
_LOCK_SUBDIR = Path(".supervisor") / "locks"


class EventsSource(Protocol):
    """v0.1 DI shape for the events.> bus subscriber.

    The real production implementation wires this to
    ``shared.fabric.JetStreamClient.subscribe(events_subject(tenant_id, ...))``.
    The default is a no-op (empty triggers list each tick).
    """

    async def __call__(self, customer_id: str) -> list[IncomingTask]: ...


def make_no_op_events_source() -> EventsSource:
    """v0.1 default events source — returns no triggers each tick.

    Production wires a real subscriber when the operator-side
    NATS deployment is ready. v0.1 default lets the scheduled-
    queue + CLI paths drive the heartbeat without a live broker.
    """

    async def _source(customer_id: str) -> list[IncomingTask]:
        del customer_id
        return []

    return _source


class Heartbeat:
    """Outer loop driver."""

    def __init__(
        self,
        *,
        customer_id: str,
        workspace_root: Path,
        routing_rules: Sequence[RoutingRule],
        events_source: EventsSource | None = None,
        invoker: DelegationInvoker | None = None,
        tick_interval_seconds: float = DEFAULT_TICK_INTERVAL_SECONDS,
        max_ticks: int | None = None,
    ) -> None:
        if tick_interval_seconds <= 0:
            raise ValueError(f"tick_interval_seconds must be > 0 (got {tick_interval_seconds})")
        if max_ticks is not None and max_ticks < 1:
            raise ValueError(f"max_ticks must be >= 1 (got {max_ticks})")

        self._customer_id = customer_id
        self._workspace_root = Path(workspace_root)
        self._routing_rules = tuple(routing_rules)
        self._events_source = events_source or make_no_op_events_source()
        self._invoker = invoker
        self._tick_interval_seconds = tick_interval_seconds
        self._max_ticks = max_ticks

    async def run_forever(self) -> list[SupervisorReport]:
        """Run until ``max_ticks`` (if set) or until cancelled.

        Each tick acquires the per-customer ``fcntl.flock`` for
        the duration of the ``agent.run`` call. Sleeps for
        ``tick_interval_seconds`` between ticks.
        """
        reports: list[SupervisorReport] = []
        tick_index = 0
        while True:
            with self._per_customer_lock():
                report = await self._tick()
                reports.append(report)
            tick_index += 1
            if self._max_ticks is not None and tick_index >= self._max_ticks:
                return reports
            await asyncio.sleep(self._tick_interval_seconds)

    async def tick_once(self) -> SupervisorReport:
        """Run a single tick (used by the CLI ``heartbeat-once``
        subcommand + by tests that don't want the outer loop)."""
        with self._per_customer_lock():
            return await self._tick()

    async def _tick(self) -> SupervisorReport:
        events_triggers = await self._events_source(self._customer_id)
        queued_triggers = drain_scheduled_queue(
            self._workspace_root,
            customer_id=self._customer_id,
        )
        triggers = list(events_triggers) + list(queued_triggers)
        return await agent_run(
            customer_id=self._customer_id,
            workspace_root=self._workspace_root,
            routing_rules=self._routing_rules,
            triggers=triggers,
            invoker=self._invoker,
            tick_id=str(ulid.ULID()),
        )

    @contextmanager
    def _per_customer_lock(self) -> Any:
        lock_dir = self._workspace_root / _LOCK_SUBDIR
        lock_dir.mkdir(parents=True, exist_ok=True)
        lock_path = lock_dir / f"{self._customer_id}.lock"
        fh = lock_path.open("a")
        try:
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
            fh.close()


__all__ = [
    "DEFAULT_TICK_INTERVAL_SECONDS",
    "EventsSource",
    "Heartbeat",
    "make_no_op_events_source",
]
