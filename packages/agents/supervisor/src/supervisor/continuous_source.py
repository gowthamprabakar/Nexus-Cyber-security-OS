"""Continuous trigger source — the A.0-orchestrated production loop's heartbeat adapter.

Phase C Sub-Sprint 1. ``agent.run()`` is single-shot; each agent's ``continuous`` scheduler only
computes which tenants are due. The fleet-wide ``nexus_runtime.ContinuousDriver`` aggregates those
schedulers. This adapter plugs the driver into the supervisor's existing per-customer heartbeat as
a third trigger source (alongside the events bus + the scheduled queue): each tick emits one
``IncomingTask`` (``target_agent`` set, ``trigger_source=CONTINUOUS``) per agent whose scheduler
shows THIS customer due, marks those runs ran, and lets the normal routing/dispatch path carry
them. Default behaviour is unchanged — the heartbeat wires a no-op source unless one is supplied.

Q-ARCH / WI-O10 + WI-X14: this source emits ``target_agent`` dispatch triggers; it never
subscribes to ``claims.>`` (the producer-only fences are untouched).
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime

import ulid
from nexus_runtime.continuous import ContinuousDriver

from supervisor.schemas import IncomingTask, TriggerSource


def _utc_now() -> datetime:
    return datetime.now(UTC)


class ContinuousTriggerSource:
    """Heartbeat trigger source backed by the fleet ``ContinuousDriver`` (A.0 orchestration)."""

    def __init__(
        self,
        driver: ContinuousDriver,
        *,
        now_fn: Callable[[], datetime] = _utc_now,
        task_id_fn: Callable[[], str] = lambda: str(ulid.ULID()),
    ) -> None:
        self._driver = driver
        self._now_fn = now_fn
        self._task_id_fn = task_id_fn

    async def __call__(self, customer_id: str) -> list[IncomingTask]:
        """Emit a dispatch trigger per agent due for ``customer_id`` this tick; mark each ran."""
        now = self._now_fn()
        tasks: list[IncomingTask] = []
        for run in self._driver.due_runs(now):
            if run.tenant_id != customer_id:
                continue
            tasks.append(
                IncomingTask(
                    task_id=self._task_id_fn(),
                    customer_id=customer_id,
                    trigger_source=TriggerSource.CONTINUOUS,
                    target_agent=run.agent_id,
                    description=f"continuous scheduler due: {run.agent_id}",
                    received_at=now,
                )
            )
            self._driver.mark_ran(run.agent_id, run.tenant_id, at=now)
        return tasks
