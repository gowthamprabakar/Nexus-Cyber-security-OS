"""The A.0-orchestrated continuous production loop (Phase C Sub-Sprint 1).

``agent.run()`` is single-shot; an agent's ``continuous`` scheduler only decides WHEN each tenant
is due. ``ContinuousDriver`` is the one shared loop that turns due-sets into runs: the supervisor
registers each agent's scheduler, and each ``tick(now)`` computes the due ``(agent, tenant)`` set
and dispatches every entry through an injected ``dispatch`` callable (the supervisor's
signed-contract dispatch path). Pure orchestration — deterministic given a caller-supplied ``now``,
no wall-clock reads, no agent/charter imports.

Failure isolation: a dispatch that raises is recorded in ``TickResult.failed`` and that tenant is
**not** marked-ran, so it is retried on the next tick; other due runs in the same tick still fire.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol


class SchedulerProtocol(Protocol):
    """Structural type satisfied by every agent's continuous scheduler (CuriosityScheduler,
    RemediationScheduler, ...): ``due(now)`` returns the due tenant ids; ``mark_ran`` records a run."""

    def due(self, now: datetime) -> list[str]: ...

    def mark_ran(self, tenant_id: str, *, at: datetime) -> None: ...


#: A dispatch callable: ``(agent_id, tenant_id) -> awaitable`` — the supervisor's dispatch path.
DispatchFn = Callable[[str, str], Awaitable[None]]


@dataclass(frozen=True, slots=True)
class DueRun:
    agent_id: str
    tenant_id: str


@dataclass(frozen=True, slots=True)
class TickResult:
    dispatched: tuple[DueRun, ...] = ()
    failed: tuple[tuple[DueRun, str], ...] = ()


class ContinuousDriver:
    """Aggregates per-agent schedulers; computes + dispatches due runs on each tick."""

    def __init__(self) -> None:
        self._schedulers: dict[str, SchedulerProtocol] = {}

    def register(self, agent_id: str, scheduler: SchedulerProtocol) -> None:
        """Register an agent's scheduler under its agent id."""
        if not agent_id:
            raise ValueError("agent_id must be non-empty")
        self._schedulers[agent_id] = scheduler

    def agents(self) -> tuple[str, ...]:
        return tuple(self._schedulers)

    def due_runs(self, now: datetime) -> list[DueRun]:
        """The flat, deterministic list of due (agent, tenant) runs at ``now`` — agents in
        registration order, tenants in each scheduler's ``due`` order."""
        runs: list[DueRun] = []
        for agent_id, scheduler in self._schedulers.items():
            for tenant_id in scheduler.due(now):
                runs.append(DueRun(agent_id=agent_id, tenant_id=tenant_id))
        return runs

    async def tick(self, now: datetime, *, dispatch: DispatchFn) -> TickResult:
        """Dispatch every due run via ``dispatch``; mark each ran only on success.

        A dispatch that raises is recorded in ``failed`` and NOT marked-ran (retried next tick);
        remaining due runs still fire (failure isolation).
        """
        dispatched: list[DueRun] = []
        failed: list[tuple[DueRun, str]] = []
        for run in self.due_runs(now):
            try:
                await dispatch(run.agent_id, run.tenant_id)
            except Exception as exc:  # isolate per-run failure; continue the tick
                failed.append((run, str(exc)))
                continue
            self._schedulers[run.agent_id].mark_ran(run.tenant_id, at=now)
            dispatched.append(run)
        return TickResult(dispatched=tuple(dispatched), failed=tuple(failed))
