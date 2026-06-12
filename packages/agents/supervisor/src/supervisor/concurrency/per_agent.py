"""Per-agent concurrency control (supervisor v0.2 Task 5, Q2).

Replaces the single global dispatch semaphore with a **per-agent** semaphore — so a slow or
backed-up agent can't starve dispatch to the others. Per **Q2** the default cap is **4**
concurrent delegations per agent, with operator-configurable per-agent overrides. Per-tenant
semaphores are deferred to v0.3.

``run_under_limits`` runs a batch of ``(agent_id, thunk)`` items, each bounded by its agent's
semaphore, preserving input order — the seam the live dispatcher (Task 6) plugs into.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping, Sequence
from contextlib import asynccontextmanager

#: Per Q2 — the default per-agent concurrent-delegation cap.
DEFAULT_PER_AGENT_CAP = 4


class PerAgentSemaphores:
    """Lazily-created ``asyncio.Semaphore`` per agent id, with a default + per-agent overrides."""

    __slots__ = ("_default", "_overrides", "_sems")

    def __init__(
        self,
        *,
        default_cap: int = DEFAULT_PER_AGENT_CAP,
        overrides: Mapping[str, int] | None = None,
    ) -> None:
        if default_cap < 1:
            raise ValueError(f"default_cap must be >= 1 (got {default_cap})")
        for agent, cap in (overrides or {}).items():
            if cap < 1:
                raise ValueError(f"override cap for {agent!r} must be >= 1 (got {cap})")
        self._default = default_cap
        self._overrides = dict(overrides or {})
        self._sems: dict[str, asyncio.Semaphore] = {}

    def cap_for(self, agent_id: str) -> int:
        return self._overrides.get(agent_id, self._default)

    def _semaphore(self, agent_id: str) -> asyncio.Semaphore:
        sem = self._sems.get(agent_id)
        if sem is None:
            sem = asyncio.Semaphore(self.cap_for(agent_id))
            self._sems[agent_id] = sem
        return sem

    @asynccontextmanager
    async def acquire(self, agent_id: str) -> AsyncIterator[None]:
        async with self._semaphore(agent_id):
            yield


async def run_under_limits[T](
    items: Sequence[tuple[str, Callable[[], Awaitable[T]]]],
    *,
    semaphores: PerAgentSemaphores,
) -> list[T]:
    """Run each ``(agent_id, thunk)`` under that agent's semaphore concurrently, preserving
    input order in the returned results."""

    async def _one(agent_id: str, thunk: Callable[[], Awaitable[T]]) -> T:
        async with semaphores.acquire(agent_id):
            return await thunk()

    return list(await asyncio.gather(*(_one(a, t) for a, t in items)))
