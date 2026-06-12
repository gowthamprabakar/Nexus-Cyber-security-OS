"""supervisor v0.2 Task 5 — per-agent semaphore tests (Q2)."""

from __future__ import annotations

import asyncio

import pytest
from supervisor.concurrency.per_agent import (
    DEFAULT_PER_AGENT_CAP,
    PerAgentSemaphores,
    run_under_limits,
)


def test_default_cap_is_four() -> None:
    assert DEFAULT_PER_AGENT_CAP == 4
    sems = PerAgentSemaphores()
    assert sems.cap_for("compliance") == 4


def test_override_cap() -> None:
    sems = PerAgentSemaphores(default_cap=4, overrides={"audit": 2})
    assert sems.cap_for("audit") == 2 and sems.cap_for("compliance") == 4


def test_nonpositive_default_rejected() -> None:
    with pytest.raises(ValueError, match="default_cap must be"):
        PerAgentSemaphores(default_cap=0)


def test_nonpositive_override_rejected() -> None:
    with pytest.raises(ValueError, match="override cap"):
        PerAgentSemaphores(overrides={"audit": 0})


@pytest.mark.asyncio
async def test_same_agent_bounded_by_cap() -> None:
    sems = PerAgentSemaphores(overrides={"audit": 2})
    live = 0
    peak = 0

    async def _probe() -> int:
        nonlocal live, peak
        live += 1
        peak = max(peak, live)
        await asyncio.sleep(0.01)
        live -= 1
        return 1

    items = [("audit", _probe) for _ in range(6)]
    results = await run_under_limits(items, semaphores=sems)
    assert len(results) == 6
    assert peak <= 2  # never more than the cap concurrent for one agent


@pytest.mark.asyncio
async def test_different_agents_independent() -> None:
    sems = PerAgentSemaphores(overrides={"a": 1, "b": 1})
    live = 0
    peak = 0

    async def _probe() -> int:
        nonlocal live, peak
        live += 1
        peak = max(peak, live)
        await asyncio.sleep(0.01)
        live -= 1
        return 1

    # one delegation each to two different agents -> they run concurrently.
    await run_under_limits([("a", _probe), ("b", _probe)], semaphores=sems)
    assert peak == 2


@pytest.mark.asyncio
async def test_order_preserved() -> None:
    sems = PerAgentSemaphores()

    def _mk(n: int):
        async def _thunk() -> int:
            return n

        return _thunk

    items = [("audit", _mk(i)) for i in range(5)]
    assert await run_under_limits(items, semaphores=sems) == [0, 1, 2, 3, 4]


@pytest.mark.asyncio
async def test_empty() -> None:
    assert await run_under_limits([], semaphores=PerAgentSemaphores()) == []
