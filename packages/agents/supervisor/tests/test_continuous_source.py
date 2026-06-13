"""Phase C SS1 — ContinuousTriggerSource (A.0 heartbeat adapter) tests."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from nexus_runtime.continuous import ContinuousDriver
from supervisor.continuous_source import ContinuousTriggerSource
from supervisor.schemas import TriggerSource

_NOW = datetime(2026, 6, 13, tzinfo=UTC)
_CUST = "cust-A"


class _FakeScheduler:
    def __init__(self, due: list[str]) -> None:
        self._due = list(due)
        self.ran: list[tuple[str, datetime]] = []

    def due(self, now: datetime) -> list[str]:
        return list(self._due)

    def mark_ran(self, tenant_id: str, *, at: datetime) -> None:
        self.ran.append((tenant_id, at))
        self._due = [t for t in self._due if t != tenant_id]


def _source(driver: ContinuousDriver) -> ContinuousTriggerSource:
    counter = {"n": 0}

    def _tid() -> str:
        counter["n"] += 1
        return f"task-{counter['n']}"

    return ContinuousTriggerSource(driver, now_fn=lambda: _NOW, task_id_fn=_tid)


@pytest.mark.asyncio
async def test_emits_target_agent_task_for_due_customer() -> None:
    driver = ContinuousDriver()
    sched = _FakeScheduler([_CUST])
    driver.register("compliance", sched)
    tasks = await _source(driver)(_CUST)
    assert len(tasks) == 1
    t = tasks[0]
    assert t.target_agent == "compliance"
    assert t.customer_id == _CUST
    assert t.trigger_source is TriggerSource.CONTINUOUS
    # marked ran -> not due again.
    assert sched.ran == [(_CUST, _NOW)]


@pytest.mark.asyncio
async def test_filters_other_customers() -> None:
    driver = ContinuousDriver()
    driver.register("compliance", _FakeScheduler(["cust-B"]))
    tasks = await _source(driver)(_CUST)
    assert tasks == []


@pytest.mark.asyncio
async def test_multiple_agents_due_same_customer() -> None:
    driver = ContinuousDriver()
    driver.register("compliance", _FakeScheduler([_CUST]))
    driver.register("curiosity", _FakeScheduler([_CUST]))
    tasks = await _source(driver)(_CUST)
    assert {t.target_agent for t in tasks} == {"compliance", "curiosity"}


@pytest.mark.asyncio
async def test_nothing_due_emits_empty() -> None:
    driver = ContinuousDriver()
    driver.register("compliance", _FakeScheduler([]))
    assert await _source(driver)(_CUST) == []
