"""Phase C SS1 — ContinuousDriver (A.0-orchestrated production loop) tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from nexus_runtime.continuous import ContinuousDriver, DueRun, TickResult

_T0 = datetime(2026, 6, 13, tzinfo=UTC)


class _FakeScheduler:
    """Minimal SchedulerProtocol impl: due() returns preset tenants until marked ran."""

    def __init__(self, tenants: list[str]) -> None:
        self._pending = list(tenants)
        self.ran: list[tuple[str, datetime]] = []

    def due(self, now: datetime) -> list[str]:
        return list(self._pending)

    def mark_ran(self, tenant_id: str, *, at: datetime) -> None:
        self.ran.append((tenant_id, at))
        self._pending = [t for t in self._pending if t != tenant_id]


def test_register_and_agents() -> None:
    d = ContinuousDriver()
    d.register("curiosity", _FakeScheduler(["t1"]))
    d.register("compliance", _FakeScheduler(["t2"]))
    assert d.agents() == ("curiosity", "compliance")


def test_empty_agent_id_rejected() -> None:
    d = ContinuousDriver()
    with pytest.raises(ValueError, match="agent_id"):
        d.register("", _FakeScheduler([]))


def test_due_runs_flattens_in_order() -> None:
    d = ContinuousDriver()
    d.register("a", _FakeScheduler(["t1", "t2"]))
    d.register("b", _FakeScheduler(["t3"]))
    assert d.due_runs(_T0) == [
        DueRun("a", "t1"),
        DueRun("a", "t2"),
        DueRun("b", "t3"),
    ]


@pytest.mark.asyncio
async def test_tick_dispatches_and_marks_ran() -> None:
    d = ContinuousDriver()
    sched = _FakeScheduler(["t1", "t2"])
    d.register("a", sched)
    calls: list[tuple[str, str]] = []

    async def dispatch(agent_id: str, tenant_id: str) -> None:
        calls.append((agent_id, tenant_id))

    result = await d.tick(_T0, dispatch=dispatch)
    assert calls == [("a", "t1"), ("a", "t2")]
    assert result.dispatched == (DueRun("a", "t1"), DueRun("a", "t2"))
    assert result.failed == ()
    # marked ran -> next tick has nothing due.
    assert d.due_runs(_T0 + timedelta(seconds=1)) == []


@pytest.mark.asyncio
async def test_tick_isolates_failures_and_retries() -> None:
    d = ContinuousDriver()
    sched = _FakeScheduler(["good", "bad"])
    d.register("a", sched)

    async def dispatch(agent_id: str, tenant_id: str) -> None:
        if tenant_id == "bad":
            raise RuntimeError("dispatch boom")

    result = await d.tick(_T0, dispatch=dispatch)
    # good dispatched + marked; bad failed + NOT marked (still due next tick).
    assert result.dispatched == (DueRun("a", "good"),)
    assert len(result.failed) == 1 and result.failed[0][0] == DueRun("a", "bad")
    assert "boom" in result.failed[0][1]
    assert d.due_runs(_T0) == [DueRun("a", "bad")]


@pytest.mark.asyncio
async def test_tick_empty_when_nothing_due() -> None:
    d = ContinuousDriver()
    d.register("a", _FakeScheduler([]))

    async def dispatch(agent_id: str, tenant_id: str) -> None:  # pragma: no cover - never called
        raise AssertionError("should not dispatch")

    result = await d.tick(_T0, dispatch=dispatch)
    assert result == TickResult()
