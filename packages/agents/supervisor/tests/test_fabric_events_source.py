"""Phase C SS1 — FabricEventsSource (events.> -> heartbeat triggers) tests."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from supervisor.fabric_events_source import FabricEventsSource
from supervisor.schemas import TriggerSource
from supervisor.triggers.event_bus import (
    EventBusListener,
    ForbiddenEventSubscriptionError,
)

_NOW = datetime(2026, 6, 13, tzinfo=UTC)
_CUST = "cust-A"


def _source() -> FabricEventsSource:
    listener = EventBusListener(subscriptions=["events.tenant.cust-A.findings_delta"])
    return FabricEventsSource(listener, now_fn=lambda: _NOW)


def _event(customer_id: str = _CUST, *, task_id: str = "evt-1") -> dict:
    return {
        "task_id": task_id,
        "customer_id": customer_id,
        "target_agent": "investigation",
        "task_type": "findings_delta",
        "description": "new finding delta",
        "priority": 3,
    }


@pytest.mark.asyncio
async def test_buffered_event_becomes_incoming_task() -> None:
    src = _source()
    src.push_event(_event())
    tasks = await src(_CUST)
    assert len(tasks) == 1
    t = tasks[0]
    assert t.task_id == "evt-1"
    assert t.customer_id == _CUST
    assert t.trigger_source is TriggerSource.EVENTS_BUS
    assert t.target_agent == "investigation"
    assert t.received_at == _NOW


@pytest.mark.asyncio
async def test_drains_buffer() -> None:
    src = _source()
    src.push_event(_event(task_id="a"))
    src.push_event(_event(task_id="b"))
    first = await src(_CUST)
    assert len(first) == 2
    # buffer drained -> next tick empty.
    assert await src(_CUST) == []


@pytest.mark.asyncio
async def test_other_customer_retained_not_dropped() -> None:
    src = _source()
    src.push_event(_event(customer_id="cust-B", task_id="b1"))
    src.push_event(_event(customer_id=_CUST, task_id="a1"))
    a_tasks = await src(_CUST)
    assert [t.task_id for t in a_tasks] == ["a1"]
    # cust-B event retained for its own tick.
    b_tasks = await src("cust-B")
    assert [t.task_id for t in b_tasks] == ["b1"]


@pytest.mark.asyncio
async def test_empty_buffer_empty_result() -> None:
    assert await _source()(_CUST) == []


def test_fence_rejects_claims_subscription() -> None:
    # The underlying listener refuses claims.> at construction (WI-O10).
    with pytest.raises(ForbiddenEventSubscriptionError):
        FabricEventsSource(EventBusListener(subscriptions=["claims.curiosity.>"]))


def test_subscriptions_exposed() -> None:
    assert _source().subscriptions == ("events.tenant.cust-A.findings_delta",)
