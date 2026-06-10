"""D.3 v0.2 Task 2 — Falco real-time subscription framework tests (no live gRPC)."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from typing import Any

import pytest
from runtime_threat.tools.falco_realtime import FalcoRealtimeSubscriber


class _Stream:
    """A fake push stream that yields a fixed list of events."""

    def __init__(self, events: list[dict[str, Any]]) -> None:
        self._events = events

    async def subscribe(self) -> AsyncIterator[dict[str, Any]]:
        for e in self._events:
            yield e


def _ev(rule: str) -> dict[str, Any]:
    return {"rule": rule, "priority": "Warning", "output_fields": {}}


@pytest.mark.asyncio
async def test_consumes_all_events() -> None:
    got: list[dict[str, Any]] = []

    async def handler(e: dict[str, Any]) -> None:
        got.append(e)

    stats = await FalcoRealtimeSubscriber(_Stream([_ev("a"), _ev("b")]), handler).run()
    assert stats.received == 2 and stats.handled == 2 and stats.errors == 0
    assert [g["rule"] for g in got] == ["a", "b"]


@pytest.mark.asyncio
async def test_empty_stream() -> None:
    async def handler(_: dict[str, Any]) -> None: ...

    stats = await FalcoRealtimeSubscriber(_Stream([]), handler).run()
    assert stats.received == 0 and stats.handled == 0


@pytest.mark.asyncio
async def test_handler_error_counted_not_fatal() -> None:
    async def bad(e: dict[str, Any]) -> None:
        if e["rule"] == "boom":
            raise RuntimeError("x")

    stats = await FalcoRealtimeSubscriber(_Stream([_ev("ok"), _ev("boom"), _ev("ok")]), bad).run()
    assert stats.handled == 2 and stats.errors == 1


@pytest.mark.asyncio
async def test_stream_error_counted_not_fatal() -> None:
    class _FlakyStream:
        async def subscribe(self) -> AsyncIterator[dict[str, Any]]:
            yield _ev("first")
            raise RuntimeError("stream dropped")

    async def handler(_: dict[str, Any]) -> None: ...

    stats = await FalcoRealtimeSubscriber(_FlakyStream(), handler).run()
    assert stats.handled == 1 and stats.errors == 1


@pytest.mark.asyncio
async def test_backpressure_drops_when_full() -> None:
    gate = asyncio.Event()

    async def blocked(_: dict[str, Any]) -> None:
        await gate.wait()

    sub = FalcoRealtimeSubscriber(
        _Stream([_ev(str(i)) for i in range(10)]), blocked, queue_maxsize=2, drop_on_full=True
    )
    task = asyncio.create_task(sub.run())
    await asyncio.sleep(0.05)
    gate.set()
    stats = await asyncio.wait_for(task, timeout=2.0)
    assert stats.dropped > 0
    assert stats.handled + stats.dropped == 10  # nothing lost-and-uncounted


@pytest.mark.asyncio
async def test_lossless_block_default() -> None:
    got: list[str] = []

    async def handler(e: dict[str, Any]) -> None:
        got.append(e["rule"])

    sub = FalcoRealtimeSubscriber(
        _Stream([_ev(str(i)) for i in range(20)]), handler, queue_maxsize=2
    )
    stats = await sub.run()
    assert stats.handled == 20 and stats.dropped == 0
    assert sorted(got, key=int) == [str(i) for i in range(20)]


@pytest.mark.asyncio
async def test_graceful_shutdown() -> None:
    class _Infinite:
        async def subscribe(self) -> AsyncIterator[dict[str, Any]]:
            i = 0
            while True:
                yield _ev(str(i))
                i += 1
                await asyncio.sleep(0.001)

    async def handler(_: dict[str, Any]) -> None: ...

    sub = FalcoRealtimeSubscriber(_Infinite(), handler)
    task = asyncio.create_task(sub.run())
    await asyncio.sleep(0.05)
    sub.request_stop()
    stats = await asyncio.wait_for(task, timeout=2.0)
    assert stats.handled > 0  # consumed a bounded number, then stopped cleanly


def test_realtime_and_heartbeat_coexist() -> None:
    # Q1: real-time mode is added ALONGSIDE the offline heartbeat path — both importable.
    from runtime_threat.tools.falco import falco_alerts_read
    from runtime_threat.tools.falco_realtime import FalcoRealtimeSubscriber as _S

    assert callable(falco_alerts_read) and _S is FalcoRealtimeSubscriber
