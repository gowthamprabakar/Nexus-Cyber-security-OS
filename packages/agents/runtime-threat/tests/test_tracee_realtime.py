"""D.3 v0.2 Task 5 — Tracee real-time subscription tests (no live pipe)."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from typing import Any

import pytest
from runtime_threat.tools.tracee_realtime import TraceeRealtimeSubscriber


class _Stream:
    def __init__(self, events: list[dict[str, Any]]) -> None:
        self._events = events

    async def subscribe(self) -> AsyncIterator[dict[str, Any]]:
        for e in self._events:
            yield e


def _ev(name: str) -> dict[str, Any]:
    return {"eventName": name, "args": []}


@pytest.mark.asyncio
async def test_consumes_tracee_events() -> None:
    got: list[str] = []

    async def handler(e: dict[str, Any]) -> None:
        got.append(e["eventName"])

    stats = await TraceeRealtimeSubscriber(
        _Stream([_ev("security_file_open"), _ev("sched_process_exec")]), handler
    ).run()
    assert stats.handled == 2 and stats.errors == 0
    assert got == ["security_file_open", "sched_process_exec"]


@pytest.mark.asyncio
async def test_empty_stream() -> None:
    async def handler(_: dict[str, Any]) -> None: ...

    stats = await TraceeRealtimeSubscriber(_Stream([]), handler).run()
    assert stats.received == 0


@pytest.mark.asyncio
async def test_backpressure_drop() -> None:
    gate = asyncio.Event()

    async def blocked(_: dict[str, Any]) -> None:
        await gate.wait()

    sub = TraceeRealtimeSubscriber(
        _Stream([_ev(str(i)) for i in range(10)]), blocked, queue_maxsize=2, drop_on_full=True
    )
    task = asyncio.create_task(sub.run())
    await asyncio.sleep(0.05)
    gate.set()
    stats = await asyncio.wait_for(task, timeout=2.0)
    assert stats.dropped > 0 and stats.handled + stats.dropped == 10


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

    sub = TraceeRealtimeSubscriber(_Infinite(), handler)
    task = asyncio.create_task(sub.run())
    await asyncio.sleep(0.05)
    sub.request_stop()
    stats = await asyncio.wait_for(task, timeout=2.0)
    assert stats.handled > 0


def test_tracee_realtime_and_heartbeat_coexist() -> None:
    # Q2: Tracee real-time added ALONGSIDE the offline heartbeat path.
    from runtime_threat.tools.tracee import tracee_alerts_read

    assert callable(tracee_alerts_read)
