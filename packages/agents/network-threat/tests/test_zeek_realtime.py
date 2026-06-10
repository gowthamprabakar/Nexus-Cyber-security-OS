"""D.4 v0.2 Task 5 — Zeek real-time subscription tests (no live Broker)."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from typing import Any

import pytest
from network_threat.tools.zeek_realtime import ZeekRealtimeSubscriber


class _Stream:
    def __init__(self, events: list[dict[str, Any]]) -> None:
        self._events = events

    async def subscribe(self) -> AsyncIterator[dict[str, Any]]:
        for e in self._events:
            yield e


def _conn(uid: str) -> dict[str, Any]:
    return {"_path": "conn", "uid": uid, "id.orig_h": "10.0.0.5", "id.resp_h": "1.2.3.4"}


@pytest.mark.asyncio
async def test_consumes_zeek_events() -> None:
    got: list[str] = []

    async def handler(e: dict[str, Any]) -> None:
        got.append(e["uid"])

    stats = await ZeekRealtimeSubscriber(_Stream([_conn("c1"), _conn("c2")]), handler).run()
    assert stats.handled == 2 and stats.errors == 0
    assert got == ["c1", "c2"]


@pytest.mark.asyncio
async def test_empty_stream() -> None:
    async def handler(_: dict[str, Any]) -> None: ...

    stats = await ZeekRealtimeSubscriber(_Stream([]), handler).run()
    assert stats.received == 0


@pytest.mark.asyncio
async def test_backpressure_drop() -> None:
    gate = asyncio.Event()

    async def blocked(_: dict[str, Any]) -> None:
        await gate.wait()

    sub = ZeekRealtimeSubscriber(
        _Stream([_conn(str(i)) for i in range(10)]), blocked, queue_maxsize=2, drop_on_full=True
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
                yield _conn(str(i))
                i += 1
                await asyncio.sleep(0.001)

    async def handler(_: dict[str, Any]) -> None: ...

    sub = ZeekRealtimeSubscriber(_Infinite(), handler)
    task = asyncio.create_task(sub.run())
    await asyncio.sleep(0.05)
    sub.request_stop()
    stats = await asyncio.wait_for(task, timeout=2.0)
    assert stats.handled > 0


def test_zeek_and_heartbeat_coexist() -> None:
    # Q2: Zeek real-time added ALONGSIDE the offline DNS heartbeat path.
    from network_threat.tools.dns_log_reader import read_dns_logs

    assert callable(read_dns_logs)
