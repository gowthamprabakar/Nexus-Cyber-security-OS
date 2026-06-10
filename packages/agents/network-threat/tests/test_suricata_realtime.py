"""D.4 v0.2 Task 2 — Suricata real-time subscription framework tests (no live socket)."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from typing import Any

import pytest
from network_threat.tools.suricata_realtime import SuricataRealtimeSubscriber


class _Stream:
    def __init__(self, events: list[dict[str, Any]]) -> None:
        self._events = events

    async def subscribe(self) -> AsyncIterator[dict[str, Any]]:
        for e in self._events:
            yield e


def _alert(sig: str) -> dict[str, Any]:
    return {"event_type": "alert", "alert": {"signature": sig}}


@pytest.mark.asyncio
async def test_consumes_all_events() -> None:
    got: list[str] = []

    async def handler(e: dict[str, Any]) -> None:
        got.append(e["alert"]["signature"])

    stats = await SuricataRealtimeSubscriber(_Stream([_alert("a"), _alert("b")]), handler).run()
    assert stats.received == 2 and stats.handled == 2 and stats.errors == 0
    assert got == ["a", "b"]


@pytest.mark.asyncio
async def test_empty_stream() -> None:
    async def handler(_: dict[str, Any]) -> None: ...

    stats = await SuricataRealtimeSubscriber(_Stream([]), handler).run()
    assert stats.received == 0


@pytest.mark.asyncio
async def test_handler_error_counted_not_fatal() -> None:
    async def bad(e: dict[str, Any]) -> None:
        if e["alert"]["signature"] == "boom":
            raise RuntimeError("x")

    stats = await SuricataRealtimeSubscriber(
        _Stream([_alert("ok"), _alert("boom"), _alert("ok")]), bad
    ).run()
    assert stats.handled == 2 and stats.errors == 1


@pytest.mark.asyncio
async def test_stream_error_counted_not_fatal() -> None:
    class _Flaky:
        async def subscribe(self) -> AsyncIterator[dict[str, Any]]:
            yield _alert("first")
            raise RuntimeError("socket dropped")

    async def handler(_: dict[str, Any]) -> None: ...

    stats = await SuricataRealtimeSubscriber(_Flaky(), handler).run()
    assert stats.handled == 1 and stats.errors == 1


@pytest.mark.asyncio
async def test_backpressure_drops_when_full() -> None:
    gate = asyncio.Event()

    async def blocked(_: dict[str, Any]) -> None:
        await gate.wait()

    sub = SuricataRealtimeSubscriber(
        _Stream([_alert(str(i)) for i in range(10)]), blocked, queue_maxsize=2, drop_on_full=True
    )
    task = asyncio.create_task(sub.run())
    await asyncio.sleep(0.05)
    gate.set()
    stats = await asyncio.wait_for(task, timeout=2.0)
    assert stats.dropped > 0 and stats.handled + stats.dropped == 10


@pytest.mark.asyncio
async def test_lossless_block_default() -> None:
    got: list[str] = []

    async def handler(e: dict[str, Any]) -> None:
        got.append(e["alert"]["signature"])

    sub = SuricataRealtimeSubscriber(
        _Stream([_alert(str(i)) for i in range(20)]), handler, queue_maxsize=2
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
                yield _alert(str(i))
                i += 1
                await asyncio.sleep(0.001)

    async def handler(_: dict[str, Any]) -> None: ...

    sub = SuricataRealtimeSubscriber(_Infinite(), handler)
    task = asyncio.create_task(sub.run())
    await asyncio.sleep(0.05)
    sub.request_stop()
    stats = await asyncio.wait_for(task, timeout=2.0)
    assert stats.handled > 0


def test_realtime_and_heartbeat_coexist() -> None:
    # Q1: real-time added ALONGSIDE the offline heartbeat path — both importable.
    from network_threat.tools.suricata_reader import read_suricata_alerts

    assert callable(read_suricata_alerts)
