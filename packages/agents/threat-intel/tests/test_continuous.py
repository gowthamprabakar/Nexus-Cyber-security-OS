"""D.8 v0.2 Task 2 — continuous-ingestion framework tests (no live feeds)."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from typing import Any

import pytest
from threat_intel.continuous import ContinuousIngestor, SubscriptionManager


def _finite_source(n: int):
    async def source() -> AsyncIterator[dict[str, Any]]:
        for i in range(n):
            yield {"i": i}

    return source


def test_register_and_introspect() -> None:
    mgr = SubscriptionManager()

    async def _h(_: dict[str, Any]) -> None: ...

    mgr.register("nvd", _finite_source(1), _h)
    mgr.register("kev", _finite_source(1), _h)
    assert set(mgr.names) == {"nvd", "kev"}
    assert mgr.get("nvd").name == "nvd"
    assert len(mgr.all()) == 2


def test_duplicate_registration_raises() -> None:
    mgr = SubscriptionManager()

    async def _h(_: dict[str, Any]) -> None: ...

    mgr.register("nvd", _finite_source(1), _h)
    with pytest.raises(ValueError, match="duplicate subscription"):
        mgr.register("nvd", _finite_source(1), _h)


@pytest.mark.asyncio
async def test_ingests_all_items_from_one_source() -> None:
    got: list[dict[str, Any]] = []

    async def handler(item: dict[str, Any]) -> None:
        got.append(item)

    mgr = SubscriptionManager()
    mgr.register("nvd", _finite_source(5), handler)
    stats = await ContinuousIngestor(mgr).run_until_drained()

    assert stats.ingested == 5
    assert stats.dropped == 0 and stats.errors == 0
    assert {g["i"] for g in got} == {0, 1, 2, 3, 4}


@pytest.mark.asyncio
async def test_multiple_subscriptions_ingest_concurrently() -> None:
    async def handler(_: dict[str, Any]) -> None: ...

    mgr = SubscriptionManager()
    mgr.register("nvd", _finite_source(3), handler)
    mgr.register("kev", _finite_source(4), handler)
    stats = await ContinuousIngestor(mgr).run_until_drained()

    assert stats.ingested == 7
    assert stats.per_feed == {"nvd": 3, "kev": 4}


@pytest.mark.asyncio
async def test_empty_manager_ingests_nothing() -> None:
    stats = await ContinuousIngestor(SubscriptionManager()).run_until_drained()
    assert stats.ingested == 0


@pytest.mark.asyncio
async def test_handler_error_is_counted_not_fatal() -> None:
    async def bad_handler(item: dict[str, Any]) -> None:
        if item["i"] == 2:
            raise RuntimeError("boom")

    mgr = SubscriptionManager()
    mgr.register("nvd", _finite_source(5), bad_handler)
    stats = await ContinuousIngestor(mgr).run_until_drained()

    assert stats.ingested == 4  # the other 4 still processed
    assert stats.errors == 1


@pytest.mark.asyncio
async def test_source_error_is_counted_not_fatal() -> None:
    async def flaky_source() -> AsyncIterator[dict[str, Any]]:
        yield {"i": 0}
        raise RuntimeError("feed dropped")

    async def handler(_: dict[str, Any]) -> None: ...

    mgr = SubscriptionManager()
    mgr.register("nvd", flaky_source, handler)
    stats = await ContinuousIngestor(mgr).run_until_drained()

    assert stats.ingested == 1  # the item before the failure
    assert stats.errors == 1


@pytest.mark.asyncio
async def test_backpressure_drops_when_full() -> None:
    gate = asyncio.Event()

    async def blocked_handler(_: dict[str, Any]) -> None:
        await gate.wait()  # hold the consumer so the bounded queue fills

    mgr = SubscriptionManager()
    mgr.register("nvd", _finite_source(10), blocked_handler)
    ing = ContinuousIngestor(mgr, queue_maxsize=2, drop_on_full=True)

    task = asyncio.create_task(ing.run_until_drained())
    await asyncio.sleep(0.05)  # let the producer fill the queue + drop the rest
    gate.set()
    stats = await asyncio.wait_for(task, timeout=2.0)

    assert stats.dropped > 0  # backpressure shed load
    assert stats.ingested + stats.dropped == 10  # nothing lost-and-uncounted


@pytest.mark.asyncio
async def test_graceful_shutdown_stops_producers() -> None:
    async def infinite_source() -> AsyncIterator[dict[str, Any]]:
        i = 0
        while True:
            yield {"i": i}
            i += 1
            await asyncio.sleep(0.001)

    async def handler(_: dict[str, Any]) -> None: ...

    mgr = SubscriptionManager()
    mgr.register("nvd", infinite_source, handler)
    ing = ContinuousIngestor(mgr)

    task = asyncio.create_task(ing.run())
    await asyncio.sleep(0.05)
    ing.request_stop()
    stats = await asyncio.wait_for(task, timeout=2.0)

    assert stats.ingested > 0  # ingested a bounded number, then stopped cleanly


@pytest.mark.asyncio
async def test_lossless_backpressure_blocks_not_drops() -> None:
    # Default (no drop_on_full): a small queue must NOT drop — every item lands.
    got: list[int] = []

    async def handler(item: dict[str, Any]) -> None:
        got.append(item["i"])

    mgr = SubscriptionManager()
    mgr.register("nvd", _finite_source(20), handler)
    stats = await ContinuousIngestor(mgr, queue_maxsize=2).run_until_drained()

    assert stats.ingested == 20 and stats.dropped == 0
    assert sorted(got) == list(range(20))
