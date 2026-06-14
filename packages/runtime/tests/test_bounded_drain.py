"""Tests for the bounded-drain abstraction (A-1 infrastructure).

Covers both bounds (count + time), infinite-stream termination, normalize-skip,
natural finite exhaustion, and the misconfiguration guards.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from typing import Any

import pytest
from nexus_runtime.realtime import BoundedDrainError, bounded_drain


class _FiniteStream:
    """Yields a fixed list of events, then ends."""

    def __init__(self, events: list[dict[str, Any]]) -> None:
        self._events = events

    async def subscribe(self) -> AsyncIterator[dict[str, Any]]:
        for e in self._events:
            yield e


class _InfiniteStream:
    """Yields events forever (models a live socket)."""

    async def subscribe(self) -> AsyncIterator[dict[str, Any]]:
        i = 0
        while True:
            yield {"n": i}
            i += 1
            await asyncio.sleep(0)  # cooperative yield


class _SlowStream:
    """Sleeps before the first event — lets a short time bound fire first."""

    async def subscribe(self) -> AsyncIterator[dict[str, Any]]:
        await asyncio.sleep(1.0)
        yield {"n": 0}


def _identity(raw: dict[str, Any]) -> dict[str, Any]:
    return raw


@pytest.mark.asyncio
async def test_count_bound_stops_at_max_events() -> None:
    out = await bounded_drain(_FiniteStream([{"n": i} for i in range(5)]), _identity, max_events=3)
    assert len(out) == 3
    assert [e["n"] for e in out] == [0, 1, 2]


@pytest.mark.asyncio
async def test_count_bound_terminates_infinite_stream() -> None:
    """The load-bearing property: a count bound stops an otherwise-infinite stream."""
    out = await bounded_drain(_InfiniteStream(), _identity, max_events=4)
    assert len(out) == 4


@pytest.mark.asyncio
async def test_finite_stream_exhausts_naturally_under_a_bound() -> None:
    out = await bounded_drain(_FiniteStream([{"n": 0}, {"n": 1}]), _identity, max_events=100)
    assert len(out) == 2  # stream ended before the bound


@pytest.mark.asyncio
async def test_normalize_none_skips_event() -> None:
    def _even_only(raw: dict[str, Any]) -> dict[str, Any] | None:
        return raw if raw["n"] % 2 == 0 else None

    out = await bounded_drain(
        _FiniteStream([{"n": i} for i in range(6)]), _even_only, max_events=10
    )
    assert [e["n"] for e in out] == [0, 2, 4]


@pytest.mark.asyncio
async def test_time_bound_returns_partial() -> None:
    """A short time bound fires before the slow stream yields → empty result."""
    out = await bounded_drain(_SlowStream(), _identity, max_duration_seconds=0.05)
    assert out == ()


@pytest.mark.asyncio
async def test_no_bound_raises() -> None:
    with pytest.raises(BoundedDrainError, match="requires max_events"):
        await bounded_drain(_FiniteStream([]), _identity)


@pytest.mark.asyncio
async def test_non_positive_max_events_raises() -> None:
    with pytest.raises(BoundedDrainError, match="max_events must be positive"):
        await bounded_drain(_FiniteStream([]), _identity, max_events=0)


@pytest.mark.asyncio
async def test_non_positive_duration_raises() -> None:
    with pytest.raises(BoundedDrainError, match="max_duration_seconds must be positive"):
        await bounded_drain(_FiniteStream([]), _identity, max_duration_seconds=0.0)
