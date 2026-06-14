"""Bounded drain for single-shot consumption of push event streams (A-1).

Live sensor sources (Suricata / Zeek / Falco / Tracee) are **infinite push
streams**: a subscriber consumes them forever via an async iterator and never
returns a record collection. A single-shot agent ``run()`` that needs "the
events available now" must therefore *bound* the drain — by count, by
wall-clock, or both — collecting normalized records as it goes.

This module is the shared, agent-agnostic abstraction for that. It has **zero
charter / shared dependency** (pure ``asyncio`` + stdlib), so any agent under
``packages/agents`` can import it. network-threat (Suricata + Zeek-DNS) and
runtime-threat (Falco + Tracee) wire their *existing* per-sensor normalizers
into it; because those normalizers already produce byte-identical offline
shapes, downstream stages stay source-agnostic.

This PR is **abstraction-only** — it ships the drain primitive and its tests.
The agent wiring that consumes it lands in the A-1.4 / A-1.5 cascade PRs.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Callable
from typing import Any, Protocol


class EventStream(Protocol):
    """A push event source.

    ``subscribe()`` yields raw event dicts until the stream ends (a finite
    source — e.g. a test fixture or a closed socket) or forever (a live socket).
    This matches the per-sensor ``*EventStream`` protocols the agents already
    define (Suricata/Zeek/Falco/Tracee), so an agent passes its live stream
    straight through.
    """

    def subscribe(self) -> AsyncIterator[dict[str, Any]]: ...


class BoundedDrainError(ValueError):
    """Raised when a drain is misconfigured.

    Most importantly: requesting a drain with **no bound** against a possibly
    infinite stream (neither ``max_events`` nor ``max_duration_seconds``) would
    never return, so it is rejected up front rather than hanging ``run()``.
    """


async def bounded_drain[T](
    stream: EventStream,
    normalize: Callable[[dict[str, Any]], T | None],
    *,
    max_events: int | None = None,
    max_duration_seconds: float | None = None,
) -> tuple[T, ...]:
    """Drain a push event stream into a bounded tuple of normalized records.

    Consumes ``stream.subscribe()``, applies ``normalize`` to each raw event
    (returning ``None`` to skip that event), and stops at the first bound
    reached:

    - ``max_events`` — stop after this many *normalized* (non-``None``) records.
    - ``max_duration_seconds`` — stop after this much wall-clock has elapsed.

    At least one bound MUST be set; otherwise a live (infinite) stream would
    never return — that raises :class:`BoundedDrainError`. A naturally finite
    stream still terminates on its own once exhausted. Records collected before
    a time bound fires are returned (a timeout is a normal stop, not an error).

    The drain is intentionally minimal: no internal queue or backpressure. For
    a single-shot "events available now" read that is correct — the caller
    bounds the read and the event loop interleaves production and the
    (synchronous, cheap) ``normalize`` call.

    Args:
        stream: The push source (its ``subscribe()`` async-iterates raw dicts).
        normalize: Maps a raw event dict to a typed record, or ``None`` to skip.
        max_events: Optional count bound (must be positive if set).
        max_duration_seconds: Optional wall-clock bound (must be positive if set).

    Returns:
        The collected records, in arrival order, as a tuple.

    Raises:
        BoundedDrainError: if no bound is set, or a bound is non-positive.
    """
    if max_events is None and max_duration_seconds is None:
        raise BoundedDrainError(
            "bounded_drain requires max_events and/or max_duration_seconds — "
            "an unbounded drain of a live stream never returns"
        )
    if max_events is not None and max_events <= 0:
        raise BoundedDrainError(f"max_events must be positive, got {max_events}")
    if max_duration_seconds is not None and max_duration_seconds <= 0:
        raise BoundedDrainError(
            f"max_duration_seconds must be positive, got {max_duration_seconds}"
        )

    collected: list[T] = []

    async def _drain() -> None:
        async for raw in stream.subscribe():
            item = normalize(raw)
            if item is not None:
                collected.append(item)
                if max_events is not None and len(collected) >= max_events:
                    return

    if max_duration_seconds is not None:
        try:
            async with asyncio.timeout(max_duration_seconds):
                await _drain()
        except TimeoutError:
            pass  # time bound reached → return what was collected so far
    else:
        await _drain()

    return tuple(collected)
