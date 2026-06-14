"""Shared real-time / push-stream infrastructure (Phase D A-1).

Agent-agnostic primitives for consuming live sensor push streams in a
single-shot agent ``run()``. Currently: :func:`bounded_drain` (count/time
bounded drain of an infinite push stream). Pure asyncio + stdlib; no charter
or shared dependency.
"""

from nexus_runtime.realtime.bounded_drain import (
    BoundedDrainError,
    EventStream,
    bounded_drain,
)

__all__ = [
    "BoundedDrainError",
    "EventStream",
    "bounded_drain",
]
