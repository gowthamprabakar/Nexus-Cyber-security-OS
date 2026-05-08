"""Budget envelope — tracks 5-dimensional resource consumption per agent invocation."""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from charter.exceptions import BudgetExhausted

_DIMENSIONS = ("llm_calls", "tokens", "wall_clock_sec", "cloud_api_calls", "mb_written")


@dataclass
class BudgetEnvelope:
    """Five-dimensional budget envelope.

    All limits must be positive. Consume tracks usage; exceeding any
    dimension raises BudgetExhausted.
    """

    llm_calls: int
    tokens: int
    wall_clock_sec: float
    cloud_api_calls: int
    mb_written: int
    _used: dict[str, float] = field(default_factory=lambda: dict.fromkeys(_DIMENSIONS, 0))
    _start: float | None = None

    def __post_init__(self) -> None:
        for dim in _DIMENSIONS:
            limit = getattr(self, dim)
            if limit <= 0:
                raise ValueError(f"{dim} must be positive (got {limit})")

    def start_clock(self) -> None:
        self._start = time.monotonic()

    def consume(self, **kwargs: float) -> None:
        """Apply usage; raises BudgetExhausted if any dimension over."""
        for dim, amount in kwargs.items():
            if dim not in _DIMENSIONS:
                raise ValueError(f"unknown budget dimension: {dim}")
            self._used[dim] += amount
            limit = getattr(self, dim)
            if self._used[dim] > limit:
                raise BudgetExhausted(dimension=dim, limit=limit, used=self._used[dim])

    def check_wall_clock(self) -> None:
        """Verify we haven't exceeded wall-clock budget. Call periodically."""
        if self._start is None:
            return
        elapsed = time.monotonic() - self._start
        self._used["wall_clock_sec"] = elapsed
        if elapsed > self.wall_clock_sec:
            raise BudgetExhausted(
                dimension="wall_clock_sec", limit=self.wall_clock_sec, used=elapsed
            )

    def used(self, dimension: str) -> float:
        return self._used[dimension]

    def remaining(self, dimension: str) -> float:
        limit: float = getattr(self, dimension)
        return limit - self._used[dimension]
