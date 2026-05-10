"""Typed results: EvalResult (per case) + SuiteResult (per suite run).

These are the contract the framework exposes to downstream consumers
(Meta-Harness, CI gates, comparison reports). Pydantic + frozen so JSON
I/O is free and the values can be cached / hashed.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from eval_framework.trace import EvalTrace


class EvalResult(BaseModel):
    """Outcome of running one `EvalCase` through one `EvalRunner`."""

    case_id: str
    runner: str  # agent_name from the runner
    passed: bool
    failure_reason: str | None
    actuals: dict[str, Any] = Field(default_factory=dict)
    duration_sec: float = Field(ge=0.0)
    trace: EvalTrace

    model_config = ConfigDict(frozen=True)


class SuiteResult(BaseModel):
    """Outcome of running an entire suite of `EvalCase`s through one runner.

    `provider_id` and `model_pin` are populated when the runner was given an
    `LLMProvider`; they're `None` for deterministic runs. Both fields survive
    JSON round-trip so the cross-provider parity gate ([ADR-003] consequence)
    can compare two runs by provider.
    """

    suite_id: str  # ULID minted by the suite runner
    runner: str
    started_at: datetime
    completed_at: datetime
    cases: list[EvalResult]
    provider_id: str | None = None
    model_pin: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(frozen=True)

    @property
    def total(self) -> int:
        return len(self.cases)

    @property
    def passed(self) -> int:
        return sum(1 for c in self.cases if c.passed)

    @property
    def pass_rate(self) -> float:
        if not self.cases:
            return 1.0  # vacuously true; an empty suite has no failures
        return self.passed / self.total
