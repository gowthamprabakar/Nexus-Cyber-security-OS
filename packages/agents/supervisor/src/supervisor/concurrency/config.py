"""Dynamic concurrency configuration (supervisor v0.2 Task 6, Q2).

Loads the per-agent concurrency caps from the charter contract config (a plain mapping the
supervisor receives — not a tool, the deviation holds), builds a ``PerAgentSemaphores``, and
provides a **timeout-aware** acquire so a delegation that can't get a slot within a bound
surfaces backpressure (``SemaphoreWaitTimeout``) instead of blocking forever.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Mapping
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any

from supervisor.concurrency.per_agent import DEFAULT_PER_AGENT_CAP, PerAgentSemaphores

CONCURRENCY_CONFIG_KEY = "supervisor_concurrency"


class SemaphoreWaitTimeout(RuntimeError):
    """A delegation could not acquire its per-agent slot within the wait timeout."""


@dataclass(frozen=True, slots=True)
class ConcurrencyConfig:
    default_cap: int = DEFAULT_PER_AGENT_CAP
    overrides: Mapping[str, int] = field(default_factory=dict)


def parse_concurrency_config(raw: Mapping[str, Any] | None) -> ConcurrencyConfig:
    """Parse a config mapping ``{"default_cap": int, "overrides": {agent: int}}``; absent keys
    fall back to the Q2 default. Caps must be >= 1."""
    if not raw:
        return ConcurrencyConfig()
    default_cap = raw.get("default_cap", DEFAULT_PER_AGENT_CAP)
    overrides_raw = raw.get("overrides", {})
    if not isinstance(default_cap, int) or default_cap < 1:
        raise ValueError(f"default_cap must be an int >= 1 (got {default_cap!r})")
    overrides: dict[str, int] = {}
    if isinstance(overrides_raw, Mapping):
        for agent, cap in overrides_raw.items():
            if not isinstance(cap, int) or cap < 1:
                raise ValueError(f"override cap for {agent!r} must be an int >= 1 (got {cap!r})")
            overrides[str(agent)] = cap
    return ConcurrencyConfig(default_cap=default_cap, overrides=overrides)


def build_semaphores(config: ConcurrencyConfig) -> PerAgentSemaphores:
    return PerAgentSemaphores(default_cap=config.default_cap, overrides=config.overrides)


@asynccontextmanager
async def acquire_within(
    semaphores: PerAgentSemaphores, agent_id: str, *, timeout_s: float
) -> AsyncIterator[None]:
    """Acquire ``agent_id``'s slot within ``timeout_s`` seconds, else raise
    ``SemaphoreWaitTimeout`` (concurrency backpressure)."""
    sem = semaphores.semaphore_for(agent_id)
    try:
        await asyncio.wait_for(sem.acquire(), timeout=timeout_s)
    except TimeoutError as exc:
        raise SemaphoreWaitTimeout(
            f"delegation to {agent_id!r} could not acquire a slot within {timeout_s}s "
            f"(cap={semaphores.cap_for(agent_id)})"
        ) from exc
    try:
        yield
    finally:
        sem.release()
