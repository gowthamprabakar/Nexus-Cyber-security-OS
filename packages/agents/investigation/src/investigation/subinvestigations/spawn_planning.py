"""Spawn-batch planning + allowlist verification (investigation v0.2 Task 9, WI-I11/WI-I15).

Splits a set of sub-investigations into batches that each honor the **H5 parallel cap**
(``MAX_SUB_AGENTS_PARALLEL = 5``) — so the orchestrator never exceeds the cap in a single batch
(WI-I11; the hard guard ``assert_worker_bounded`` lands in Task 17). Also re-exposes the
**sub-agent allowlist check** (``only_investigation_spawns``) — WI-I15: only ``investigation``
may spawn workers, preserving the Supervisor H2 hierarchy. Pure + deterministic.
"""

from __future__ import annotations

from investigation.orchestrator import MAX_SUB_AGENTS_PARALLEL, SUB_AGENT_ALLOWLIST


def plan_spawn_batches(
    worker_count: int, *, parallel_cap: int = MAX_SUB_AGENTS_PARALLEL
) -> tuple[int, ...]:
    """Split ``worker_count`` workers into batches of at most ``parallel_cap`` (H5/WI-I11)."""
    if worker_count < 0:
        raise ValueError(f"worker_count must be >= 0 (got {worker_count})")
    if parallel_cap < 1:
        raise ValueError(f"parallel_cap must be >= 1 (got {parallel_cap})")
    full, remainder = divmod(worker_count, parallel_cap)
    batches = [parallel_cap] * full
    if remainder:
        batches.append(remainder)
    return tuple(batches)


def only_investigation_spawns() -> bool:
    """WI-I15: the spawn allowlist is exactly ``{"investigation"}`` (Supervisor H2 hierarchy)."""
    return frozenset({"investigation"}) == SUB_AGENT_ALLOWLIST
