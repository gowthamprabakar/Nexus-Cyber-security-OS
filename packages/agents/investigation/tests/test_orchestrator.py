"""Tests for `investigation.orchestrator` (D.7 Task 8 / Q2 resolution).

Sub-agent spawning primitive. The orchestrator-workers pattern. D.7 is
the **first agent** to need this, so the primitive lives here in v0.1
with allowlist enforcement (one entry: `investigation`). Promotes to
`charter.subagent` in ADR-007 v1.4 if Supervisor (when it ships)
duplicates the pattern.

Production contract:

- `SubAgentOrchestrator(parent_agent_id)` validates the parent against
  the allowlist at construction. Non-allowed parent → `PermissionError`.
- `spawn_batch(parent_depth, scopes, worker)` runs every scope
  concurrently under `asyncio.TaskGroup`. Returns `tuple[SubResult, ...]`.
- Depth enforced: `parent_depth + 1` must be ≤ `MAX_SUB_AGENT_DEPTH = 3`.
  Over-depth raises `SubAgentDepthExceeded` at spawn time.
- Parallel enforced: at most `MAX_SUB_AGENTS_PARALLEL = 5` scopes per
  `spawn_batch` call. Over-limit raises `SubAgentParallelExceeded`.
- Worker function signature: `async def worker(scope: dict[str, Any])
  -> Any`. Whatever it returns gets wrapped in a `SubResult` along
  with the scope and a deterministic sub-id.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest
from investigation.orchestrator import (
    MAX_SUB_AGENT_DEPTH,
    MAX_SUB_AGENTS_PARALLEL,
    SUB_AGENT_ALLOWLIST,
    SubAgentDepthExceeded,
    SubAgentOrchestrator,
    SubAgentParallelExceeded,
    SubResult,
)

# ---------------------------- allowlist --------------------------------


def test_allowlist_has_only_investigation_in_v0_1() -> None:
    """v0.1 ships one entry. ADR-007 v1.4 candidate adds Supervisor when it lands."""
    assert frozenset({"investigation"}) == SUB_AGENT_ALLOWLIST


def test_constructor_rejects_non_allowlisted_parent() -> None:
    with pytest.raises(PermissionError, match="not authorized"):
        SubAgentOrchestrator(parent_agent_id="cloud_posture")


def test_constructor_accepts_allowlisted_parent() -> None:
    orch = SubAgentOrchestrator(parent_agent_id="investigation")
    assert orch.parent_agent_id == "investigation"


# ---------------------------- cap constants ----------------------------


def test_cap_constants_match_agent_spec() -> None:
    """Agent spec pins depth ≤ 3 and parallel ≤ 5 (per the D.7 plan)."""
    assert MAX_SUB_AGENT_DEPTH == 3
    assert MAX_SUB_AGENTS_PARALLEL == 5


# ---------------------------- depth enforcement ----------------------


@pytest.mark.asyncio
async def test_spawn_batch_at_depth_zero_succeeds() -> None:
    """Parent at depth 0 spawning children → child depth = 1 (≤ 3)."""
    orch = SubAgentOrchestrator(parent_agent_id="investigation")

    async def worker(scope: dict[str, Any]) -> dict[str, Any]:
        return {"echoed": scope["payload"]}

    results = await orch.spawn_batch(
        parent_depth=0,
        scopes=[
            {"kind": "timeline", "payload": "a"},
            {"kind": "ioc_pivot", "payload": "b"},
        ],
        worker=worker,
    )
    assert len(results) == 2
    assert results[0].depth == 1


@pytest.mark.asyncio
async def test_spawn_batch_at_depth_two_succeeds() -> None:
    """Parent at depth 2 → child depth = 3 (== cap, still allowed)."""
    orch = SubAgentOrchestrator(parent_agent_id="investigation")

    async def worker(scope: dict[str, Any]) -> str:
        return "ok"

    results = await orch.spawn_batch(
        parent_depth=2,
        scopes=[{"kind": "timeline"}],
        worker=worker,
    )
    assert len(results) == 1
    assert results[0].depth == 3


@pytest.mark.asyncio
async def test_spawn_batch_rejects_when_child_would_exceed_max_depth() -> None:
    orch = SubAgentOrchestrator(parent_agent_id="investigation")

    async def worker(scope: dict[str, Any]) -> str:
        return "ok"

    with pytest.raises(SubAgentDepthExceeded):
        await orch.spawn_batch(
            parent_depth=3,  # child would be depth 4 → exceeds cap
            scopes=[{"kind": "timeline"}],
            worker=worker,
        )


# ---------------------------- parallel enforcement -------------------


@pytest.mark.asyncio
async def test_spawn_batch_accepts_up_to_five_parallel() -> None:
    orch = SubAgentOrchestrator(parent_agent_id="investigation")

    async def worker(scope: dict[str, Any]) -> int:
        return int(scope["i"])

    scopes = [{"kind": "timeline", "i": i} for i in range(5)]
    results = await orch.spawn_batch(parent_depth=0, scopes=scopes, worker=worker)
    assert {r.result for r in results} == {0, 1, 2, 3, 4}


@pytest.mark.asyncio
async def test_spawn_batch_rejects_six_or_more_parallel() -> None:
    orch = SubAgentOrchestrator(parent_agent_id="investigation")

    async def worker(scope: dict[str, Any]) -> str:
        return "ok"

    with pytest.raises(SubAgentParallelExceeded):
        await orch.spawn_batch(
            parent_depth=0,
            scopes=[{"kind": "x"} for _ in range(6)],
            worker=worker,
        )


# ---------------------------- concurrency ----------------------------


@pytest.mark.asyncio
async def test_workers_run_concurrently_not_serially() -> None:
    """Five workers each sleeping 0.1s should finish in < 0.5s when
    parallel. Loose bound (< 0.3s) to absorb fixture overhead.
    """
    import time

    orch = SubAgentOrchestrator(parent_agent_id="investigation")

    async def slow_worker(scope: dict[str, Any]) -> int:
        await asyncio.sleep(0.1)
        return int(scope["i"])

    start = time.perf_counter()
    await orch.spawn_batch(
        parent_depth=0,
        scopes=[{"kind": "timeline", "i": i} for i in range(5)],
        worker=slow_worker,
    )
    elapsed = time.perf_counter() - start
    assert elapsed < 0.3, f"workers ran serially: {elapsed:.2f}s"


# ---------------------------- result shape ---------------------------


@pytest.mark.asyncio
async def test_sub_result_carries_scope_kind_and_depth() -> None:
    orch = SubAgentOrchestrator(parent_agent_id="investigation")

    async def worker(scope: dict[str, Any]) -> str:
        return f"processed {scope['payload']}"

    results = await orch.spawn_batch(
        parent_depth=1,
        scopes=[{"kind": "ioc_pivot", "payload": "abc"}],
        worker=worker,
    )
    assert len(results) == 1
    r = results[0]
    assert isinstance(r, SubResult)
    assert r.kind == "ioc_pivot"
    assert r.depth == 2
    assert r.result == "processed abc"
    assert r.sub_id  # non-empty deterministic ID


@pytest.mark.asyncio
async def test_sub_ids_are_unique_per_batch() -> None:
    orch = SubAgentOrchestrator(parent_agent_id="investigation")

    async def worker(scope: dict[str, Any]) -> str:
        return "x"

    results = await orch.spawn_batch(
        parent_depth=0,
        scopes=[{"kind": "timeline"}, {"kind": "ioc_pivot"}, {"kind": "asset_enum"}],
        worker=worker,
    )
    ids = {r.sub_id for r in results}
    assert len(ids) == 3


# ---------------------------- empty batch ----------------------------


@pytest.mark.asyncio
async def test_empty_scope_list_returns_empty_tuple() -> None:
    orch = SubAgentOrchestrator(parent_agent_id="investigation")

    async def worker(scope: dict[str, Any]) -> str:
        return "never called"

    results = await orch.spawn_batch(parent_depth=0, scopes=[], worker=worker)
    assert results == ()
