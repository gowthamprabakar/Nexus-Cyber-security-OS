"""Sub-agent orchestrator — Orchestrator-Workers primitive (D.7 Task 8).

**Q2 resolution from the D.7 plan.** The runtime charter has no
sub-agent spawning primitive in F.1; D.7 is the first agent that needs
one. v0.1 lands the primitive **here in D.7** with:

- **Explicit allowlist** of which agents may spawn sub-agents
  (`SUB_AGENT_ALLOWLIST`). One entry in v0.1: `investigation`. The
  constructor refuses any other parent_agent_id with `PermissionError`.
- **Depth cap** at `MAX_SUB_AGENT_DEPTH = 3` (matches the agent spec).
  A parent at depth 3 attempting to spawn raises `SubAgentDepthExceeded`
  at spawn time (not after the workers fire).
- **Parallel cap** at `MAX_SUB_AGENTS_PARALLEL = 5` per batch (matches
  the agent spec). Over-limit raises `SubAgentParallelExceeded`.

If Supervisor (when it ships) needs the same pattern, this module
hoists to `charter.subagent` as ADR-007 v1.4 (the "third duplicate"
rule). v0.1 keeps it local + allowlisted so the policy stays explicit.

**v0.1 simplification.** Sub-agents do NOT get their own
`ExecutionContract` / `Charter` / workspace in this version. The agent
spec calls for that, but a per-sub-Charter is heavy infrastructure
(child workspace + audit log + budget envelope per spawn). v0.1 runs
sub-investigations as **scoped TaskGroup workers under the parent
Charter** — same tenant, same audit chain, narrower budget reasoning
(the parent driver caps each scope's work via the worker function).
Phase 1c can introduce real per-sub-Charter spawning if real workloads
demand it.
"""

from __future__ import annotations

import asyncio
import secrets
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from typing import Any

MAX_SUB_AGENT_DEPTH = 3
MAX_SUB_AGENTS_PARALLEL = 5

SUB_AGENT_ALLOWLIST: frozenset[str] = frozenset({"investigation"})


class SubAgentDepthExceeded(RuntimeError):
    """Spawn would push a child past `MAX_SUB_AGENT_DEPTH`."""


class SubAgentParallelExceeded(RuntimeError):
    """Batch exceeds `MAX_SUB_AGENTS_PARALLEL` scopes."""


@dataclass(frozen=True, slots=True)
class SubResult:
    """A completed sub-investigation's output."""

    sub_id: str
    kind: str
    depth: int
    scope: dict[str, Any]
    result: Any


WorkerFn = Callable[[dict[str, Any]], Awaitable[Any]]


class SubAgentOrchestrator:
    """Spawn + manage sub-investigations under depth/parallel caps."""

    def __init__(self, *, parent_agent_id: str) -> None:
        if parent_agent_id not in SUB_AGENT_ALLOWLIST:
            raise PermissionError(
                f"parent_agent_id={parent_agent_id!r} not authorized to spawn "
                f"sub-agents; allowlist = {sorted(SUB_AGENT_ALLOWLIST)}"
            )
        self.parent_agent_id = parent_agent_id

    async def spawn_batch(
        self,
        *,
        parent_depth: int,
        scopes: Sequence[dict[str, Any]],
        worker: WorkerFn,
    ) -> tuple[SubResult, ...]:
        """Run every scope concurrently under `asyncio.TaskGroup`.

        Each scope is dispatched to `worker(scope)` as an async call.
        The orchestrator wraps each result in a `SubResult` with a
        deterministic sub-id, the scope's `kind`, the child depth, and
        the worker's return value.

        Enforces depth + parallel caps **before** spawning any worker.
        An over-cap batch fails fast — no workers run.
        """
        if not scopes:
            return ()

        child_depth = parent_depth + 1
        if child_depth > MAX_SUB_AGENT_DEPTH:
            raise SubAgentDepthExceeded(
                f"parent_depth={parent_depth} → child depth {child_depth} "
                f"exceeds MAX_SUB_AGENT_DEPTH={MAX_SUB_AGENT_DEPTH}"
            )
        if len(scopes) > MAX_SUB_AGENTS_PARALLEL:
            raise SubAgentParallelExceeded(
                f"batch size {len(scopes)} exceeds MAX_SUB_AGENTS_PARALLEL="
                f"{MAX_SUB_AGENTS_PARALLEL}"
            )

        # Pre-assign sub_ids so the wire shape is deterministic on
        # success and the ordering matches the input.
        sub_ids = [secrets.token_hex(8) for _ in scopes]

        results: list[SubResult | None] = [None] * len(scopes)

        async def _run(idx: int, sub_id: str, scope: dict[str, Any]) -> None:
            kind = str(scope.get("kind", "unknown"))
            result = await worker(scope)
            results[idx] = SubResult(
                sub_id=sub_id,
                kind=kind,
                depth=child_depth,
                scope=scope,
                result=result,
            )

        async with asyncio.TaskGroup() as tg:
            for idx, (sub_id, scope) in enumerate(zip(sub_ids, scopes, strict=True)):
                tg.create_task(_run(idx, sub_id, scope))

        return tuple(r for r in results if r is not None)


__all__ = [
    "MAX_SUB_AGENTS_PARALLEL",
    "MAX_SUB_AGENT_DEPTH",
    "SUB_AGENT_ALLOWLIST",
    "SubAgentDepthExceeded",
    "SubAgentOrchestrator",
    "SubAgentParallelExceeded",
    "SubResult",
]
