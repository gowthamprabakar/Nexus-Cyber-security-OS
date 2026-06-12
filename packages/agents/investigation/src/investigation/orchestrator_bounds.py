"""Orchestrator-Workers bounds — code-level invariant (investigation v0.2 Task 17, WI-I11).

The first of D.7's **three NEW** invariants — and a **new institutional pattern** for
Orchestrator-Workers agents. Per **Q1/H5** a sub-investigation tree is bounded: **depth <= 3**,
**parallel <= 5** per batch. ``assert_worker_bounded`` is the hard guard called at
``spawn_batch`` + the F.5 memory-walk depth; over-cap raises (never worked around). Mirrors the
D.3/D.4/data-security/F.6/supervisor/D.13 invariant pattern. The template D.12 / A.1 / future
orchestrator-style agents inherit.
"""

from __future__ import annotations

from investigation.orchestrator import MAX_SUB_AGENT_DEPTH, MAX_SUB_AGENTS_PARALLEL


class WorkerBoundsViolationError(RuntimeError):
    """Raised when a sub-investigation exceeds the H5 depth/parallel caps (WI-I11)."""


def assert_worker_bounded(depth: int, parallel: int) -> None:
    """Hard guard — raise if ``depth`` > 3 or ``parallel`` > 5 (the H5 Orchestrator-Workers caps).

    Depth is checked first so a too-deep tree surfaces before a too-wide batch.
    """
    if depth > MAX_SUB_AGENT_DEPTH:
        raise WorkerBoundsViolationError(
            f"Investigation depth {depth} exceeds the H5 cap of {MAX_SUB_AGENT_DEPTH}."
        )
    if parallel > MAX_SUB_AGENTS_PARALLEL:
        raise WorkerBoundsViolationError(
            f"Parallel workers {parallel} exceed the H5 cap of {MAX_SUB_AGENTS_PARALLEL}."
        )
