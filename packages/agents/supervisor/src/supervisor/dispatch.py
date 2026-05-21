"""Parallel-dispatch orchestrator — Stage 3 DISPATCH.

Takes a list of ``RoutingMatch`` decisions + a per-delegation
``DelegationInvoker`` callable and returns ``DelegationOutcome[]``
under a concurrency cap (default 5 per Q3 / ``MAX_PARALLEL_DISPATCH``).

**Dependency-injection design.** Dispatch is pure orchestration:
- It constructs a ``DelegationContract`` for each match.
- It wraps each invocation in ``asyncio.wait_for`` for budget
  enforcement (per Q4 — one attempt; no auto-retry).
- It catches every per-delegation exception and surfaces it as
  ``DelegationOutcome(status="error", reason=...)``.
- The actual specialist-invocation logic lives in the injected
  ``invoker`` (production: agent.py wires it to entry-point
  lookup + ``agent.run(...)``; tests: fake callable).

This keeps dispatch.py decoupled from charter ExecutionContract
construction + entry-point resolution — both land in Task 10's
agent.py integration layer.

**Failure model** (per Q4):

- ``OK`` — invoker returned a normal outcome.
- ``TIMEOUT_PARTIAL`` — ``asyncio.wait_for`` raised TimeoutError
  on the budget; reason notes the budget value.
- ``ERROR`` — any other exception; reason carries the
  ``type(exc).__name__: exc`` prefix.

**Q-ARCH-2 compliance.** No LLM import. No A.4 introspection
import. Source-grep guard in test_smoke.py still passes.

**WI-4 sub-clause.** Dispatch never inspects ``DelegationContract``
fields beyond what it passes through; no OCSF payload introspection.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Sequence
from datetime import UTC, datetime
from typing import Protocol

from supervisor.schemas import (
    MAX_PARALLEL_DISPATCH,
    DelegationContract,
    DelegationOutcome,
    DelegationStatus,
)


class DelegationInvoker(Protocol):
    """Per-delegation callable. Production wires this to the
    ``nexus_eval_runners`` entry-point lookup + ``agent.run``;
    tests pass a fake."""

    def __call__(self, contract: DelegationContract) -> Awaitable[None]: ...


async def dispatch_parallel(
    contracts: Sequence[DelegationContract],
    *,
    invoker: DelegationInvoker,
    concurrency: int = MAX_PARALLEL_DISPATCH,
) -> list[DelegationOutcome]:
    """Dispatch every contract in parallel under a Semaphore.

    Per Q3:

    - One delegation per declared sub-task (Supervisor never
      *decides* which agents to invoke beyond what the caller
      pre-declared).
    - ``concurrency`` defaults to ``MAX_PARALLEL_DISPATCH`` (5);
      tests may override but production callers always use the
      default.

    Per Q4:

    - Per-delegation budget enforced via ``asyncio.wait_for``
      with ``timeout = contract.budget_wall_clock_sec``.
    - TimeoutError -> ``TIMEOUT_PARTIAL``.
    - Any other exception -> ``ERROR``.
    - Successful completion -> ``OK``.

    Order: the output list preserves ``contracts`` input order
    (asyncio.gather guarantees this).
    """
    if concurrency < 1:
        raise ValueError(f"concurrency must be >= 1 (got {concurrency})")

    semaphore = asyncio.Semaphore(concurrency)

    async def _run_one(contract: DelegationContract) -> DelegationOutcome:
        async with semaphore:
            return await _invoke_with_timeout(contract, invoker=invoker)

    return list(await asyncio.gather(*(_run_one(c) for c in contracts)))


async def _invoke_with_timeout(
    contract: DelegationContract,
    *,
    invoker: DelegationInvoker,
) -> DelegationOutcome:
    """Run one invoker call under wait_for + classify the outcome."""
    started = time.perf_counter()
    try:
        await asyncio.wait_for(
            invoker(contract),
            timeout=contract.budget_wall_clock_sec,
        )
    except TimeoutError:
        return DelegationOutcome(
            delegation_id=contract.delegation_id,
            target_agent=contract.target_agent,
            status=DelegationStatus.TIMEOUT_PARTIAL,
            duration_sec=time.perf_counter() - started,
            reason=f"timeout after {contract.budget_wall_clock_sec}s",
            completed_at=datetime.now(UTC),
        )
    except Exception as exc:  # boundary - convert to outcome
        return DelegationOutcome(
            delegation_id=contract.delegation_id,
            target_agent=contract.target_agent,
            status=DelegationStatus.ERROR,
            duration_sec=time.perf_counter() - started,
            reason=_short_error(exc),
            completed_at=datetime.now(UTC),
        )

    return DelegationOutcome(
        delegation_id=contract.delegation_id,
        target_agent=contract.target_agent,
        status=DelegationStatus.OK,
        duration_sec=time.perf_counter() - started,
        reason=None,
        completed_at=datetime.now(UTC),
    )


def _short_error(exc: BaseException) -> str:
    """Bound the error string to fit DelegationOutcome.reason cap."""
    message = f"{type(exc).__name__}: {exc}"
    return message[:512]


__all__ = ["DelegationInvoker", "dispatch_parallel"]
