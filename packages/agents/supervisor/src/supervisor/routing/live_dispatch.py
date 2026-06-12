"""Live delegation execution (supervisor v0.2 Task 3, Q1).

Migrates dispatch from scaffolded execution to **registry-validated live dispatch**: each
pre-declared ``DelegationContract`` is annotated with its registry dispatch mode (full for the
11 v0.2 agents, basic otherwise — Q1) and an unknown target is rejected, then the existing
``dispatch_parallel`` runs them through the injectable ``DelegationInvoker`` seam (production
wires the real agent runner; tests inject a fake).

Supervisor still **constructs** the contracts and never opens their bodies (deviation profile
holds, WI-O11); the signed-contract guard lands in Task 16 (WI-O9).
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from supervisor.dispatch import DelegationInvoker, dispatch_parallel
from supervisor.routing.live_registry import DispatchMode, dispatch_mode
from supervisor.schemas import DelegationContract, DelegationOutcome


@dataclass(frozen=True, slots=True)
class LiveDelegation:
    contract: DelegationContract
    dispatch_mode: DispatchMode


@dataclass(frozen=True, slots=True)
class LiveDispatchResult:
    outcomes: tuple[DelegationOutcome, ...]
    full_dispatched: int
    basic_dispatched: int


def plan_live_delegations(
    contracts: Sequence[DelegationContract],
) -> tuple[LiveDelegation, ...]:
    """Annotate each contract with its registry dispatch mode. An unknown target raises
    ``KeyError`` (a rule can never reach an agent outside the registry)."""
    return tuple(
        LiveDelegation(contract=c, dispatch_mode=dispatch_mode(c.target_agent)) for c in contracts
    )


async def execute_live(
    delegations: Sequence[LiveDelegation],
    *,
    invoker: DelegationInvoker,
    concurrency: int | None = None,
) -> LiveDispatchResult:
    """Execute planned delegations through the injectable invoker, preserving order, and tally
    how many ran at full vs basic dispatch fidelity. ``concurrency=None`` uses
    ``dispatch_parallel``'s own default."""
    contracts = [d.contract for d in delegations]
    if concurrency is None:
        outcomes = await dispatch_parallel(contracts, invoker=invoker)
    else:
        outcomes = await dispatch_parallel(contracts, invoker=invoker, concurrency=concurrency)
    full = sum(1 for d in delegations if d.dispatch_mode is DispatchMode.FULL)
    basic = sum(1 for d in delegations if d.dispatch_mode is DispatchMode.BASIC)
    return LiveDispatchResult(
        outcomes=tuple(outcomes), full_dispatched=full, basic_dispatched=basic
    )
