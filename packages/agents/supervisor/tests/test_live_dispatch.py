"""supervisor v0.2 Task 3 — live delegation execution tests (Q1)."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from supervisor.routing.live_dispatch import (
    LiveDispatchResult,
    execute_live,
    plan_live_delegations,
)
from supervisor.routing.live_registry import DispatchMode
from supervisor.schemas import DelegationContract


def _contract(target: str, *, task_id: str = "t-1") -> DelegationContract:
    return DelegationContract(
        delegation_id=f"d-{target}-{task_id}",
        customer_id="cust-1",
        target_agent=target,
        task_id=task_id,
        budget_wall_clock_sec=30.0,
        budget_max_tool_calls=100,
        created_at=datetime(2026, 6, 1, tzinfo=UTC),
    )


async def _ok_invoker(contract: DelegationContract) -> None:
    return None  # clean completion -> OK outcome


def test_plan_annotates_full_mode() -> None:
    [d] = plan_live_delegations([_contract("compliance")])
    assert d.dispatch_mode == DispatchMode.FULL


def test_plan_annotates_basic_mode() -> None:
    [d] = plan_live_delegations([_contract("synthesis")])
    assert d.dispatch_mode == DispatchMode.BASIC


def test_plan_unknown_target_raises() -> None:
    with pytest.raises(KeyError):
        plan_live_delegations([_contract("ghost")])


@pytest.mark.asyncio
async def test_execute_live_runs_via_invoker() -> None:
    delegations = plan_live_delegations([_contract("compliance"), _contract("audit")])
    result = await execute_live(delegations, invoker=_ok_invoker)
    assert isinstance(result, LiveDispatchResult)
    assert len(result.outcomes) == 2
    assert all(o.status.value == "ok" for o in result.outcomes)


@pytest.mark.asyncio
async def test_execute_live_tallies_modes() -> None:
    delegations = plan_live_delegations(
        [_contract("compliance"), _contract("audit"), _contract("synthesis")]
    )
    result = await execute_live(delegations, invoker=_ok_invoker)
    assert result.full_dispatched == 2 and result.basic_dispatched == 1


@pytest.mark.asyncio
async def test_execute_live_preserves_order() -> None:
    delegations = plan_live_delegations([_contract("audit"), _contract("compliance")])
    result = await execute_live(delegations, invoker=_ok_invoker)
    assert [o.target_agent for o in result.outcomes] == ["audit", "compliance"]


@pytest.mark.asyncio
async def test_execute_live_captures_error() -> None:
    async def _boom(contract: DelegationContract) -> None:
        raise RuntimeError("agent crashed")

    delegations = plan_live_delegations([_contract("compliance")])
    result = await execute_live(delegations, invoker=_boom)
    assert result.outcomes[0].status.value == "error"


@pytest.mark.asyncio
async def test_execute_live_empty() -> None:
    result = await execute_live([], invoker=_ok_invoker)
    assert result.outcomes == () and result.full_dispatched == 0
