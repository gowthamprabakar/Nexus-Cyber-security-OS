"""Tests — `supervisor.dispatch` (Task 5).

13 tests covering the Stage 3 DISPATCH orchestrator:

1.  Empty contracts -> empty outcomes (no work).
2.  Single contract, clean invoker -> OK outcome.
3.  Two contracts, clean invoker -> 2x OK; output preserves input
    order.
4.  Invoker that raises -> ERROR outcome; reason carries the
    exception class name + message.
5.  Invoker that exceeds budget -> TIMEOUT_PARTIAL outcome; reason
    mentions the budget value.
6.  Mixed batch (one OK, one ERROR, one TIMEOUT_PARTIAL) -> batch
    completes; statuses preserved per-contract.
7.  ``concurrency=1`` serialises invocations (subsequent invoker
    calls wait until the prior one completes).
8.  ``concurrency=5`` (default cap per Q3) allows 5 concurrent
    invocations; a 6th waits behind the semaphore.
9.  ``concurrency < 1`` -> ValueError.
10. ``duration_sec`` populated on every outcome (non-negative).
11. ``completed_at`` populated on every outcome (recent UTC).
12. Per-delegation crash does NOT poison the batch (other
    delegations still complete).
13. Tasks run truly in parallel under cap (5 concurrent invokers
    finish in ~max-latency time, not Σ-latency).
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

import pytest
from supervisor.dispatch import DelegationInvoker, dispatch_parallel
from supervisor.schemas import (
    DelegationContract,
    DelegationStatus,
)

_NOW = datetime(2026, 5, 21, 12, 0, tzinfo=UTC)


def _contract(
    delegation_id: str,
    target_agent: str = "agent_x",
    budget_wall_clock_sec: float = 5.0,
) -> DelegationContract:
    return DelegationContract(
        delegation_id=delegation_id,
        customer_id="acme",
        target_agent=target_agent,
        task_id=f"t_{delegation_id}",
        budget_wall_clock_sec=budget_wall_clock_sec,
        budget_max_tool_calls=10,
        created_at=_NOW,
    )


# ---------------------------------------------------------------------------
# Invoker factories
# ---------------------------------------------------------------------------


def _ok_invoker(delay_sec: float = 0.0) -> DelegationInvoker:
    async def _invoke(contract: DelegationContract) -> None:
        del contract
        if delay_sec > 0.0:
            await asyncio.sleep(delay_sec)

    return _invoke


def _raising_invoker(exc: BaseException) -> DelegationInvoker:
    async def _invoke(contract: DelegationContract) -> None:
        del contract
        raise exc

    return _invoke


def _slow_invoker(delay_sec: float) -> DelegationInvoker:
    async def _invoke(contract: DelegationContract) -> None:
        del contract
        await asyncio.sleep(delay_sec)

    return _invoke


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_empty_contracts_empty_outcomes() -> None:
    outcomes = await dispatch_parallel([], invoker=_ok_invoker())
    assert outcomes == []


@pytest.mark.asyncio
async def test_single_contract_ok() -> None:
    outcomes = await dispatch_parallel(
        [_contract("d1")],
        invoker=_ok_invoker(),
    )
    assert len(outcomes) == 1
    assert outcomes[0].status == DelegationStatus.OK
    assert outcomes[0].reason is None


@pytest.mark.asyncio
async def test_two_contracts_preserves_input_order() -> None:
    contracts = [_contract("d1"), _contract("d2"), _contract("d3")]
    outcomes = await dispatch_parallel(contracts, invoker=_ok_invoker())
    assert [o.delegation_id for o in outcomes] == ["d1", "d2", "d3"]


@pytest.mark.asyncio
async def test_raising_invoker_yields_error_outcome() -> None:
    outcomes = await dispatch_parallel(
        [_contract("d1")],
        invoker=_raising_invoker(RuntimeError("boom")),
    )
    assert outcomes[0].status == DelegationStatus.ERROR
    assert outcomes[0].reason is not None
    assert "RuntimeError" in outcomes[0].reason
    assert "boom" in outcomes[0].reason


@pytest.mark.asyncio
async def test_invoker_exceeding_budget_yields_timeout_partial() -> None:
    """Budget=0.05s vs delay=1s -> wait_for raises -> TIMEOUT_PARTIAL."""
    outcomes = await dispatch_parallel(
        [_contract("d1", budget_wall_clock_sec=0.05)],
        invoker=_slow_invoker(delay_sec=1.0),
    )
    assert outcomes[0].status == DelegationStatus.TIMEOUT_PARTIAL
    assert "timeout" in outcomes[0].reason.lower()  # type: ignore[union-attr]


@pytest.mark.asyncio
async def test_mixed_batch_each_status_preserved() -> None:
    """Three contracts; mixed invokers via dispatcher dict."""

    async def mixed_invoker(contract: DelegationContract) -> None:
        if contract.delegation_id == "d_ok":
            return
        if contract.delegation_id == "d_err":
            raise RuntimeError("synthetic")
        if contract.delegation_id == "d_slow":
            await asyncio.sleep(1.0)
        return

    contracts = [
        _contract("d_ok"),
        _contract("d_err"),
        _contract("d_slow", budget_wall_clock_sec=0.05),
    ]
    outcomes = await dispatch_parallel(contracts, invoker=mixed_invoker)
    by_id = {o.delegation_id: o for o in outcomes}
    assert by_id["d_ok"].status == DelegationStatus.OK
    assert by_id["d_err"].status == DelegationStatus.ERROR
    assert by_id["d_slow"].status == DelegationStatus.TIMEOUT_PARTIAL


@pytest.mark.asyncio
async def test_concurrency_1_serialises() -> None:
    """With concurrency=1 + 2 invokers each taking 0.1s, total
    wall-clock should be ~0.2s, not ~0.1s."""
    contracts = [_contract("d1"), _contract("d2")]
    invoker = _slow_invoker(delay_sec=0.1)
    started = asyncio.get_event_loop().time()
    outcomes = await dispatch_parallel(contracts, invoker=invoker, concurrency=1)
    elapsed = asyncio.get_event_loop().time() - started
    assert all(o.status == DelegationStatus.OK for o in outcomes)
    # Sequential ~= 2 * 0.1s ; parallel would be ~0.1s. Bound loose.
    assert elapsed >= 0.15, f"concurrency=1 should serialise; elapsed={elapsed:.3f}s"


@pytest.mark.asyncio
async def test_concurrency_5_allows_parallel() -> None:
    """With concurrency=5 + 5 invokers each taking 0.1s, total
    wall-clock should be ~0.1s, not ~0.5s."""
    contracts = [_contract(f"d{i}") for i in range(5)]
    invoker = _slow_invoker(delay_sec=0.1)
    started = asyncio.get_event_loop().time()
    outcomes = await dispatch_parallel(contracts, invoker=invoker, concurrency=5)
    elapsed = asyncio.get_event_loop().time() - started
    assert all(o.status == DelegationStatus.OK for o in outcomes)
    # All 5 in parallel should finish in ~0.1s; cap at 0.4s loose.
    assert elapsed < 0.4, f"concurrency=5 should parallelise; elapsed={elapsed:.3f}s"


@pytest.mark.asyncio
async def test_concurrency_below_one_raises() -> None:
    with pytest.raises(ValueError, match=r"concurrency must be >= 1"):
        await dispatch_parallel([], invoker=_ok_invoker(), concurrency=0)


@pytest.mark.asyncio
async def test_duration_sec_populated_non_negative() -> None:
    outcomes = await dispatch_parallel(
        [_contract("d1")],
        invoker=_ok_invoker(delay_sec=0.05),
    )
    assert outcomes[0].duration_sec >= 0.0


@pytest.mark.asyncio
async def test_completed_at_recent_utc() -> None:
    before = datetime.now(UTC)
    outcomes = await dispatch_parallel(
        [_contract("d1")],
        invoker=_ok_invoker(),
    )
    after = datetime.now(UTC)
    assert before <= outcomes[0].completed_at <= after + timedelta(seconds=1)


@pytest.mark.asyncio
async def test_per_delegation_crash_does_not_poison_batch() -> None:
    """A raising invoker on one contract must not block other
    contracts from completing."""

    async def mixed(contract: DelegationContract) -> None:
        if contract.delegation_id == "d_crash":
            raise ValueError("intentional")
        return

    contracts = [
        _contract("d1"),
        _contract("d_crash"),
        _contract("d3"),
    ]
    outcomes = await dispatch_parallel(contracts, invoker=mixed)
    by_id = {o.delegation_id: o.status for o in outcomes}
    assert by_id["d1"] == DelegationStatus.OK
    assert by_id["d_crash"] == DelegationStatus.ERROR
    assert by_id["d3"] == DelegationStatus.OK


@pytest.mark.asyncio
async def test_sixth_dispatch_waits_behind_semaphore() -> None:
    """Concurrency=5 + 6 invokers each taking 0.1s -> total should be
    ~0.2s (5 in first wave + 1 in second wave), not ~0.1s."""
    contracts = [_contract(f"d{i}") for i in range(6)]
    invoker = _slow_invoker(delay_sec=0.1)
    started = asyncio.get_event_loop().time()
    outcomes = await dispatch_parallel(contracts, invoker=invoker, concurrency=5)
    elapsed = asyncio.get_event_loop().time() - started
    assert all(o.status == DelegationStatus.OK for o in outcomes)
    assert 0.15 < elapsed < 0.5, (
        f"6 dispatches under concurrency=5 should take ~0.2s; elapsed={elapsed:.3f}s"
    )
