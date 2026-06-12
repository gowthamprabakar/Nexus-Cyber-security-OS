"""supervisor v0.2 Task 8 — bounded retry policy tests (Q3/H4)."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from supervisor.failure.classifier import FailureClass
from supervisor.failure.retry import (
    MAX_TOTAL_ATTEMPTS,
    RetryDecision,
    decide_retry,
    run_with_retry,
)
from supervisor.schemas import DelegationContract, DelegationOutcome, DelegationStatus


def _contract() -> DelegationContract:
    return DelegationContract(
        delegation_id="d-1",
        customer_id="c-1",
        target_agent="compliance",
        task_id="t-1",
        budget_wall_clock_sec=30.0,
        budget_max_tool_calls=100,
        created_at=datetime(2026, 6, 1, tzinfo=UTC),
    )


def _outcome(status: DelegationStatus, *, reason: str | None = None) -> DelegationOutcome:
    if status is not DelegationStatus.OK and reason is None:
        reason = "x"
    return DelegationOutcome(
        delegation_id="d-1",
        target_agent="compliance",
        status=status,
        duration_sec=1.0,
        reason=reason,
        completed_at=datetime(2026, 6, 1, tzinfo=UTC),
    )


def _scripted(*outcomes: DelegationOutcome):
    seq = iter(outcomes)

    async def _attempt(contract: DelegationContract) -> DelegationOutcome:
        return next(seq)

    return _attempt


def test_max_total_attempts_is_two() -> None:
    assert MAX_TOTAL_ATTEMPTS == 2


def test_decide_retry_transient_under_cap() -> None:
    assert decide_retry(FailureClass.TRANSIENT, attempts_made=1) == RetryDecision.RETRY


def test_decide_retry_transient_at_cap_escalates() -> None:
    assert decide_retry(FailureClass.TRANSIENT, attempts_made=2) == RetryDecision.ESCALATE


def test_decide_retry_permanent_escalates() -> None:
    assert decide_retry(FailureClass.PERMANENT, attempts_made=1) == RetryDecision.ESCALATE


def test_decide_retry_timeout_escalates() -> None:
    assert decide_retry(FailureClass.TIMEOUT, attempts_made=1) == RetryDecision.ESCALATE


@pytest.mark.asyncio
async def test_ok_first_try_no_retry() -> None:
    result = await run_with_retry(_contract(), attempt=_scripted(_outcome(DelegationStatus.OK)))
    assert result.attempts == 1 and result.retried is False
    assert result.outcome.status == DelegationStatus.OK


@pytest.mark.asyncio
async def test_transient_then_ok_one_retry() -> None:
    result = await run_with_retry(
        _contract(),
        attempt=_scripted(
            _outcome(DelegationStatus.ERROR, reason="503"), _outcome(DelegationStatus.OK)
        ),
    )
    assert result.attempts == 2 and result.retried is True
    assert result.outcome.status == DelegationStatus.OK


@pytest.mark.asyncio
async def test_transient_twice_escalates_at_cap() -> None:
    result = await run_with_retry(
        _contract(),
        attempt=_scripted(
            _outcome(DelegationStatus.ERROR, reason="503"),
            _outcome(DelegationStatus.ERROR, reason="503"),
        ),
    )
    assert result.attempts == MAX_TOTAL_ATTEMPTS and result.retried is True
    assert result.outcome.status == DelegationStatus.ERROR


@pytest.mark.asyncio
async def test_permanent_no_retry() -> None:
    result = await run_with_retry(
        _contract(), attempt=_scripted(_outcome(DelegationStatus.ERROR, reason="401 unauthorized"))
    )
    assert result.attempts == 1 and result.retried is False


@pytest.mark.asyncio
async def test_timeout_no_retry() -> None:
    result = await run_with_retry(
        _contract(), attempt=_scripted(_outcome(DelegationStatus.TIMEOUT_PARTIAL, reason="budget"))
    )
    assert result.attempts == 1 and result.retried is False
