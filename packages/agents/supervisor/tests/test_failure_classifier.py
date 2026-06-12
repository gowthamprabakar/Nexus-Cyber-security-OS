"""supervisor v0.2 Task 7 — failure classification tests (Q3)."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from supervisor.failure.classifier import (
    FailureClass,
    classify_failure,
    classify_outcome,
)
from supervisor.schemas import DelegationOutcome, DelegationStatus


def test_timeout_status_is_timeout() -> None:
    assert (
        classify_failure(status=DelegationStatus.TIMEOUT_PARTIAL, reason="budget")
        == FailureClass.TIMEOUT
    )


@pytest.mark.parametrize(
    "reason",
    [
        "503 Service Unavailable",
        "rate limit exceeded",
        "connection reset by peer",
        "please try again",
        "429 Too Many Requests",
    ],
)
def test_transient_markers(reason: str) -> None:
    assert classify_failure(status=DelegationStatus.ERROR, reason=reason) == FailureClass.TRANSIENT


@pytest.mark.parametrize(
    "reason",
    [
        "401 Unauthorized",
        "resource not found",
        "validation failed",
        "permission denied",
        "invalid argument",
    ],
)
def test_permanent_markers(reason: str) -> None:
    assert classify_failure(status=DelegationStatus.ERROR, reason=reason) == FailureClass.PERMANENT


def test_unknown_error_defaults_permanent() -> None:
    # Conservative: an unrecognized error escalates, never retried blindly (H4).
    assert (
        classify_failure(status=DelegationStatus.ERROR, reason="weird kaboom")
        == FailureClass.PERMANENT
    )


def test_none_reason_defaults_permanent() -> None:
    assert classify_failure(status=DelegationStatus.ERROR, reason=None) == FailureClass.PERMANENT


def test_permanent_wins_over_transient() -> None:
    # A 403 that also says "try again" must stay permanent (no retry).
    assert (
        classify_failure(status=DelegationStatus.ERROR, reason="403 forbidden, try again later")
        == FailureClass.PERMANENT
    )


def test_ok_raises() -> None:
    with pytest.raises(ValueError, match="successful"):
        classify_failure(status=DelegationStatus.OK, reason=None)


def test_classify_outcome() -> None:
    outcome = DelegationOutcome(
        delegation_id="d-1",
        target_agent="compliance",
        status=DelegationStatus.ERROR,
        duration_sec=1.0,
        reason="503 unavailable",
        completed_at=datetime(2026, 6, 1, tzinfo=UTC),
    )
    assert classify_outcome(outcome) == FailureClass.TRANSIENT
