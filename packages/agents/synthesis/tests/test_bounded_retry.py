"""synthesis v0.2 Task 16 — bounded-retry invariant tests (WI-Y10/H5)."""

from __future__ import annotations

import pytest
from synthesis.retry.bounded import (
    MAX_ATTEMPTS,
    BoundedRetryViolationError,
    assert_bounded_retry,
)


def test_max_attempts_is_two() -> None:
    assert MAX_ATTEMPTS == 2


def test_initial_attempt_ok() -> None:
    assert_bounded_retry(1)  # initial attempt


def test_one_retry_ok() -> None:
    assert_bounded_retry(2)  # initial + 1 retry


def test_third_attempt_rejected() -> None:
    with pytest.raises(BoundedRetryViolationError, match="exceeds the H5 bound"):
        assert_bounded_retry(3)


def test_large_attempt_rejected() -> None:
    with pytest.raises(BoundedRetryViolationError):
        assert_bounded_retry(99)


def test_error_message_explains_bound() -> None:
    with pytest.raises(BoundedRetryViolationError, match="degraded draft"):
        assert_bounded_retry(4)


def test_zero_attempt_ok() -> None:
    # A defensive lower edge: 0 attempts (before the run) is within bound.
    assert_bounded_retry(0)
