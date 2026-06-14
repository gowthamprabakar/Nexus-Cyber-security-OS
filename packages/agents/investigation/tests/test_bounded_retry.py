"""investigation v0.2 Task 15 — bounded-retry invariant tests (WI-I9, inherited from D.13)."""

from __future__ import annotations

import pytest
from nexus_runtime.llm_invariants.bounded import (
    MAX_ATTEMPTS,
    BoundedRetryViolationError,
    assert_bounded_retry,
)


def test_max_attempts_is_two() -> None:
    assert MAX_ATTEMPTS == 2


def test_initial_and_one_retry_ok() -> None:
    assert_bounded_retry(1)
    assert_bounded_retry(2)


def test_third_attempt_rejected() -> None:
    with pytest.raises(BoundedRetryViolationError, match="bounded-retry cap"):
        assert_bounded_retry(3)


def test_large_rejected() -> None:
    with pytest.raises(BoundedRetryViolationError):
        assert_bounded_retry(50)


def test_zero_ok() -> None:
    assert_bounded_retry(0)


def test_message_mentions_deterministic() -> None:
    with pytest.raises(BoundedRetryViolationError, match="never retry beyond"):
        assert_bounded_retry(4)
