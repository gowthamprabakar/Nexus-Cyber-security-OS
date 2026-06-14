"""curiosity v0.2 Task 13 — assert_bounded_retry tests (WI-X10, inherited from D.13)."""

from __future__ import annotations

import pytest
from nexus_runtime.llm_invariants.bounded import (
    MAX_ATTEMPTS,
    BoundedRetryViolationError,
    assert_bounded_retry,
)


def test_max_attempts_is_two() -> None:
    assert MAX_ATTEMPTS == 2


def test_initial_call_ok() -> None:
    assert_bounded_retry(1)


def test_one_retry_ok() -> None:
    assert_bounded_retry(2)


def test_second_retry_raises() -> None:
    with pytest.raises(BoundedRetryViolationError, match="bounded-retry cap"):
        assert_bounded_retry(3)


def test_message_mentions_deterministic_draft() -> None:
    with pytest.raises(BoundedRetryViolationError, match="never retry beyond"):
        assert_bounded_retry(5)
