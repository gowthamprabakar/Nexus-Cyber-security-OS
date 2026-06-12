"""investigation v0.2 Task 17 — assert_worker_bounded tests (WI-I11)."""

from __future__ import annotations

import pytest
from investigation.orchestrator_bounds import (
    WorkerBoundsViolationError,
    assert_worker_bounded,
)


def test_at_cap_ok() -> None:
    assert_worker_bounded(depth=3, parallel=5)  # no raise


def test_under_cap_ok() -> None:
    assert_worker_bounded(depth=1, parallel=2)


def test_zero_ok() -> None:
    assert_worker_bounded(depth=0, parallel=0)


def test_depth_over_cap_raises() -> None:
    with pytest.raises(WorkerBoundsViolationError, match="depth 4 exceeds"):
        assert_worker_bounded(depth=4, parallel=2)


def test_parallel_over_cap_raises() -> None:
    with pytest.raises(WorkerBoundsViolationError, match="Parallel workers 6 exceed"):
        assert_worker_bounded(depth=2, parallel=6)


def test_depth_checked_first() -> None:
    # both over -> depth surfaces first.
    with pytest.raises(WorkerBoundsViolationError, match="depth"):
        assert_worker_bounded(depth=9, parallel=9)


def test_message_mentions_h5() -> None:
    with pytest.raises(WorkerBoundsViolationError, match="H5 cap"):
        assert_worker_bounded(depth=10, parallel=1)
