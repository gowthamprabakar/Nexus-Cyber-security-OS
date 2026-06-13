"""remediation v0.2 Task 14 — batch-level safety primitives (Q5/WI-A12)."""

from __future__ import annotations

import pytest
from remediation.batch_safety import (
    BatchAbortError,
    artifacts_requiring_rollback,
    assert_all_dry_run_passed,
)


def test_all_dry_run_passed_ok() -> None:
    assert_all_dry_run_passed({"corr-a": True, "corr-b": True})


def test_empty_batch_ok() -> None:
    assert_all_dry_run_passed({})


def test_one_dry_run_failure_aborts_batch() -> None:
    with pytest.raises(BatchAbortError, match="all-or-nothing"):
        assert_all_dry_run_passed({"corr-a": True, "corr-b": False})


def test_full_success_no_rollback() -> None:
    assert artifacts_requiring_rollback({"corr-a": True, "corr-b": True}) == ()


def test_partial_failure_rolls_back_succeeded() -> None:
    # corr-a executed, corr-b failed -> roll back corr-a (all-or-nothing).
    assert artifacts_requiring_rollback({"corr-a": True, "corr-b": False}) == ("corr-a",)


def test_total_failure_nothing_succeeded() -> None:
    assert artifacts_requiring_rollback({"corr-a": False, "corr-b": False}) == ()
