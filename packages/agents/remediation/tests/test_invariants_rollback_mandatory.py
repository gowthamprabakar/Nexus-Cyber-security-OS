"""remediation v0.2 Task 5 — assert_rollback_on_failed_validation tests (WI-A11/H4)."""

from __future__ import annotations

import pytest
from remediation.invariants.rollback_mandatory import (
    RollbackSkippedError,
    assert_rollback_on_failed_validation,
)


def test_required_and_executed_ok() -> None:
    assert_rollback_on_failed_validation(requires_rollback=True, rollback_executed=True)


def test_not_required_ok() -> None:
    assert_rollback_on_failed_validation(requires_rollback=False, rollback_executed=False)


def test_not_required_but_executed_ok() -> None:
    # over-rolling-back is not a violation (validation passed; a rollback still ran).
    assert_rollback_on_failed_validation(requires_rollback=False, rollback_executed=True)


def test_required_but_skipped_raises() -> None:
    with pytest.raises(RollbackSkippedError, match="rollback is"):
        assert_rollback_on_failed_validation(requires_rollback=True, rollback_executed=False)
