"""remediation v0.2 Task 2 — assert_default_recommend tests (WI-A8/H1)."""

from __future__ import annotations

import pytest
from remediation.invariants.default_recommend import (
    DefaultRecommendViolationError,
    assert_default_recommend,
)
from remediation.schemas import RemediationMode


def test_recommend_always_ok() -> None:
    assert_default_recommend(
        RemediationMode.RECOMMEND, enable_execute_flag=False, auth_mode_authorized=False
    )


def test_execute_with_both_layers_ok() -> None:
    assert_default_recommend(
        RemediationMode.EXECUTE, enable_execute_flag=True, auth_mode_authorized=True
    )


def test_execute_without_cli_flag_raises() -> None:
    with pytest.raises(DefaultRecommendViolationError, match="--enable-execute"):
        assert_default_recommend(
            RemediationMode.EXECUTE, enable_execute_flag=False, auth_mode_authorized=True
        )


def test_execute_without_auth_field_raises() -> None:
    with pytest.raises(DefaultRecommendViolationError, match="mode_execute_authorized"):
        assert_default_recommend(
            RemediationMode.EXECUTE, enable_execute_flag=True, auth_mode_authorized=False
        )


def test_execute_with_neither_raises() -> None:
    with pytest.raises(DefaultRecommendViolationError):
        assert_default_recommend(
            RemediationMode.EXECUTE, enable_execute_flag=False, auth_mode_authorized=False
        )


def test_dry_run_not_blocked_here() -> None:
    # dry-run is gated by authz.enforce_mode (non-mutating); this guard only fences execute.
    assert_default_recommend(
        RemediationMode.DRY_RUN, enable_execute_flag=False, auth_mode_authorized=False
    )
