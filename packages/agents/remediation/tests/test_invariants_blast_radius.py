"""remediation v0.2 Task 6 — assert_blast_radius_capped tests (WI-A12/H5)."""

from __future__ import annotations

import pytest
from remediation.invariants.blast_radius import (
    HARD_CEILING,
    BlastRadiusViolationError,
    assert_blast_radius_capped,
    effective_cap,
)


def test_hard_ceiling_is_50() -> None:
    assert HARD_CEILING == 50


def test_within_cap_ok() -> None:
    assert_blast_radius_capped(3, 5)


def test_at_cap_ok() -> None:
    assert_blast_radius_capped(5, 5)


def test_over_per_run_cap_raises() -> None:
    with pytest.raises(BlastRadiusViolationError, match="blast-radius cap"):
        assert_blast_radius_capped(6, 5)


def test_effective_cap_is_min() -> None:
    assert effective_cap(5) == 5
    assert effective_cap(999) == 50


def test_hard_ceiling_enforced_even_with_huge_config() -> None:
    # per-run config above 50 cannot lift the ceiling.
    assert_blast_radius_capped(50, 999)  # at ceiling ok
    with pytest.raises(BlastRadiusViolationError):
        assert_blast_radius_capped(51, 999)


def test_zero_actions_ok() -> None:
    assert_blast_radius_capped(0, 5)
