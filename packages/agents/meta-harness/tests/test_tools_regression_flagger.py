"""Tests — `meta_harness.tools.regression_flagger` (Task 7).

10 tests covering:

1.  Empty deltas -> empty flags.
2.  Improvement (positive delta) -> not flagged.
3.  Below-threshold drop (-3%) -> not flagged.
4.  At-threshold drop (-5.0%) -> flagged (<= boundary).
5.  Above-threshold drop (-10%) -> flagged.
6.  First-run delta never flagged even if delta_pct is < -threshold
    (it can't be, but the filter must short-circuit before checking).
7.  Non-comparable (current_pass_rate=None) never flagged.
8.  Multi-agent batch: only regressors surface; order preserved.
9.  Zero-regressions case (everyone improved or held steady).
10. Threshold customization: threshold_pct=2.0 flags a -3% drop;
    threshold_pct <= 0 raises ValueError.
"""

from __future__ import annotations

import pytest
from meta_harness.schemas import ScorecardDelta
from meta_harness.tools.regression_flagger import (
    REGRESSION_THRESHOLD_PCT,
    flag_regressions,
)


def _delta(
    agent_id: str,
    *,
    prev: float | None = 0.9,
    curr: float | None = 0.9,
    delta_pct: float = 0.0,
    is_first_run: bool = False,
) -> ScorecardDelta:
    return ScorecardDelta(
        agent_id=agent_id,
        previous_pass_rate=prev,
        current_pass_rate=curr,
        delta_pct=delta_pct,
        is_first_run=is_first_run,
    )


def test_empty_deltas_empty_flags() -> None:
    assert flag_regressions([]) == ()


def test_improvement_not_flagged() -> None:
    d = _delta("x", prev=0.6, curr=0.9, delta_pct=30.0)
    assert flag_regressions([d]) == ()


def test_below_threshold_drop_not_flagged() -> None:
    d = _delta("x", prev=0.9, curr=0.87, delta_pct=-3.0)
    assert flag_regressions([d]) == ()


def test_at_threshold_drop_flagged() -> None:
    d = _delta("x", prev=0.9, curr=0.85, delta_pct=-5.0)
    flags = flag_regressions([d])
    assert len(flags) == 1
    assert flags[0].agent_id == "x"
    assert flags[0].delta_pct == -5.0


def test_above_threshold_drop_flagged() -> None:
    d = _delta("x", prev=0.9, curr=0.8, delta_pct=-10.0)
    flags = flag_regressions([d])
    assert len(flags) == 1
    assert flags[0].delta_pct == -10.0


def test_first_run_never_flagged() -> None:
    # In practice first_run forces delta_pct=0.0 by schema invariant,
    # but the filter short-circuits before that — exercise the gate.
    d = _delta("x", prev=None, curr=0.9, delta_pct=0.0, is_first_run=True)
    assert flag_regressions([d]) == ()


def test_non_comparable_never_flagged() -> None:
    d = _delta("x", prev=0.9, curr=None, delta_pct=0.0)
    assert flag_regressions([d]) == ()


def test_multi_agent_only_regressors_surface_with_preserved_order() -> None:
    deltas = [
        _delta("steady", prev=0.9, curr=0.9, delta_pct=0.0),
        _delta("regressor_a", prev=0.9, curr=0.8, delta_pct=-10.0),
        _delta("improver", prev=0.7, curr=0.9, delta_pct=20.0),
        _delta("regressor_b", prev=0.85, curr=0.6, delta_pct=-25.0),
    ]
    flags = flag_regressions(deltas)
    assert [f.agent_id for f in flags] == ["regressor_a", "regressor_b"]


def test_zero_regressions_case() -> None:
    deltas = [
        _delta("a", prev=0.6, curr=0.9, delta_pct=30.0),
        _delta("b", prev=0.9, curr=0.9, delta_pct=0.0),
    ]
    assert flag_regressions(deltas) == ()


def test_threshold_customization_and_validation() -> None:
    d = _delta("x", prev=0.9, curr=0.87, delta_pct=-3.0)
    # -3.0 is below the default 5.0 threshold but crosses 2.0.
    assert flag_regressions([d], threshold_pct=2.0)[0].delta_pct == -3.0
    assert flag_regressions([d], threshold_pct=REGRESSION_THRESHOLD_PCT) == ()
    with pytest.raises(ValueError, match="must be > 0"):
        flag_regressions([], threshold_pct=0.0)
