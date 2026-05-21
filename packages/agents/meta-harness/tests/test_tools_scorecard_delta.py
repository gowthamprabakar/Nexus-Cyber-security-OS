"""Tests — `meta_harness.tools.scorecard_delta` (Task 6).

10 tests covering:

1.  First run (prev=None) -> is_first_run=True, delta_pct=0.0.
2.  Identical pass_rate -> delta_pct=0.0, not first-run.
3.  Improvement (60% -> 90%) -> +30.0 pct.
4.  Regression (90% -> 60%) -> -30.0 pct.
5.  Current failed (pass_rate=None) -> delta_pct=0.0, both rates
    surfaced.
6.  Previous failed (pass_rate=None) -> delta_pct=0.0.
7.  Mismatched agent_ids -> ValueError.
8.  ``compute_batch_deltas`` happy path matches by agent_id and
    preserves current-order.
9.  ``compute_batch_deltas`` missing-prev yields first-run delta.
10. ``compute_batch_deltas`` ignores previous agents not in current.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from meta_harness.schemas import Scorecard
from meta_harness.tools.scorecard_delta import compute_batch_deltas, compute_delta

_NOW = datetime(2026, 5, 21, 12, 0, tzinfo=UTC)


def _scorecard(
    agent_id: str,
    *,
    pass_rate: float | None = 0.9,
    error: str | None = None,
    total: int = 10,
    passed: int = 9,
    failed: int = 1,
) -> Scorecard:
    return Scorecard(
        customer_id="acme",
        run_id="r1",
        agent_id=agent_id,
        total_cases=total,
        passed=passed,
        failed=failed,
        pass_rate=pass_rate,
        error=error,
        evaluated_at=_NOW,
    )


def _failed_scorecard(agent_id: str) -> Scorecard:
    return _scorecard(
        agent_id,
        pass_rate=None,
        error="boom",
        total=0,
        passed=0,
        failed=0,
    )


def test_first_run_is_flagged_with_zero_delta() -> None:
    current = _scorecard("cloud_posture", pass_rate=0.9)
    delta = compute_delta(current, None)
    assert delta.is_first_run is True
    assert delta.previous_pass_rate is None
    assert delta.current_pass_rate == 0.9
    assert delta.delta_pct == 0.0


def test_same_pass_rate_zero_delta() -> None:
    cur = _scorecard("x", pass_rate=0.9)
    prev = _scorecard("x", pass_rate=0.9)
    delta = compute_delta(cur, prev)
    assert delta.delta_pct == 0.0
    assert delta.is_first_run is False
    assert delta.is_comparable is True


def test_improvement_positive_delta() -> None:
    cur = _scorecard("x", pass_rate=0.9)
    prev = _scorecard("x", pass_rate=0.6)
    delta = compute_delta(cur, prev)
    assert delta.delta_pct == pytest.approx(30.0)


def test_regression_negative_delta() -> None:
    cur = _scorecard("x", pass_rate=0.6)
    prev = _scorecard("x", pass_rate=0.9)
    delta = compute_delta(cur, prev)
    assert delta.delta_pct == pytest.approx(-30.0)


def test_current_failed_yields_zero_delta() -> None:
    cur = _failed_scorecard("x")
    prev = _scorecard("x", pass_rate=0.9)
    delta = compute_delta(cur, prev)
    assert delta.delta_pct == 0.0
    assert delta.current_pass_rate is None
    assert delta.previous_pass_rate == 0.9
    assert delta.is_comparable is False


def test_previous_failed_yields_zero_delta() -> None:
    cur = _scorecard("x", pass_rate=0.9)
    prev = _failed_scorecard("x")
    delta = compute_delta(cur, prev)
    assert delta.delta_pct == 0.0
    assert delta.previous_pass_rate is None
    assert delta.is_comparable is False


def test_mismatched_agent_id_raises() -> None:
    cur = _scorecard("a", pass_rate=0.9)
    prev = _scorecard("b", pass_rate=0.9)
    with pytest.raises(ValueError, match="agent_id mismatch"):
        compute_delta(cur, prev)


def test_compute_batch_deltas_matches_by_agent_id_and_preserves_order() -> None:
    cur_list = [
        _scorecard("a", pass_rate=0.8),
        _scorecard("b", pass_rate=0.7),
        _scorecard("c", pass_rate=0.9),
    ]
    prev_list = [
        _scorecard("b", pass_rate=0.6),
        _scorecard("a", pass_rate=0.5),
        # No "c" in prev -> first-run for c.
    ]
    deltas = compute_batch_deltas(cur_list, prev_list)
    assert [d.agent_id for d in deltas] == ["a", "b", "c"]
    by_agent = {d.agent_id: d for d in deltas}
    assert by_agent["a"].delta_pct == pytest.approx(30.0)
    assert by_agent["b"].delta_pct == pytest.approx(10.0)
    assert by_agent["c"].is_first_run is True


def test_compute_batch_deltas_first_run_for_missing_prev() -> None:
    cur = [_scorecard("x", pass_rate=0.9)]
    deltas = compute_batch_deltas(cur, [])
    assert len(deltas) == 1
    assert deltas[0].is_first_run is True


def test_compute_batch_deltas_ignores_orphan_previous() -> None:
    cur = [_scorecard("x", pass_rate=0.9)]
    prev = [
        _scorecard("x", pass_rate=0.8),
        _scorecard("dropped_agent", pass_rate=0.5),
    ]
    deltas = compute_batch_deltas(cur, prev)
    assert {d.agent_id for d in deltas} == {"x"}
