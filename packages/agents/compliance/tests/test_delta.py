"""compliance v0.2 Task 13 — delta detection tests."""

from __future__ import annotations

from compliance.continuous.delta import (
    compute_control_delta,
    compute_delta,
)


def test_newly_failing() -> None:
    d = compute_delta({"a"}, {"a", "b"})
    assert d.newly_failing == ("b",) and d.resolved == () and d.still_failing == ("a",)


def test_resolved() -> None:
    d = compute_delta({"a", "b"}, {"a"})
    assert d.resolved == ("b",) and d.newly_failing == ()


def test_no_changes() -> None:
    d = compute_delta({"a"}, {"a"})
    assert d.has_changes is False and d.still_failing == ("a",)


def test_has_changes() -> None:
    assert compute_delta(set(), {"x"}).has_changes is True


def test_sorted_output() -> None:
    d = compute_delta(set(), {"c", "a", "b"})
    assert d.newly_failing == ("a", "b", "c")


def test_control_regressed() -> None:
    delta = compute_control_delta({"5.2": "pass"}, {"5.2": "fail"})
    assert delta.regressed == ("5.2",) and delta.remediated == ()


def test_control_remediated() -> None:
    delta = compute_control_delta({"5.2": "fail"}, {"5.2": "pass"})
    assert delta.remediated == ("5.2",) and delta.regressed == ()


def test_control_not_evaluated_to_fail_is_regression() -> None:
    # was unknown, now failing -> counts as a regression worth surfacing.
    delta = compute_control_delta({"5.2": "not_evaluated"}, {"5.2": "fail"})
    assert delta.regressed == ("5.2",)


def test_control_new_control_failing() -> None:
    delta = compute_control_delta({}, {"6.1": "fail"})
    assert delta.regressed == ("6.1",) and delta.has_changes is True
