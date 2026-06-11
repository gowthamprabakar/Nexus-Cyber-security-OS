"""compliance v0.2 Task 8 — PASS+FAIL roll-up aggregation tests."""

from __future__ import annotations

from compliance.rollup import (
    FAIL,
    NOT_EVALUATED,
    PASS,
    classify_control,
    roll_up_framework,
)


def test_classify_pass() -> None:
    assert classify_control(["a"], evaluated={"a", "b"}, failing=set()) == PASS


def test_classify_fail() -> None:
    assert classify_control(["a"], evaluated={"a"}, failing={"a"}) == FAIL


def test_classify_not_evaluated_when_rule_missing() -> None:
    assert classify_control(["a", "b"], evaluated={"a"}, failing=set()) == NOT_EVALUATED


def test_classify_unwired_is_not_evaluated() -> None:
    assert classify_control([], evaluated={"a"}, failing=set()) == NOT_EVALUATED


def test_multi_emitter_any_failing_fails() -> None:
    # A control mapped to a kube-bench id + a runtime rule: one failing -> the control fails.
    assert (
        classify_control(
            ["5.2.2", "privileged-container"],
            evaluated={"5.2.2", "privileged-container"},
            failing={"privileged-container"},
        )
        == FAIL
    )


def test_rollup_counts() -> None:
    controls = [
        ("1", ["a"]),  # pass
        ("2", ["b"]),  # fail
        ("3", ["c", "d"]),  # not evaluated (d missing)
        ("4", []),  # not evaluated (unwired)
    ]
    rollup = roll_up_framework("cis_aws_v3", controls, evaluated={"a", "b", "c"}, failing={"b"})
    assert rollup.pass_count == 1 and rollup.fail_count == 1
    assert rollup.not_evaluated_count == 2 and rollup.total_controls == 4


def test_coverage_pct() -> None:
    rollup = roll_up_framework(
        "cis_aws_v3",
        [("1", ["a"]), ("2", ["b"]), ("3", ["c"]), ("4", ["d"])],
        evaluated={"a", "b"},
        failing={"b"},
    )
    # 2 of 4 determinable (1 pass + 1 fail) -> 50%.
    assert rollup.coverage_pct == 50.0


def test_coverage_pct_empty() -> None:
    assert roll_up_framework("f", [], evaluated=set(), failing=set()).coverage_pct == 0.0
