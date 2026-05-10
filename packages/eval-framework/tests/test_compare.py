"""Tests for `diff_results` — case-id-keyed join over two SuiteResults."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest
from eval_framework.compare import (
    CaseDiff,
    ComparisonReport,
    ComparisonSummary,
    diff_results,
)
from eval_framework.results import EvalResult, SuiteResult
from eval_framework.trace import EvalTrace, LLMCallRecord


def _result(
    case_id: str,
    *,
    passed: bool = True,
    actuals: dict[str, Any] | None = None,
    duration_sec: float = 0.1,
    llm_calls: list[LLMCallRecord] | None = None,
    runner: str = "cloud_posture",
) -> EvalResult:
    return EvalResult(
        case_id=case_id,
        runner=runner,
        passed=passed,
        failure_reason=None if passed else "synthetic failure",
        actuals=actuals or {},
        duration_sec=duration_sec,
        trace=EvalTrace(llm_calls=llm_calls or []),
    )


def _suite(
    cases: list[EvalResult],
    *,
    suite_id: str = "01J7BASELINE",
    provider_id: str | None = None,
    runner: str = "cloud_posture",
) -> SuiteResult:
    now = datetime.now(UTC)
    return SuiteResult(
        suite_id=suite_id,
        runner=runner,
        started_at=now,
        completed_at=now,
        cases=cases,
        provider_id=provider_id,
    )


def _llm(input_tokens: int, output_tokens: int) -> LLMCallRecord:
    return LLMCallRecord(
        provider_id="p",
        model_pin="m",
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        stop_reason="end_turn",
        started_at=datetime.now(UTC),
        duration_sec=0.0,
    )


# ---------------------------- Identity case ------------------------------


def test_identical_suites_have_zero_regressions() -> None:
    a = _suite([_result("001"), _result("002")], suite_id="A")
    b = _suite([_result("001"), _result("002")], suite_id="B")

    report = diff_results(a, b)

    assert isinstance(report, ComparisonReport)
    assert report.summary.regressions_count == 0
    assert report.summary.improvements_count == 0
    assert report.summary.pass_rate_delta == 0.0
    assert {d.status for d in report.case_diffs} == {"unchanged_pass"}
    assert all(not d.actuals_changed for d in report.case_diffs)


# ---------------------------- Regressions / improvements ------------------


def test_baseline_pass_candidate_fail_is_a_regression() -> None:
    a = _suite([_result("001", passed=True)])
    b = _suite([_result("001", passed=False)])

    report = diff_results(a, b)
    assert report.case_diffs[0].status == "newly_failing"
    assert report.summary.regressions_count == 1


def test_baseline_fail_candidate_pass_is_an_improvement() -> None:
    a = _suite([_result("001", passed=False)])
    b = _suite([_result("001", passed=True)])

    report = diff_results(a, b)
    assert report.case_diffs[0].status == "newly_passing"
    assert report.summary.improvements_count == 1
    assert report.summary.regressions_count == 0


def test_pass_rate_delta_reflects_aggregate_change() -> None:
    a = _suite([_result(f"{i:03}", passed=True) for i in range(10)])  # 10/10
    b_cases = [_result(f"{i:03}", passed=True) for i in range(9)] + [_result("009", passed=False)]
    b = _suite(b_cases)  # 9/10

    report = diff_results(a, b)
    assert pytest.approx(report.summary.pass_rate_delta, rel=1e-9) == -0.1
    assert report.summary.regressions_count == 1


# ---------------------------- actuals_changed flag ------------------------


def test_actuals_changed_set_when_dict_differs() -> None:
    a = _suite([_result("001", actuals={"finding_count": 1})])
    b = _suite([_result("001", actuals={"finding_count": 2})])

    report = diff_results(a, b)
    assert report.case_diffs[0].actuals_changed is True


def test_actuals_unchanged_when_dict_equals() -> None:
    a = _suite([_result("001", actuals={"finding_count": 1, "by_severity": {"high": 1}})])
    b = _suite([_result("001", actuals={"finding_count": 1, "by_severity": {"high": 1}})])

    report = diff_results(a, b)
    assert report.case_diffs[0].actuals_changed is False


# ---------------------------- token / duration deltas ---------------------


def test_token_delta_subtracts_baseline_from_candidate() -> None:
    a = _suite([_result("001", llm_calls=[_llm(100, 50)])])  # 150
    b = _suite([_result("001", llm_calls=[_llm(120, 60)])])  # 180

    report = diff_results(a, b)
    assert report.case_diffs[0].token_delta == 30


def test_token_delta_is_none_when_neither_side_has_llm_calls() -> None:
    a = _suite([_result("001")])
    b = _suite([_result("001")])
    report = diff_results(a, b)
    assert report.case_diffs[0].token_delta is None


def test_duration_delta_subtracts_baseline_from_candidate() -> None:
    a = _suite([_result("001", duration_sec=1.0)])
    b = _suite([_result("001", duration_sec=1.5)])

    report = diff_results(a, b)
    assert pytest.approx(report.case_diffs[0].duration_delta_sec, rel=1e-9) == 0.5


# ---------------------------- Set-symmetric handling ----------------------


def test_baseline_only_case_appears_with_dropped_marker() -> None:
    """A case present only in the baseline is reported (caller sees coverage gap)."""
    a = _suite([_result("001"), _result("002")])
    b = _suite([_result("001")])

    report = diff_results(a, b)
    statuses = {d.case_id: d.status for d in report.case_diffs}
    assert statuses["002"] == "dropped"


def test_candidate_only_case_appears_with_added_marker() -> None:
    a = _suite([_result("001")])
    b = _suite([_result("001"), _result("003")])

    report = diff_results(a, b)
    statuses = {d.case_id: d.status for d in report.case_diffs}
    assert statuses["003"] == "added"


# ---------------------------- Provider metadata ---------------------------


def test_provider_ids_propagated_to_report() -> None:
    a = _suite([_result("001")], provider_id="anthropic", suite_id="A")
    b = _suite([_result("001")], provider_id="ollama", suite_id="B")

    report = diff_results(a, b)
    assert report.baseline_suite_id == "A"
    assert report.candidate_suite_id == "B"
    assert report.baseline_provider_id == "anthropic"
    assert report.candidate_provider_id == "ollama"


# ---------------------------- ComparisonSummary frozen --------------------


def test_models_are_frozen() -> None:
    diff = CaseDiff(
        case_id="001",
        baseline_passed=True,
        candidate_passed=True,
        status="unchanged_pass",
        actuals_changed=False,
        token_delta=None,
        duration_delta_sec=0.0,
    )
    with pytest.raises((TypeError, ValueError)):
        diff.case_id = "002"  # type: ignore[misc]

    summary = ComparisonSummary(
        total_cases=1,
        regressions_count=0,
        improvements_count=0,
        pass_rate_delta=0.0,
    )
    with pytest.raises((TypeError, ValueError)):
        summary.regressions_count = 1  # type: ignore[misc]
