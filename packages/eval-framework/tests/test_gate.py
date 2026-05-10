"""Tests for `Gate` + `apply_gate` — configurable thresholds with explainable failures."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from eval_framework.gate import Gate, GateResult, apply_gate
from eval_framework.results import EvalResult, SuiteResult
from eval_framework.trace import EvalTrace, LLMCallRecord


def _result(
    case_id: str,
    *,
    passed: bool = True,
    duration_sec: float = 0.1,
    llm_calls: list[LLMCallRecord] | None = None,
) -> EvalResult:
    return EvalResult(
        case_id=case_id,
        runner="cloud_posture",
        passed=passed,
        failure_reason=None if passed else "synthetic failure",
        actuals={},
        duration_sec=duration_sec,
        trace=EvalTrace(llm_calls=llm_calls or []),
    )


def _suite(cases: list[EvalResult], suite_id: str = "S") -> SuiteResult:
    now = datetime.now(UTC)
    return SuiteResult(
        suite_id=suite_id,
        runner="cloud_posture",
        started_at=now,
        completed_at=now,
        cases=cases,
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


# ---------------------------- Pass-rate gate ------------------------------


def test_pass_rate_gate_passes_at_threshold() -> None:
    suite = _suite([_result(f"{i}", passed=True) for i in range(10)])  # 10/10
    result = apply_gate(suite, Gate(min_pass_rate=1.0))
    assert isinstance(result, GateResult)
    assert result.passed is True
    assert result.failures == []


def test_pass_rate_gate_fails_below_threshold_with_explanation() -> None:
    cases = [_result(f"{i}", passed=True) for i in range(9)] + [_result("9", passed=False)]
    suite = _suite(cases)  # 9/10
    result = apply_gate(suite, Gate(min_pass_rate=1.0))
    assert result.passed is False
    assert any("pass_rate" in f for f in result.failures)
    # The failure should name the actual numbers, not just "failed".
    assert any("0.9" in f or "90" in f for f in result.failures)


def test_pass_rate_gate_passes_when_above_relaxed_threshold() -> None:
    cases = [_result(f"{i}", passed=True) for i in range(9)] + [_result("9", passed=False)]
    suite = _suite(cases)
    result = apply_gate(suite, Gate(min_pass_rate=0.8))
    assert result.passed is True


# ---------------------------- Regression gate -----------------------------


def test_no_regressions_gate_with_baseline() -> None:
    baseline = _suite([_result("001", passed=True)], suite_id="A")
    candidate = _suite([_result("001", passed=False)], suite_id="B")

    result = apply_gate(
        candidate,
        Gate(min_pass_rate=0.0, no_regressions_vs_baseline=True),
        baseline=baseline,
    )
    assert result.passed is False
    assert any("regression" in f.lower() for f in result.failures)


def test_no_regressions_gate_without_baseline_is_silently_skipped() -> None:
    """If no baseline supplied, the regression check is a no-op."""
    suite = _suite([_result("001", passed=False)])
    result = apply_gate(suite, Gate(min_pass_rate=0.0, no_regressions_vs_baseline=True))
    assert result.passed is True


def test_no_regressions_gate_passes_when_baseline_matches() -> None:
    baseline = _suite([_result("001", passed=True)], suite_id="A")
    candidate = _suite([_result("001", passed=True)], suite_id="B")
    result = apply_gate(
        candidate,
        Gate(min_pass_rate=1.0, no_regressions_vs_baseline=True),
        baseline=baseline,
    )
    assert result.passed is True


# ---------------------------- Token-budget gate ---------------------------


def test_max_token_delta_pct_fails_when_candidate_blows_budget() -> None:
    baseline = _suite(
        [_result("001", llm_calls=[_llm(100, 0)])],
        suite_id="A",
    )  # 100 tokens
    candidate = _suite(
        [_result("001", llm_calls=[_llm(150, 0)])],
        suite_id="B",
    )  # 150 → +50%

    result = apply_gate(
        candidate,
        Gate(min_pass_rate=0.0, max_token_delta_pct=0.20),  # 20% allowed
        baseline=baseline,
    )
    assert result.passed is False
    assert any("token" in f.lower() for f in result.failures)


def test_max_token_delta_pct_passes_when_within_budget() -> None:
    baseline = _suite([_result("001", llm_calls=[_llm(100, 0)])], suite_id="A")
    candidate = _suite([_result("001", llm_calls=[_llm(110, 0)])], suite_id="B")

    result = apply_gate(
        candidate,
        Gate(min_pass_rate=0.0, max_token_delta_pct=0.20),
        baseline=baseline,
    )
    assert result.passed is True


def test_max_token_delta_pct_no_op_without_baseline() -> None:
    suite = _suite([_result("001", llm_calls=[_llm(1000, 0)])])
    result = apply_gate(suite, Gate(min_pass_rate=0.0, max_token_delta_pct=0.05))
    assert result.passed is True


# ---------------------------- p95 duration gate ---------------------------


def test_max_p95_duration_sec_fails_on_slow_case() -> None:
    """4 fast cases + 1 slow → the slow case lands above the 95th percentile."""
    cases = [_result(f"{i}", duration_sec=0.5) for i in range(4)] + [
        _result("slow", duration_sec=10.0)
    ]
    suite = _suite(cases)
    result = apply_gate(suite, Gate(min_pass_rate=0.0, max_p95_duration_sec=5.0))
    assert result.passed is False
    assert any("duration" in f.lower() or "p95" in f.lower() for f in result.failures)


def test_max_p95_duration_sec_passes_when_all_cases_fast() -> None:
    cases = [_result(f"{i}", duration_sec=0.1) for i in range(100)]
    suite = _suite(cases)
    result = apply_gate(suite, Gate(min_pass_rate=0.0, max_p95_duration_sec=5.0))
    assert result.passed is True


def test_max_p95_duration_sec_skipped_for_empty_suite() -> None:
    result = apply_gate(_suite([]), Gate(min_pass_rate=0.0, max_p95_duration_sec=1.0))
    assert result.passed is True


# ---------------------------- Aggregation: multiple failures --------------


def test_multiple_failures_are_all_reported() -> None:
    cases = [_result(f"{i}", passed=False, duration_sec=10.0) for i in range(2)]
    suite = _suite(cases)
    result = apply_gate(
        suite,
        Gate(min_pass_rate=1.0, max_p95_duration_sec=5.0),
    )
    assert result.passed is False
    assert len(result.failures) >= 2  # pass-rate AND p95


# ---------------------------- Frozen models ------------------------------


def test_models_are_frozen() -> None:
    g = Gate()
    with pytest.raises((TypeError, ValueError)):
        g.min_pass_rate = 0.5  # type: ignore[misc]

    r = GateResult(passed=True, failures=[])
    with pytest.raises((TypeError, ValueError)):
        r.passed = False  # type: ignore[misc]


def test_default_gate_is_strict() -> None:
    """Default gate construction = 100% pass-rate, no regressions, no token/p95 ceilings."""
    g = Gate()
    assert g.min_pass_rate == 1.0
    assert g.no_regressions_vs_baseline is True
    assert g.max_token_delta_pct is None
    assert g.max_p95_duration_sec is None
