"""Tests for the markdown renderers — suite, comparison, gate."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest
from eval_framework.compare import diff_results
from eval_framework.gate import Gate, GateResult, apply_gate
from eval_framework.render_md import (
    render_comparison_md,
    render_gate_md,
    render_suite_md,
)
from eval_framework.results import EvalResult, SuiteResult
from eval_framework.trace import EvalTrace, LLMCallRecord


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


def _result(
    case_id: str,
    *,
    passed: bool = True,
    failure_reason: str | None = None,
    actuals: dict[str, Any] | None = None,
    duration_sec: float = 0.1,
    llm_calls: list[LLMCallRecord] | None = None,
) -> EvalResult:
    return EvalResult(
        case_id=case_id,
        runner="cloud_posture",
        passed=passed,
        failure_reason=failure_reason or (None if passed else "synthetic"),
        actuals=actuals or {},
        duration_sec=duration_sec,
        trace=EvalTrace(llm_calls=llm_calls or []),
    )


def _suite(
    cases: list[EvalResult],
    *,
    suite_id: str = "01J7TESTSUITE",
    provider_id: str | None = None,
    model_pin: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> SuiteResult:
    now = datetime.now(UTC)
    return SuiteResult(
        suite_id=suite_id,
        runner="cloud_posture",
        started_at=now,
        completed_at=now,
        cases=cases,
        provider_id=provider_id,
        model_pin=model_pin,
        metadata=metadata or {},
    )


# ---------------------------- Suite renderer -----------------------------


def test_render_suite_empty() -> None:
    md = render_suite_md(_suite([]))
    assert "0/0" in md or "no cases" in md.lower()
    # Renders without crashing on empty.
    assert md.startswith("#")


def test_render_suite_all_pass_lists_pass_ratio_first() -> None:
    cases = [_result(f"00{i}") for i in range(10)]
    md = render_suite_md(_suite(cases))
    # Pass ratio appears in the first 200 chars (early in the doc).
    head = md[:300]
    assert "10/10" in head
    assert "100" in head  # 100% somewhere up top


def test_render_suite_includes_metadata() -> None:
    md = render_suite_md(
        _suite(
            [_result("001")],
            suite_id="01J7BRANCH",
            provider_id="anthropic",
            model_pin="claude-sonnet-4-test",
            metadata={"branch": "main", "commit": "abc123"},
        )
    )
    assert "01J7BRANCH" in md
    assert "anthropic" in md
    assert "claude-sonnet-4-test" in md
    assert "main" in md
    assert "abc123" in md


def test_render_suite_per_case_table_has_each_case() -> None:
    cases = [
        _result("001", passed=True, duration_sec=0.5),
        _result("002", passed=False, failure_reason="boom"),
    ]
    md = render_suite_md(_suite(cases))
    assert "001" in md
    assert "002" in md
    assert "boom" in md  # failure reason surfaces


def test_render_suite_with_token_usage() -> None:
    cases = [_result("001", llm_calls=[_llm(100, 50)])]
    md = render_suite_md(_suite(cases))
    assert "150" in md  # total tokens for case


def test_render_suite_with_severity_actuals_section() -> None:
    """If runner emits by_severity, the renderer surfaces it."""
    cases = [
        _result(
            "001",
            actuals={"finding_count": 3, "by_severity": {"high": 2, "medium": 1}},
        )
    ]
    md = render_suite_md(_suite(cases))
    assert "high" in md.lower() or "severity" in md.lower()


# ---------------------------- Comparison renderer ------------------------


def test_render_comparison_regressions_lead_first_line() -> None:
    a = _suite([_result("001", passed=True), _result("002", passed=True)], suite_id="A")
    b = _suite([_result("001", passed=True), _result("002", passed=False)], suite_id="B")
    md = render_comparison_md(diff_results(a, b))

    head = md.split("\n\n", 2)[0] + "\n\n" + (md.split("\n\n", 2)[1] if "\n\n" in md else "")
    assert "1" in head and ("regress" in head.lower() or "newly_failing" in head)


def test_render_comparison_table_has_each_case_diff() -> None:
    a = _suite([_result("001"), _result("002")], suite_id="A")
    b = _suite([_result("001"), _result("002", passed=False)], suite_id="B")
    md = render_comparison_md(diff_results(a, b))

    assert "001" in md
    assert "002" in md
    assert "newly_failing" in md
    assert "unchanged_pass" in md


def test_render_comparison_clean_run_says_zero_regressions() -> None:
    a = _suite([_result("001")], suite_id="A")
    b = _suite([_result("001")], suite_id="B")
    md = render_comparison_md(diff_results(a, b))
    assert "0" in md and "regression" in md.lower()


def test_render_comparison_includes_provider_ids() -> None:
    a = _suite([_result("001")], suite_id="A", provider_id="anthropic")
    b = _suite([_result("001")], suite_id="B", provider_id="ollama")
    md = render_comparison_md(diff_results(a, b))
    assert "anthropic" in md
    assert "ollama" in md


def test_render_comparison_handles_dropped_and_added() -> None:
    a = _suite([_result("001"), _result("002")], suite_id="A")
    b = _suite([_result("001"), _result("003")], suite_id="B")
    md = render_comparison_md(diff_results(a, b))
    assert "dropped" in md
    assert "added" in md


# ---------------------------- Gate renderer ------------------------------


def test_render_gate_passing_says_passed() -> None:
    suite = _suite([_result("001")])
    result = apply_gate(suite, Gate())
    md = render_gate_md(result, suite)
    assert result.passed is True
    assert "passed" in md.lower() or "✅" in md


def test_render_gate_failures_each_appear() -> None:
    cases = [_result("001", passed=False)]
    suite = _suite(cases)
    result = apply_gate(suite, Gate(min_pass_rate=1.0))
    md = render_gate_md(result, suite)

    assert result.passed is False
    # Every failure string should be present.
    for failure in result.failures:
        assert failure in md


def test_render_gate_with_no_failures_still_renders() -> None:
    """An empty failures list shouldn't crash the renderer."""
    md = render_gate_md(GateResult(passed=True, failures=[]), _suite([]))
    assert md.startswith("#")


# ---------------------------- General constraints -------------------------


def test_renderers_produce_pure_strings() -> None:
    """Every renderer must return `str` so a caller can pipe to disk or stdout."""
    suite = _suite([_result("001")])
    assert isinstance(render_suite_md(suite), str)
    assert isinstance(
        render_comparison_md(diff_results(suite, suite)),
        str,
    )
    assert isinstance(render_gate_md(GateResult(passed=True, failures=[]), suite), str)


def test_renderer_does_not_crash_on_long_failure_reason() -> None:
    """A long, multiline failure reason should render without breaking the table."""
    cases = [_result("001", passed=False, failure_reason="x" * 500 + "\nstack\ntrace")]
    md = render_suite_md(_suite(cases))
    assert "001" in md


@pytest.mark.parametrize("metadata", [None, {}, {"k": "v"}])
def test_render_suite_handles_optional_metadata(metadata: dict[str, Any] | None) -> None:
    md = render_suite_md(_suite([_result("001")], metadata=metadata))
    assert "001" in md
