"""Tests for `render_json` — schema-stable JSON wire format for Meta-Harness."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

import pytest
from eval_framework.compare import diff_results
from eval_framework.render_json import (
    comparison_from_json,
    comparison_to_json,
    suite_from_json,
    suite_to_json,
)
from eval_framework.results import EvalResult, SuiteResult
from eval_framework.trace import EvalTrace, LLMCallRecord


def _llm() -> LLMCallRecord:
    return LLMCallRecord(
        provider_id="anthropic",
        model_pin="claude-sonnet-4-test",
        input_tokens=100,
        output_tokens=50,
        stop_reason="end_turn",
        started_at=datetime.now(UTC),
        duration_sec=0.5,
    )


def _result(
    case_id: str,
    *,
    passed: bool = True,
    actuals: dict[str, Any] | None = None,
    llm_calls: list[LLMCallRecord] | None = None,
) -> EvalResult:
    return EvalResult(
        case_id=case_id,
        runner="cloud_posture",
        passed=passed,
        failure_reason=None if passed else "synthetic",
        actuals=actuals or {},
        duration_sec=0.1,
        trace=EvalTrace(llm_calls=llm_calls or []),
    )


def _suite(
    cases: list[EvalResult],
    *,
    suite_id: str = "01J7XYZSTABLE",
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


# ---------------------------- Suite round-trip ---------------------------


def test_suite_round_trip_preserves_equality() -> None:
    original = _suite(
        [
            _result("001", actuals={"finding_count": 1}, llm_calls=[_llm()]),
            _result("002", passed=False),
        ],
        provider_id="anthropic",
        model_pin="claude-sonnet-4",
        metadata={"branch": "main"},
    )

    payload = suite_to_json(original)
    restored = suite_from_json(payload)

    assert restored == original


def test_suite_round_trip_via_bytes() -> None:
    original = _suite([_result("001")])
    restored = suite_from_json(suite_to_json(original).encode("utf-8"))
    assert restored == original


def test_suite_to_json_is_valid_json() -> None:
    payload = suite_to_json(_suite([_result("001")]))
    parsed = json.loads(payload)
    assert isinstance(parsed, dict)
    assert parsed["suite_id"] == "01J7XYZSTABLE"
    assert parsed["runner"] == "cloud_posture"
    assert isinstance(parsed["cases"], list)


def test_suite_to_json_indent_param() -> None:
    payload_pretty = suite_to_json(_suite([_result("001")]), indent=2)
    payload_compact = suite_to_json(_suite([_result("001")]), indent=None)
    assert "\n" in payload_pretty
    assert "\n" not in payload_compact


def test_suite_to_json_default_indent_is_two() -> None:
    payload = suite_to_json(_suite([_result("001")]))
    assert "\n  " in payload  # 2-space indent on nested keys


def test_suite_to_json_includes_utc_timestamps() -> None:
    payload = suite_to_json(_suite([_result("001")]))
    parsed = json.loads(payload)
    # ISO-8601 with timezone marker — pydantic emits "+00:00" or "Z".
    assert "+00:00" in parsed["started_at"] or "Z" in parsed["started_at"]


# ---------------------------- Comparison round-trip ----------------------


def test_comparison_round_trip_preserves_equality() -> None:
    a = _suite([_result("001")], suite_id="A", provider_id="anthropic")
    b = _suite([_result("001", passed=False)], suite_id="B", provider_id="ollama")
    original = diff_results(a, b)

    restored = comparison_from_json(comparison_to_json(original))
    assert restored == original


def test_comparison_to_json_includes_summary_block() -> None:
    a = _suite([_result("001")], suite_id="A")
    b = _suite([_result("001", passed=False)], suite_id="B")
    payload = comparison_to_json(diff_results(a, b))
    parsed = json.loads(payload)
    assert parsed["summary"]["regressions_count"] == 1
    assert parsed["baseline_suite_id"] == "A"
    assert parsed["candidate_suite_id"] == "B"


def test_comparison_round_trip_via_bytes() -> None:
    a = _suite([_result("001")], suite_id="A")
    b = _suite([_result("001")], suite_id="B")
    original = diff_results(a, b)

    restored = comparison_from_json(comparison_to_json(original).encode("utf-8"))
    assert restored == original


# ---------------------------- Failure modes ------------------------------


def test_suite_from_json_rejects_invalid_payload() -> None:
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        suite_from_json('{"not": "a suite"}')


def test_comparison_from_json_rejects_invalid_payload() -> None:
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        comparison_from_json('{"not": "a report"}')


# ---------------------------- Schema stability ---------------------------


def test_suite_json_top_level_keys_match_model() -> None:
    """The top-level JSON keys are the SuiteResult field names — stable contract."""
    payload = suite_to_json(_suite([_result("001")]))
    parsed = json.loads(payload)
    expected_keys = {
        "suite_id",
        "runner",
        "started_at",
        "completed_at",
        "cases",
        "provider_id",
        "model_pin",
        "metadata",
    }
    assert expected_keys.issubset(parsed.keys())


def test_comparison_json_top_level_keys_match_model() -> None:
    a = _suite([_result("001")], suite_id="A")
    b = _suite([_result("001")], suite_id="B")
    payload = comparison_to_json(diff_results(a, b))
    parsed = json.loads(payload)
    expected_keys = {
        "baseline_suite_id",
        "candidate_suite_id",
        "baseline_provider_id",
        "candidate_provider_id",
        "case_diffs",
        "summary",
    }
    assert expected_keys.issubset(parsed.keys())
