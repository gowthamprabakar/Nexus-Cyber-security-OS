"""Tests for the typed result + trace pydantic models."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from eval_framework.results import EvalResult, SuiteResult
from eval_framework.trace import (
    EvalTrace,
    LLMCallRecord,
    OutputWriteRecord,
    ToolCallRecord,
)
from pydantic import ValidationError

# ---------------------------- record-level types ---------------------------


def test_llm_call_record_round_trip() -> None:
    rec = LLMCallRecord(
        provider_id="anthropic",
        model_pin="claude-sonnet-4-5",
        input_tokens=42,
        output_tokens=7,
        stop_reason="end_turn",
        started_at=datetime(2026, 5, 10, 12, 0, tzinfo=UTC),
        duration_sec=1.5,
    )
    payload = rec.model_dump_json()
    rebuilt = LLMCallRecord.model_validate_json(payload)
    assert rebuilt == rec


def test_tool_call_record_round_trip() -> None:
    rec = ToolCallRecord(tool="prowler_scan", version="5.0.0", duration_sec=12.3)
    rebuilt = ToolCallRecord.model_validate_json(rec.model_dump_json())
    assert rebuilt == rec


def test_output_write_record_round_trip() -> None:
    rec = OutputWriteRecord(name="findings.json", bytes_written=4096)
    rebuilt = OutputWriteRecord.model_validate_json(rec.model_dump_json())
    assert rebuilt == rec


# ---------------------------- EvalTrace ------------------------------------


def test_eval_trace_with_empty_records_round_trips() -> None:
    trace = EvalTrace(audit_log_path=None)
    rebuilt = EvalTrace.model_validate_json(trace.model_dump_json())
    assert rebuilt == trace
    assert rebuilt.llm_calls == []
    assert rebuilt.tool_calls == []
    assert rebuilt.output_writes == []
    assert rebuilt.audit_chain_valid is None


def test_eval_trace_with_records_round_trips() -> None:
    trace = EvalTrace(
        audit_log_path="audit.jsonl",
        llm_calls=[
            LLMCallRecord(
                provider_id="ollama",
                model_pin="qwen3:4b",
                input_tokens=20,
                output_tokens=30,
                stop_reason="stop",
                started_at=datetime(2026, 5, 10, 12, 0, tzinfo=UTC),
                duration_sec=2.0,
            ),
        ],
        tool_calls=[ToolCallRecord(tool="prowler_scan", version="5.0.0", duration_sec=11.0)],
        output_writes=[OutputWriteRecord(name="findings.json", bytes_written=1024)],
        audit_chain_valid=True,
    )
    rebuilt = EvalTrace.model_validate_json(trace.model_dump_json())
    assert rebuilt == trace


def test_eval_trace_is_frozen() -> None:
    trace = EvalTrace(audit_log_path=None)
    with pytest.raises(ValidationError):
        trace.audit_chain_valid = True  # type: ignore[misc]


# ---------------------------- EvalResult -----------------------------------


def _trace() -> EvalTrace:
    return EvalTrace(audit_log_path=None, audit_chain_valid=True)


def test_eval_result_round_trip() -> None:
    result = EvalResult(
        case_id="001_x",
        runner="cloud_posture",
        passed=True,
        failure_reason=None,
        actuals={"finding_count": 0, "by_severity": {"high": 0}},
        duration_sec=0.5,
        trace=_trace(),
    )
    rebuilt = EvalResult.model_validate_json(result.model_dump_json())
    assert rebuilt == result


def test_eval_result_is_frozen() -> None:
    result = EvalResult(
        case_id="001_x",
        runner="r",
        passed=True,
        failure_reason=None,
        actuals={},
        duration_sec=0.0,
        trace=_trace(),
    )
    with pytest.raises(ValidationError):
        result.passed = False  # type: ignore[misc]


# ---------------------------- SuiteResult ----------------------------------


def _result(case_id: str, *, passed: bool) -> EvalResult:
    return EvalResult(
        case_id=case_id,
        runner="cloud_posture",
        passed=passed,
        failure_reason=None if passed else "expected 0, got 1",
        actuals={},
        duration_sec=0.1,
        trace=_trace(),
    )


def _suite(cases: list[EvalResult]) -> SuiteResult:
    started = datetime(2026, 5, 10, 12, 0, tzinfo=UTC)
    return SuiteResult(
        suite_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
        runner="cloud_posture",
        started_at=started,
        completed_at=started + timedelta(seconds=5),
        cases=cases,
        provider_id=None,
        model_pin=None,
        metadata={"branch": "main"},
    )


def test_suite_result_total_and_passed_and_pass_rate() -> None:
    suite = _suite(
        [
            _result("001", passed=True),
            _result("002", passed=True),
            _result("003", passed=False),
            _result("004", passed=True),
        ]
    )
    assert suite.total == 4
    assert suite.passed == 3
    assert suite.pass_rate == 0.75


def test_suite_result_pass_rate_when_empty() -> None:
    """An empty suite has a defined pass_rate (1.0 — vacuously true)."""
    suite = _suite([])
    assert suite.total == 0
    assert suite.passed == 0
    assert suite.pass_rate == 1.0


def test_suite_result_round_trip_preserves_cases() -> None:
    suite = _suite([_result("001", passed=True), _result("002", passed=False)])
    rebuilt = SuiteResult.model_validate_json(suite.model_dump_json())
    assert rebuilt == suite
    assert rebuilt.total == 2
    assert rebuilt.passed == 1


def test_suite_result_is_frozen() -> None:
    suite = _suite([])
    with pytest.raises(ValidationError):
        suite.runner = "other"  # type: ignore[misc]


def test_suite_result_records_provider_pin() -> None:
    """provider_id and model_pin survive round-trip — the parity gate needs them."""
    started = datetime(2026, 5, 10, 12, 0, tzinfo=UTC)
    suite = SuiteResult(
        suite_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
        runner="cloud_posture",
        started_at=started,
        completed_at=started + timedelta(seconds=5),
        cases=[],
        provider_id="ollama",
        model_pin="qwen3:4b",
        metadata={},
    )
    rebuilt = SuiteResult.model_validate_json(suite.model_dump_json())
    assert rebuilt.provider_id == "ollama"
    assert rebuilt.model_pin == "qwen3:4b"
