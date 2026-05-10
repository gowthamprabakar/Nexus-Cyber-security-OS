"""Tests for `build_trace_from_audit_log` — parses charter audit.jsonl into EvalTrace."""

from __future__ import annotations

from pathlib import Path

import pytest
from charter.audit import AuditLog
from eval_framework.trace import build_trace_from_audit_log


def _seed_log(path: Path, agent: str = "test_agent", run_id: str = "run-1") -> AuditLog:
    return AuditLog(path=path, agent=agent, run_id=run_id)


# ---------------------------- Empty / missing ----------------------------


def test_missing_path_returns_invalid_trace(tmp_path: Path) -> None:
    trace = build_trace_from_audit_log(tmp_path / "does-not-exist.jsonl")
    assert trace.audit_chain_valid is False
    assert trace.audit_log_path == str(tmp_path / "does-not-exist.jsonl")
    assert trace.llm_calls == []
    assert trace.tool_calls == []
    assert trace.output_writes == []


def test_empty_file_is_valid_but_carries_no_records(tmp_path: Path) -> None:
    p = tmp_path / "audit.jsonl"
    p.write_text("")
    trace = build_trace_from_audit_log(p)
    assert trace.audit_chain_valid is True
    assert trace.llm_calls == []
    assert trace.tool_calls == []
    assert trace.output_writes == []


# ---------------------------- Tool / output records ----------------------


def test_tool_call_and_output_written_become_records(tmp_path: Path) -> None:
    p = tmp_path / "audit.jsonl"
    log = _seed_log(p)
    log.append("invocation_started", {"task": "scan"})
    log.append("tool_call", {"tool": "prowler_scan", "version": "5.0.0", "kwargs_keys": []})
    log.append("tool_call", {"tool": "aws_iam_list_users", "version": "1.0.0", "kwargs_keys": []})
    log.append("output_written", {"name": "findings.json", "bytes": 4096})
    log.append("output_written", {"name": "summary.md", "bytes": 512})
    log.append("invocation_completed", {})

    trace = build_trace_from_audit_log(p)

    assert trace.audit_chain_valid is True
    assert [tc.tool for tc in trace.tool_calls] == ["prowler_scan", "aws_iam_list_users"]
    assert trace.tool_calls[0].version == "5.0.0"
    assert [ow.name for ow in trace.output_writes] == ["findings.json", "summary.md"]
    assert trace.output_writes[0].bytes_written == 4096
    assert trace.audit_log_path == str(p)


def test_tool_call_default_duration_is_zero(tmp_path: Path) -> None:
    """Charter doesn't yet emit per-call duration; trace records 0.0 placeholder."""
    p = tmp_path / "audit.jsonl"
    log = _seed_log(p)
    log.append("invocation_started", {"task": "x"})
    log.append("tool_call", {"tool": "t", "version": "1.0.0", "kwargs_keys": []})
    log.append("invocation_completed", {})

    trace = build_trace_from_audit_log(p)
    assert trace.tool_calls[0].duration_sec == 0.0


# ---------------------------- LLM-call pairing ---------------------------


def test_paired_llm_call_produces_record(tmp_path: Path) -> None:
    p = tmp_path / "audit.jsonl"
    log = _seed_log(p)
    log.append("invocation_started", {"task": "x"})
    log.append(
        "llm_call_started",
        {
            "provider_id": "anthropic",
            "model_pin": "claude-sonnet-4-test",
            "max_tokens": 1024,
            "temperature": 0.0,
            "tools": [],
        },
    )
    log.append(
        "llm_call_completed",
        {
            "provider_id": "anthropic",
            "model_pin": "claude-sonnet-4-test",
            "input_tokens": 200,
            "output_tokens": 50,
            "stop_reason": "end_turn",
            "tool_calls": [],
        },
    )
    log.append("invocation_completed", {})

    trace = build_trace_from_audit_log(p)

    assert len(trace.llm_calls) == 1
    rec = trace.llm_calls[0]
    assert rec.provider_id == "anthropic"
    assert rec.model_pin == "claude-sonnet-4-test"
    assert rec.input_tokens == 200
    assert rec.output_tokens == 50
    assert rec.stop_reason == "end_turn"
    assert rec.duration_sec >= 0.0


def test_unpaired_started_without_completed_yields_no_record(tmp_path: Path) -> None:
    """A `started` without a matching `completed` (e.g., crash) is dropped."""
    p = tmp_path / "audit.jsonl"
    log = _seed_log(p)
    log.append("invocation_started", {"task": "x"})
    log.append(
        "llm_call_started",
        {
            "provider_id": "p",
            "model_pin": "m",
            "max_tokens": 1,
            "temperature": 0.0,
            "tools": [],
        },
    )
    # No `completed` — simulate crash.

    trace = build_trace_from_audit_log(p)
    assert trace.llm_calls == []


def test_llm_call_failed_drops_unpaired_start(tmp_path: Path) -> None:
    p = tmp_path / "audit.jsonl"
    log = _seed_log(p)
    log.append("invocation_started", {"task": "x"})
    log.append(
        "llm_call_started",
        {"provider_id": "p", "model_pin": "m", "max_tokens": 1, "temperature": 0.0, "tools": []},
    )
    log.append(
        "llm_call_failed",
        {"provider_id": "p", "model_pin": "m", "error_type": "TimeoutError", "error": "boom"},
    )
    log.append("invocation_completed", {})

    trace = build_trace_from_audit_log(p)
    assert trace.llm_calls == []


def test_multiple_llm_calls_pair_in_order(tmp_path: Path) -> None:
    p = tmp_path / "audit.jsonl"
    log = _seed_log(p)
    log.append("invocation_started", {"task": "x"})
    for i in range(3):
        log.append(
            "llm_call_started",
            {
                "provider_id": "p",
                "model_pin": f"m{i}",
                "max_tokens": 10,
                "temperature": 0.0,
                "tools": [],
            },
        )
        log.append(
            "llm_call_completed",
            {
                "provider_id": "p",
                "model_pin": f"m{i}",
                "input_tokens": i * 10,
                "output_tokens": i,
                "stop_reason": "end_turn",
                "tool_calls": [],
            },
        )
    log.append("invocation_completed", {})

    trace = build_trace_from_audit_log(p)
    assert [c.model_pin for c in trace.llm_calls] == ["m0", "m1", "m2"]
    assert [c.input_tokens for c in trace.llm_calls] == [0, 10, 20]


# ---------------------------- Chain verification -------------------------


def test_tampered_audit_log_marks_chain_invalid(tmp_path: Path) -> None:
    p = tmp_path / "audit.jsonl"
    log = _seed_log(p)
    log.append("invocation_started", {"task": "x"})
    log.append("tool_call", {"tool": "t", "version": "1.0.0", "kwargs_keys": []})
    log.append("invocation_completed", {})

    # Tamper: mutate one line so the recomputed hash no longer matches.
    lines = p.read_text(encoding="utf-8").splitlines()
    tampered = lines[1].replace('"tool":"t"', '"tool":"OTHER"')
    p.write_text("\n".join([lines[0], tampered, lines[2]]) + "\n", encoding="utf-8")

    trace = build_trace_from_audit_log(p)
    assert trace.audit_chain_valid is False


def test_malformed_line_marks_chain_invalid_but_does_not_crash(tmp_path: Path) -> None:
    p = tmp_path / "audit.jsonl"
    log = _seed_log(p)
    log.append("invocation_started", {"task": "x"})
    with p.open("a", encoding="utf-8") as f:
        f.write("not-json\n")
    log.append("invocation_completed", {})

    # Should not raise, even though one line cannot be parsed.
    trace = build_trace_from_audit_log(p)
    assert trace.audit_chain_valid is False
    # The well-formed lines still produce no spurious tool/output records.
    assert trace.tool_calls == []
    assert trace.output_writes == []


def test_blank_lines_are_skipped(tmp_path: Path) -> None:
    p = tmp_path / "audit.jsonl"
    log = _seed_log(p)
    log.append("invocation_started", {"task": "x"})
    log.append("tool_call", {"tool": "t", "version": "1.0.0", "kwargs_keys": []})
    log.append("invocation_completed", {})

    # Inject blank lines around the existing chain. Blank lines are
    # ignored by both the parser and the verifier.
    raw = p.read_text(encoding="utf-8")
    p.write_text("\n\n" + raw + "\n\n", encoding="utf-8")

    trace = build_trace_from_audit_log(p)
    assert trace.audit_chain_valid is True
    assert len(trace.tool_calls) == 1


# ---------------------------- run_suite integration ---------------------


@pytest.mark.asyncio
async def test_run_suite_populates_trace_from_audit_log(tmp_path: Path) -> None:
    """End-to-end: run_suite calls build_trace_from_audit_log when a path is returned."""
    from eval_framework.cases import EvalCase
    from eval_framework.runner import FakeRunner
    from eval_framework.suite import run_suite

    audit = tmp_path / "audit.jsonl"
    log = _seed_log(audit)
    log.append("invocation_started", {"task": "x"})
    log.append("tool_call", {"tool": "prowler_scan", "version": "5.0.0", "kwargs_keys": []})
    log.append("invocation_completed", {})

    runner = FakeRunner()
    runner.queue("001", passed=True, audit_log_path=audit)

    result = await run_suite(
        [EvalCase(case_id="001", description="d")],
        runner,
        workspace_root=tmp_path / "ws",
    )

    trace = result.cases[0].trace
    assert trace.audit_chain_valid is True
    assert [tc.tool for tc in trace.tool_calls] == ["prowler_scan"]
