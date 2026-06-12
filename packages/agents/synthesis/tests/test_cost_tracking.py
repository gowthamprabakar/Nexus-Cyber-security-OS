"""synthesis v0.2 Task 10 — LLM call cost tracking tests (Q5/WI-Y11)."""

from __future__ import annotations

import json
from pathlib import Path

from charter.audit import AuditLog
from charter.llm import LLMResponse, TokenUsage
from synthesis.providers.cost_tracking import (
    ACTION_LLM_CALL_COMPLETED,
    LLMCostTracker,
    emit_llm_cost,
)


def _resp(inp: int, out: int) -> LLMResponse:
    return LLMResponse(
        text="x",
        stop_reason="end_turn",
        usage=TokenUsage(input_tokens=inp, output_tokens=out),
        model_pin="m",
    )


def test_record_accumulates() -> None:
    t = LLMCostTracker()
    t.record(_resp(100, 50), provider_used="deepseek")
    t.record(_resp(20, 10), provider_used="deepseek")
    assert t.call_count == 2 and t.input_tokens == 120 and t.output_tokens == 60


def test_estimated_tokens() -> None:
    t = LLMCostTracker()
    t.record(_resp(100, 50), provider_used="deepseek")
    assert t.estimated_tokens == 150


def test_provider_used_tracked() -> None:
    t = LLMCostTracker()
    t.record(_resp(1, 1), provider_used="deepseek")
    t.record(_resp(1, 1), provider_used="anthropic")  # fell back on the 2nd call
    assert t.provider_used == "anthropic"


def test_to_audit_payload() -> None:
    t = LLMCostTracker()
    t.record(_resp(100, 50), provider_used="deepseek")
    p = t.to_audit_payload()
    assert p["llm_call_count"] == 1
    assert p["estimated_tokens"] == 150 and p["provider_used"] == "deepseek"


def test_action_constant() -> None:
    assert ACTION_LLM_CALL_COMPLETED == "synthesis.llm.call_completed"


def test_emit_appends_audit_entry(tmp_path: Path) -> None:
    log = AuditLog(tmp_path / "audit.jsonl", agent="synthesis", run_id="run-1")
    t = LLMCostTracker()
    t.record(_resp(100, 50), provider_used="deepseek")
    emit_llm_cost(log, tracker=t)
    entries = [json.loads(line) for line in log.path.read_text().splitlines() if line.strip()]
    assert entries[0]["action"] == ACTION_LLM_CALL_COMPLETED
    assert entries[0]["payload"]["estimated_tokens"] == 150


def test_empty_tracker_payload() -> None:
    p = LLMCostTracker().to_audit_payload()
    assert p["llm_call_count"] == 0 and p["provider_used"] is None
