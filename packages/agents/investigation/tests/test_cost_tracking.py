"""investigation v0.2 Task 6 — LLM cost telemetry tests (Q3/WI-I17)."""

from __future__ import annotations

import json
from pathlib import Path

from charter.audit import AuditLog
from charter.llm import LLMResponse, TokenUsage
from investigation.providers.cost_tracking import (
    ACTION_LLM_CALL_COMPLETED,
    InvestigationCostTracker,
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
    t = InvestigationCostTracker()
    t.record(_resp(100, 50), provider_used="deepseek")
    t.record(_resp(20, 10), provider_used="deepseek")
    assert t.llm_call_count == 2 and t.estimated_tokens == 180


def test_provider_used_tracked() -> None:
    t = InvestigationCostTracker()
    t.record(_resp(1, 1), provider_used="deepseek")
    t.record(_resp(1, 1), provider_used="anthropic")
    assert t.provider_used == "anthropic"


def test_to_report_section() -> None:
    t = InvestigationCostTracker()
    t.record(_resp(100, 50), provider_used="deepseek")
    s = t.to_report_section()
    assert s["llm_call_count"] == 1 and s["estimated_tokens"] == 150
    assert s["provider_used"] == "deepseek"


def test_action_constant() -> None:
    assert ACTION_LLM_CALL_COMPLETED == "investigation.llm.call_completed"


def test_emit_appends_audit_entry(tmp_path: Path) -> None:
    log = AuditLog(tmp_path / "audit.jsonl", agent="investigation", run_id="run-1")
    t = InvestigationCostTracker()
    t.record(_resp(100, 50), provider_used="deepseek")
    emit_llm_cost(log, tracker=t)
    entries = [json.loads(line) for line in log.path.read_text().splitlines() if line.strip()]
    assert entries[0]["action"] == ACTION_LLM_CALL_COMPLETED
    assert entries[0]["payload"]["estimated_tokens"] == 150


def test_empty_tracker() -> None:
    s = InvestigationCostTracker().to_report_section()
    assert s["llm_call_count"] == 0 and s["provider_used"] is None
