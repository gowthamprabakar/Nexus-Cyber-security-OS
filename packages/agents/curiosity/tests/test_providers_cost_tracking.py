"""curiosity v0.2 Task 11 — LLM cost telemetry per scan window (Q3/H4)."""

from __future__ import annotations

from charter.llm import LLMResponse, TokenUsage
from curiosity.providers.cost_tracking import (
    ACTION_LLM_CALL_COMPLETED,
    CuriosityCostTracker,
)


def _resp(inp: int, out: int) -> LLMResponse:
    return LLMResponse(
        text="t",
        stop_reason="stop",
        usage=TokenUsage(input_tokens=inp, output_tokens=out),
        model_pin="pin",
        provider_id="deepseek",
    )


def test_record_accumulates() -> None:
    t = CuriosityCostTracker()
    t.record(_resp(10, 20), provider_used="deepseek")
    t.record(_resp(5, 5), provider_used="anthropic")
    assert t.llm_call_count == 2
    assert t.estimated_tokens == 40
    assert t.provider_used == "anthropic"
    assert t.llm_skipped is False


def test_skip_is_the_common_path() -> None:
    # H4/WI-X15: no gaps -> LLM skipped; zero calls recorded explicitly.
    t = CuriosityCostTracker()
    t.record_skip()
    section = t.to_report_section()
    assert section["llm_skipped"] is True
    assert section["llm_call_count"] == 0
    assert section["estimated_tokens"] == 0
    assert section["provider_used"] is None


def test_record_clears_skip() -> None:
    t = CuriosityCostTracker()
    t.record_skip()
    t.record(_resp(1, 1), provider_used="deepseek")
    assert t.llm_skipped is False


def test_report_section_shape() -> None:
    t = CuriosityCostTracker()
    t.record(_resp(3, 4), provider_used="deepseek")
    assert t.to_report_section() == {
        "llm_call_count": 1,
        "estimated_tokens": 7,
        "input_tokens": 3,
        "output_tokens": 4,
        "provider_used": "deepseek",
        "llm_skipped": False,
    }


def test_audit_action_vocab() -> None:
    assert ACTION_LLM_CALL_COMPLETED == "curiosity.llm.call_completed"
