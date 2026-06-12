"""investigation v0.2 Task 10 — resilient synthesis support tests (Q3/H3)."""

from __future__ import annotations

import pytest
from charter.llm import FakeLLMProvider, LLMResponse, TokenUsage
from investigation.providers.cost_tracking import InvestigationCostTracker
from investigation.providers.synthesis_support import resilient_synthesize


def _resp(text: str) -> LLMResponse:
    return LLMResponse(
        text=text,
        stop_reason="end_turn",
        usage=TokenUsage(input_tokens=10, output_tokens=5),
        model_pin="m",
    )


class _Boom:
    provider_id = "deepseek"

    async def complete(self, **kwargs: object) -> LLMResponse:
        raise RuntimeError("503 + fallback also down")


@pytest.mark.asyncio
async def test_llm_success() -> None:
    provider = FakeLLMProvider([_resp("hypothesis text")], provider_id="deepseek")
    result = await resilient_synthesize(
        provider=provider, prompt="p", model_pin="m", deterministic_fallback=lambda: "fallback"
    )
    assert result.text == "hypothesis text" and result.used_deterministic_fallback is False


@pytest.mark.asyncio
async def test_deterministic_fallback_on_failure() -> None:
    result = await resilient_synthesize(
        provider=_Boom(), prompt="p", model_pin="m", deterministic_fallback=lambda: "DETERMINISTIC"
    )
    assert result.text == "DETERMINISTIC"
    assert result.used_deterministic_fallback is True and result.provider_used == "deterministic"


@pytest.mark.asyncio
async def test_records_cost() -> None:
    provider = FakeLLMProvider([_resp("x")], provider_id="deepseek")
    tracker = InvestigationCostTracker()
    await resilient_synthesize(
        provider=provider,
        prompt="p",
        model_pin="m",
        deterministic_fallback=lambda: "f",
        tracker=tracker,
    )
    assert tracker.llm_call_count == 1 and tracker.estimated_tokens == 15


@pytest.mark.asyncio
async def test_no_cost_recorded_on_fallback() -> None:
    tracker = InvestigationCostTracker()
    await resilient_synthesize(
        provider=_Boom(),
        prompt="p",
        model_pin="m",
        deterministic_fallback=lambda: "f",
        tracker=tracker,
    )
    assert tracker.llm_call_count == 0
