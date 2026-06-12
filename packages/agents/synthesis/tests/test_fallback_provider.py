"""synthesis v0.2 Task 8 — DeepSeek primary + Anthropic fallback tests (Q5)."""

from __future__ import annotations

import pytest
from charter.llm import FakeLLMProvider, LLMResponse, TokenUsage
from synthesis.providers.fallback import FallbackLLMProvider


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
        raise RuntimeError("503 service unavailable")


async def _complete(provider: FallbackLLMProvider) -> LLMResponse:
    return await provider.complete(prompt="hi", model_pin="m", max_tokens=100)


@pytest.mark.asyncio
async def test_primary_success_uses_primary() -> None:
    primary = FakeLLMProvider([_resp("primary")], provider_id="deepseek")
    fallback = FakeLLMProvider([_resp("fallback")], provider_id="anthropic")
    wrapper = FallbackLLMProvider(primary=primary, fallback=fallback)
    resp = await _complete(wrapper)
    assert resp.text == "primary" and wrapper.provider_used == "deepseek"
    assert wrapper.fallback_count == 0


@pytest.mark.asyncio
async def test_primary_failure_falls_back() -> None:
    fallback = FakeLLMProvider([_resp("fallback")], provider_id="anthropic")
    wrapper = FallbackLLMProvider(primary=_Boom(), fallback=fallback)
    resp = await _complete(wrapper)
    assert resp.text == "fallback" and wrapper.provider_used == "anthropic"
    assert wrapper.fallback_count == 1


@pytest.mark.asyncio
async def test_should_fallback_false_reraises() -> None:
    fallback = FakeLLMProvider([_resp("fallback")], provider_id="anthropic")
    wrapper = FallbackLLMProvider(
        primary=_Boom(), fallback=fallback, should_fallback=lambda exc: False
    )
    with pytest.raises(RuntimeError, match="503"):
        await _complete(wrapper)


@pytest.mark.asyncio
async def test_fallback_also_fails_raises() -> None:
    wrapper = FallbackLLMProvider(primary=_Boom(), fallback=_Boom())
    with pytest.raises(RuntimeError):
        await _complete(wrapper)


def test_provider_id_is_primary() -> None:
    primary = FakeLLMProvider([_resp("x")], provider_id="deepseek")
    fallback = FakeLLMProvider([_resp("y")], provider_id="anthropic")
    assert FallbackLLMProvider(primary=primary, fallback=fallback).provider_id == "deepseek"
