"""investigation v0.2 Task 5 — DeepSeek primary + Anthropic fallback tests (Q3)."""

from __future__ import annotations

import pytest
from charter.llm import FakeLLMProvider, LLMResponse, TokenUsage
from investigation.providers.fallback import (
    FallbackLLMProvider,
    make_resilient_provider,
    should_fallback,
)


def _resp(text: str) -> LLMResponse:
    return LLMResponse(
        text=text,
        stop_reason="end_turn",
        usage=TokenUsage(input_tokens=1, output_tokens=1),
        model_pin="m",
    )


class _Boom:
    provider_id = "deepseek"

    def __init__(self, msg: str = "503 unavailable") -> None:
        self._msg = msg

    async def complete(self, **kwargs: object) -> LLMResponse:
        raise RuntimeError(self._msg)


@pytest.mark.parametrize(
    "msg", ["500 internal", "503 service unavailable", "429 too many requests", "rate limit"]
)
def test_transient_triggers_fallback(msg: str) -> None:
    assert should_fallback(RuntimeError(msg)) is True


def test_timeout_triggers_fallback() -> None:
    assert should_fallback(TimeoutError("x")) is True


@pytest.mark.parametrize("msg", ["401 unauthorized", "invalid api key"])
def test_permanent_no_fallback(msg: str) -> None:
    assert should_fallback(RuntimeError(msg)) is False


@pytest.mark.asyncio
async def test_primary_success() -> None:
    primary = FakeLLMProvider([_resp("primary")], provider_id="deepseek")
    fb = FakeLLMProvider([_resp("fb")], provider_id="anthropic")
    p = FallbackLLMProvider(primary=primary, fallback=fb)
    resp = await p.complete(prompt="x", model_pin="m", max_tokens=10)
    assert resp.text == "primary" and p.provider_used == "deepseek"


@pytest.mark.asyncio
async def test_resilient_falls_back_on_503() -> None:
    fb = FakeLLMProvider([_resp("from-anthropic")], provider_id="anthropic")
    p = make_resilient_provider(primary=_Boom("503"), fallback=fb)  # type: ignore[arg-type]
    resp = await p.complete(prompt="x", model_pin="m", max_tokens=10)
    assert resp.text == "from-anthropic" and p.provider_used == "anthropic"


@pytest.mark.asyncio
async def test_resilient_reraises_on_401() -> None:
    fb = FakeLLMProvider([_resp("y")], provider_id="anthropic")
    p = make_resilient_provider(primary=_Boom("401 unauthorized"), fallback=fb)  # type: ignore[arg-type]
    with pytest.raises(RuntimeError, match="401"):
        await p.complete(prompt="x", model_pin="m", max_tokens=10)
