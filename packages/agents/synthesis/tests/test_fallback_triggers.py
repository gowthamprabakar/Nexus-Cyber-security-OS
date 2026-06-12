"""synthesis v0.2 Task 9 — fallback trigger logic tests (Q5/WI-Y11)."""

from __future__ import annotations

import pytest
from charter.llm import FakeLLMProvider, LLMResponse, TokenUsage
from synthesis.providers.triggers import make_resilient_provider, should_fallback


def _resp(text: str) -> LLMResponse:
    return LLMResponse(
        text=text,
        stop_reason="end_turn",
        usage=TokenUsage(input_tokens=1, output_tokens=1),
        model_pin="m",
    )


@pytest.mark.parametrize(
    "msg",
    [
        "500 internal",
        "502 bad gateway",
        "503 service unavailable",
        "504 gateway timeout",
        "429 too many requests",
        "rate limit exceeded",
        "connection reset by peer",
    ],
)
def test_transient_triggers_fallback(msg: str) -> None:
    assert should_fallback(RuntimeError(msg)) is True


def test_timeout_error_triggers_fallback() -> None:
    assert should_fallback(TimeoutError("timed out")) is True


@pytest.mark.parametrize(
    "msg", ["401 unauthorized", "403 forbidden", "invalid api key", "400 bad request"]
)
def test_permanent_does_not_trigger_fallback(msg: str) -> None:
    assert should_fallback(RuntimeError(msg)) is False


def test_unknown_does_not_trigger_fallback() -> None:
    assert should_fallback(RuntimeError("weird kaboom")) is False


class _Boom:
    provider_id = "deepseek"

    def __init__(self, msg: str) -> None:
        self._msg = msg

    async def complete(self, **kwargs: object) -> LLMResponse:
        raise RuntimeError(self._msg)


@pytest.mark.asyncio
async def test_resilient_falls_back_on_503() -> None:
    fallback = FakeLLMProvider([_resp("from-anthropic")], provider_id="anthropic")
    provider = make_resilient_provider(primary=_Boom("503 unavailable"), fallback=fallback)
    resp = await provider.complete(prompt="x", model_pin="m", max_tokens=10)
    assert resp.text == "from-anthropic" and provider.provider_used == "anthropic"


@pytest.mark.asyncio
async def test_resilient_reraises_on_401() -> None:
    fallback = FakeLLMProvider([_resp("y")], provider_id="anthropic")
    provider = make_resilient_provider(primary=_Boom("401 unauthorized"), fallback=fallback)
    with pytest.raises(RuntimeError, match="401"):
        await provider.complete(prompt="x", model_pin="m", max_tokens=10)
