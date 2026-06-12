"""curiosity v0.2 Task 10 — DeepSeek+Anthropic fallback provider (Q3/WI-X12)."""

from __future__ import annotations

import pytest
from charter.llm import LLMResponse, TokenUsage
from curiosity.providers.fallback import (
    FallbackLLMProvider,
    make_resilient_provider,
    should_fallback,
)


class _StubProvider:
    def __init__(self, *, provider_id: str, raises: Exception | None = None) -> None:
        self._provider_id = provider_id
        self._raises = raises
        self.calls = 0

    @property
    def provider_id(self) -> str:
        return self._provider_id

    async def complete(self, **_: object) -> LLMResponse:
        self.calls += 1
        if self._raises is not None:
            raise self._raises
        return LLMResponse(
            text=f"ok:{self._provider_id}",
            stop_reason="stop",
            usage=TokenUsage(input_tokens=1, output_tokens=2),
            model_pin="pin",
            provider_id=self._provider_id,
        )


def test_should_fallback_transient() -> None:
    assert should_fallback(TimeoutError("x"))
    assert should_fallback(RuntimeError("HTTP 503 service unavailable"))
    assert should_fallback(RuntimeError("429 too many requests"))


def test_should_not_fallback_permanent() -> None:
    assert not should_fallback(ValueError("401 unauthorized: bad api key"))
    assert not should_fallback(RuntimeError("invalid model_pin"))


@pytest.mark.asyncio
async def test_primary_succeeds_no_fallback() -> None:
    primary = _StubProvider(provider_id="deepseek")
    fallback = _StubProvider(provider_id="anthropic")
    prov = make_resilient_provider(primary=primary, fallback=fallback)
    resp = await prov.complete(prompt="p", model_pin="m", max_tokens=10)
    assert resp.text == "ok:deepseek"
    assert prov.provider_used == "deepseek"
    assert prov.fallback_count == 0
    assert fallback.calls == 0


@pytest.mark.asyncio
async def test_transient_triggers_fallback() -> None:
    primary = _StubProvider(provider_id="deepseek", raises=RuntimeError("503 service unavailable"))
    fallback = _StubProvider(provider_id="anthropic")
    prov = FallbackLLMProvider(primary=primary, fallback=fallback)
    resp = await prov.complete(prompt="p", model_pin="m", max_tokens=10)
    assert resp.text == "ok:anthropic"
    assert prov.provider_used == "anthropic"
    assert prov.fallback_count == 1


@pytest.mark.asyncio
async def test_permanent_error_propagates() -> None:
    primary = _StubProvider(provider_id="deepseek", raises=ValueError("401 unauthorized"))
    fallback = _StubProvider(provider_id="anthropic")
    prov = FallbackLLMProvider(primary=primary, fallback=fallback)
    with pytest.raises(ValueError, match="401"):
        await prov.complete(prompt="p", model_pin="m", max_tokens=10)
    assert fallback.calls == 0


def test_provider_id_is_primary() -> None:
    prov = make_resilient_provider(
        primary=_StubProvider(provider_id="deepseek"),
        fallback=_StubProvider(provider_id="anthropic"),
    )
    assert prov.provider_id == "deepseek"
