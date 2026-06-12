"""DeepSeek-primary + Anthropic-fallback LLM provider (synthesis v0.2 Task 8, Q5).

A thin ``LLMProvider`` wrapper that tries the **primary** (DeepSeek via the charter
openai-compatible adapter) and, on a fallback-eligible failure, retries the same call on the
**fallback** (Anthropic). It **composes charter providers only** — no per-agent ``llm.py``
(ADR-007 v1.1; the ``test_no_per_agent_llm_module`` guard), no new charter.llm module, no direct
SDK import (WI-Y9). ``provider_used`` records which provider answered (WI-Y11).

This task ships the wrapper structure with an injectable ``should_fallback`` predicate (default:
fall back on any error); Task 9 plugs in the precise 5xx/rate-limit/timeout trigger.
"""

from __future__ import annotations

from collections.abc import Callable

from charter.llm import LLMProvider, LLMResponse, ToolSchema


def _default_should_fallback(exc: Exception) -> bool:
    return True


class FallbackLLMProvider:
    """Implements ``LLMProvider``; primary first, fallback on a fallback-eligible error."""

    def __init__(
        self,
        *,
        primary: LLMProvider,
        fallback: LLMProvider,
        should_fallback: Callable[[Exception], bool] | None = None,
    ) -> None:
        self._primary = primary
        self._fallback = fallback
        self._should_fallback = should_fallback or _default_should_fallback
        self.provider_used: str | None = None
        self.fallback_count = 0

    @property
    def provider_id(self) -> str:
        return self._primary.provider_id

    async def complete(
        self,
        *,
        prompt: str,
        model_pin: str,
        max_tokens: int,
        system: str | None = None,
        temperature: float = 0.0,
        stop: list[str] | None = None,
        tools: list[ToolSchema] | None = None,
    ) -> LLMResponse:
        kwargs = {
            "prompt": prompt,
            "model_pin": model_pin,
            "max_tokens": max_tokens,
            "system": system,
            "temperature": temperature,
            "stop": stop,
            "tools": tools,
        }
        try:
            response = await self._primary.complete(**kwargs)  # type: ignore[arg-type]
            self.provider_used = self._primary.provider_id
            return response
        except Exception as exc:
            if not self._should_fallback(exc):
                raise
            self.fallback_count += 1
            response = await self._fallback.complete(**kwargs)  # type: ignore[arg-type]
            self.provider_used = self._fallback.provider_id
            return response
