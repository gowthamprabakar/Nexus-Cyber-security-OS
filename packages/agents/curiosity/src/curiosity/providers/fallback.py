"""DeepSeek-primary + Anthropic-fallback LLM provider (curiosity v0.2 Task 10, Q3).

Inherits the D.13 (Cycle 13) + D.7 (Cycle 14) institutional pattern: a thin ``LLMProvider``
wrapper that tries the **primary** (DeepSeek via the charter openai-compatible adapter) and, on a
transient failure, retries the same call on the **fallback** (Anthropic). Composes **charter
providers only** — no per-agent ``llm.py`` (ADR-007 v1.1; the ``test_no_per_agent_llm_module``
guard, WI-X12), no direct SDK import. ``should_fallback`` triggers only on transient (5xx /
rate-limit / timeout) failures; ``provider_used`` records which provider answered.
"""

from __future__ import annotations

from collections.abc import Callable

from charter.llm import LLMProvider, LLMResponse, ToolSchema

_TRANSIENT_MARKERS = (
    "timeout",
    "timed out",
    "rate limit",
    "429",
    "too many requests",
    "500",
    "502",
    "503",
    "504",
    "service unavailable",
    "bad gateway",
    "gateway timeout",
    "connection reset",
    "connection refused",
    "temporarily unavailable",
)


def should_fallback(exc: Exception) -> bool:
    """True iff ``exc`` is a transient (5xx / rate-limit / timeout) failure worth a fallback."""
    if isinstance(exc, TimeoutError):
        return True
    text = str(exc).lower()
    return any(marker in text for marker in _TRANSIENT_MARKERS)


class FallbackLLMProvider:
    """Implements ``LLMProvider``; primary first, fallback on a fallback-eligible error."""

    def __init__(
        self,
        *,
        primary: LLMProvider,
        fallback: LLMProvider,
        should_fallback: Callable[[Exception], bool] = should_fallback,
    ) -> None:
        self._primary = primary
        self._fallback = fallback
        self._should_fallback = should_fallback
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


def make_resilient_provider(*, primary: LLMProvider, fallback: LLMProvider) -> FallbackLLMProvider:
    """Wrap ``primary`` (DeepSeek) with ``fallback`` (Anthropic) — falls back only on a transient
    failure (Q3). ``provider_used`` is recorded per call."""
    return FallbackLLMProvider(primary=primary, fallback=fallback)
