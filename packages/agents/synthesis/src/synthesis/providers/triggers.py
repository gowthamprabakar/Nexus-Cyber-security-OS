"""Fallback trigger classification (synthesis v0.2 Task 9, Q5).

Decides which primary-provider failures warrant a fallback to Anthropic (Q5): **5xx**,
**rate-limit (429)**, and **timeout** errors are transient and worth retrying on the other
provider. A **permanent** error (auth / validation / 4xx other than 429) is NOT retried — the
fallback would fail the same way; the error surfaces instead. ``make_resilient_provider`` wires
this predicate into the Task-8 ``FallbackLLMProvider``.
"""

from __future__ import annotations

from charter.llm import LLMProvider

from synthesis.providers.fallback import FallbackLLMProvider

#: Substrings that mark a transient, fallback-eligible failure (5xx / rate-limit / timeout).
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


def make_resilient_provider(*, primary: LLMProvider, fallback: LLMProvider) -> FallbackLLMProvider:
    """Wrap ``primary`` (DeepSeek) with ``fallback`` (Anthropic), falling back only on a
    transient failure (Q5). ``provider_used`` is recorded per call (WI-Y11)."""
    return FallbackLLMProvider(primary=primary, fallback=fallback, should_fallback=should_fallback)
