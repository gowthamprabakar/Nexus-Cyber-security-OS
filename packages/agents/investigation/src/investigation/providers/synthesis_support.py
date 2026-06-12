"""Resilient hypothesis synthesis support (investigation v0.2 Task 10, Q3/H3).

Wraps the LLM hypothesis call with the Task-5 resilient provider (DeepSeek -> Anthropic) and a
**deterministic enumeration fallback** (H3): if the LLM is unavailable even after the fallback,
synthesis still produces a grounded result rather than failing the investigation. The cost
tracker (Task 6) records each call. The Hypothesis schema is unchanged, so the OCSF 2005 wire
shape stays byte-identical (WI-I5). Pure orchestration over an injectable provider.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from charter.llm import LLMProvider

from investigation.providers.cost_tracking import InvestigationCostTracker


@dataclass(frozen=True, slots=True)
class SynthesisResult:
    text: str
    provider_used: str
    used_deterministic_fallback: bool


async def resilient_synthesize(
    *,
    provider: LLMProvider,
    prompt: str,
    model_pin: str,
    deterministic_fallback: Callable[[], str],
    tracker: InvestigationCostTracker | None = None,
    max_tokens: int = 2000,
) -> SynthesisResult:
    """Synthesize via ``provider``; on any failure (incl. the fallback provider also failing),
    return the deterministic enumeration (H3). Records usage in ``tracker`` if given."""
    try:
        response = await provider.complete(
            prompt=prompt, model_pin=model_pin, max_tokens=max_tokens
        )
    except Exception:
        return SynthesisResult(
            text=deterministic_fallback(),
            provider_used="deterministic",
            used_deterministic_fallback=True,
        )
    provider_used = getattr(provider, "provider_used", None) or provider.provider_id
    if tracker is not None:
        tracker.record(response, provider_used=provider_used)
    return SynthesisResult(
        text=response.text,
        provider_used=provider_used,
        used_deterministic_fallback=False,
    )
