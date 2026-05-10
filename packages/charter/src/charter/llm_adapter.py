"""LLM adapter — picks the right `LLMProvider` from config.

Per ADR-003 and ADR-006: agents NEVER import `anthropic` or `openai`
directly. Instead this module:

1. Reads a deployment-side `LLMConfig` (built from env vars or constructed
   in code), and
2. Returns a concrete `charter.llm.LLMProvider` that the agent driver
   calls through.

**Hoisted into the charter package per ADR-007 v1.1** (2026-05-11).
F.3 (Cloud Posture) and D.1 (Vulnerability) each shipped verbatim copies
of this module under their own packages; the diff between the two was
exactly 1 line (the docstring header). D.1's risk-down review surfaced
the duplication and the canonical home for it.

All 18 agents do:

    from charter.llm_adapter import LLMConfig, make_provider, config_from_env

The `NEXUS_LLM_*` env-var schema is the deployment-time contract.

Supported `provider` values:
- `"anthropic"`            — Anthropic Claude API (frontier tier path)
- `"openai"`               — OpenAI API (gpt-4o-mini etc.)
- `"openai-compatible"`    — any compatible HTTP endpoint (OpenRouter,
                              Together, Fireworks, Groq, DeepSeek, …)
- `"vllm-local"`           — self-hosted vLLM (FedRAMP-High / sovereign path)
- `"ollama"`               — Ollama on localhost (edge / dev / air-gap)

SDK imports are deferred to the branch that needs them so a deployment
using only one provider doesn't pay the cost of importing the other's SDK.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass

from charter.llm import LLMProvider, ModelTier

DEFAULT_PROVIDER = "anthropic"
DEFAULT_VLLM_BASE_URL = "http://localhost:8000/v1"
DEFAULT_OLLAMA_BASE_URL = "http://localhost:11434/v1"


@dataclass(frozen=True, slots=True)
class LLMConfig:
    """Deployment-side LLM configuration for the Cloud Posture Agent."""

    provider: str
    model_pin: str
    model_class: ModelTier = ModelTier.WORKHORSE
    base_url: str | None = None
    api_key: str | None = None
    provider_id: str | None = None
    max_retries: int = 5


def make_provider(config: LLMConfig) -> LLMProvider:
    """Construct an `LLMProvider` from configuration.

    Raises `ValueError` for unknown providers or missing required fields.
    SDK imports are deferred to the branch that needs them.
    """
    if not config.model_pin:
        raise ValueError("LLMConfig.model_pin must be non-empty")

    p = config.provider
    if p == "anthropic":
        from charter.llm_anthropic import AnthropicProvider

        return AnthropicProvider(
            model_class=config.model_class,
            api_key=config.api_key,
            max_retries=config.max_retries,
        )

    if p == "openai":
        from charter.llm_openai_compat import OpenAICompatibleProvider

        return OpenAICompatibleProvider(
            model_class=config.model_class,
            api_key=config.api_key,
            base_url=config.base_url,  # None → SDK default (api.openai.com)
            provider_id=config.provider_id or "openai",
            max_retries=config.max_retries,
        )

    if p == "vllm-local":
        from charter.llm_openai_compat import OpenAICompatibleProvider

        return OpenAICompatibleProvider.for_vllm_local(
            model_class=config.model_class,
            base_url=config.base_url or DEFAULT_VLLM_BASE_URL,
            max_retries=config.max_retries,
        )

    if p == "ollama":
        from charter.llm_openai_compat import OpenAICompatibleProvider

        return OpenAICompatibleProvider.for_ollama(
            model_class=config.model_class,
            base_url=config.base_url or DEFAULT_OLLAMA_BASE_URL,
            max_retries=config.max_retries,
        )

    if p == "openai-compatible":
        if not config.base_url:
            raise ValueError(
                "provider='openai-compatible' requires base_url (e.g. https://openrouter.ai/api/v1)"
            )
        from charter.llm_openai_compat import OpenAICompatibleProvider

        return OpenAICompatibleProvider(
            model_class=config.model_class,
            api_key=config.api_key,
            base_url=config.base_url,
            provider_id=config.provider_id or "openai-compatible",
            max_retries=config.max_retries,
        )

    raise ValueError(
        f"unknown provider: {p!r} "
        "(expected one of: anthropic, openai, openai-compatible, vllm-local, ollama)"
    )


def config_from_env(env: Mapping[str, str] | None = None) -> LLMConfig:
    """Build `LLMConfig` from environment variables.

    Reads:
    - `NEXUS_LLM_PROVIDER`    (default: "anthropic")
    - `NEXUS_LLM_MODEL_PIN`   (required)
    - `NEXUS_LLM_TIER`        (default: "workhorse"; one of frontier/workhorse/edge)
    - `NEXUS_LLM_BASE_URL`    (optional; required for "openai-compatible")
    - `NEXUS_LLM_API_KEY`     (optional; SDK falls back to its native env var
                                — e.g. `ANTHROPIC_API_KEY`, `OPENAI_API_KEY` —
                                if not set)
    - `NEXUS_LLM_PROVIDER_ID` (optional; labels audit entries)
    - `NEXUS_LLM_MAX_RETRIES` (default: 5)

    Raises `ValueError` for missing or malformed required vars.
    """
    e: Mapping[str, str] = env if env is not None else os.environ

    provider = e.get("NEXUS_LLM_PROVIDER", DEFAULT_PROVIDER)
    model_pin = e.get("NEXUS_LLM_MODEL_PIN", "").strip()
    if not model_pin:
        raise ValueError("NEXUS_LLM_MODEL_PIN environment variable is required")

    tier_raw = e.get("NEXUS_LLM_TIER", ModelTier.WORKHORSE.value)
    try:
        tier = ModelTier(tier_raw)
    except ValueError as exc:
        raise ValueError(
            f"NEXUS_LLM_TIER={tier_raw!r} not in {[t.value for t in ModelTier]}"
        ) from exc

    max_retries_raw = e.get("NEXUS_LLM_MAX_RETRIES", "5")
    try:
        max_retries = int(max_retries_raw)
    except ValueError as exc:
        raise ValueError(f"NEXUS_LLM_MAX_RETRIES={max_retries_raw!r} must be an integer") from exc

    return LLMConfig(
        provider=provider,
        model_pin=model_pin,
        model_class=tier,
        base_url=e.get("NEXUS_LLM_BASE_URL") or None,
        api_key=e.get("NEXUS_LLM_API_KEY") or None,
        provider_id=e.get("NEXUS_LLM_PROVIDER_ID") or None,
        max_retries=max_retries,
    )
