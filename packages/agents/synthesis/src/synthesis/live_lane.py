"""NEXUS_LIVE_SYNTHESIS gated live-eval lane (synthesis v0.2 Task 11, Q6).

Consumes the hoisted charter Pattern D (``charter.live_lane``). A single env gate,
``NEXUS_LIVE_SYNTHESIS``, gates the **live-LLM** synthesis lane (DeepSeek primary + Anthropic
fallback), alongside the byte-identical stub-LLM harness (Q6/WI-Y5). Reachability is an
LLM-provider probe (provider env configured). A distinct gate from every prior cycle's lane and
from the older ``NEXUS_LIVE_LLM`` smoke.
"""

from __future__ import annotations

import os
from collections.abc import Callable

from charter.live_lane import live_skip_reason, nexus_live_enabled

SYNTHESIS_LIVE_ENV = "NEXUS_LIVE_SYNTHESIS"
SYNTHESIS_LIVE_SETUP = (
    "set NEXUS_LIVE_SYNTHESIS=1 and configure the LLM provider (NEXUS_LLM_PROVIDER + the model "
    "pin + the provider API key, e.g. DEEPSEEK_API_KEY or ANTHROPIC_API_KEY). e.g.: "
    "NEXUS_LIVE_SYNTHESIS=1 uv run pytest "
    "packages/agents/synthesis/tests/integration/test_synthesis_live_llm_e2e.py -v"
)

#: Env vars that indicate an LLM provider is configured for the live lane.
_PROVIDER_ENV_KEYS = ("NEXUS_LLM_PROVIDER", "DEEPSEEK_API_KEY", "ANTHROPIC_API_KEY")


def nexus_live_synthesis_enabled() -> bool:
    """True iff the live synthesis lane is enabled (``NEXUS_LIVE_SYNTHESIS=1``)."""
    return nexus_live_enabled(SYNTHESIS_LIVE_ENV)


def provider_reachable(
    env: dict[str, str] | None = None,
    probe: Callable[[], tuple[bool, str]] | None = None,
) -> tuple[bool, str]:
    """Reachable iff an LLM provider is configured (a provider env var is set). Pass an explicit
    ``env`` mapping or ``probe``."""
    if probe is not None:
        return probe()
    source = env if env is not None else dict(os.environ)
    if any(source.get(key) for key in _PROVIDER_ENV_KEYS):
        return True, ""
    return False, "no-llm-provider-configured"


def synthesis_live_skip_reason(
    probe: Callable[[], tuple[bool, str]] = lambda: (False, "no-llm-provider-configured"),
) -> str | None:
    return live_skip_reason(SYNTHESIS_LIVE_ENV, "live LLM provider", SYNTHESIS_LIVE_SETUP, probe)
