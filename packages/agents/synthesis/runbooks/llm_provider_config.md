# Runbook — LLM Provider Configuration (synthesis v0.2)

## DeepSeek primary + Anthropic fallback (Q5)

Configure via `charter.llm_adapter` (D.13 ships NO per-agent llm.py — WI-Y9):

- Primary: DeepSeek through the openai-compatible adapter (`NEXUS_LLM_PROVIDER=openai-compatible`
  - endpoint + `DEEPSEEK_API_KEY`).
- Fallback: Anthropic (`ANTHROPIC_API_KEY`).

Wrap with `synthesis.providers.triggers.make_resilient_provider(primary=..., fallback=...)`:
DeepSeek is tried first; a transient failure (5xx / 429 / timeout) falls back to Anthropic; a
permanent error (auth/validation) surfaces. `provider_used` is recorded per call (WI-Y11).
