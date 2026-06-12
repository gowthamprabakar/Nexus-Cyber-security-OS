# Runbook — LLM Provider Configuration (curiosity v0.2)

D.12 synthesizes hypotheses via `charter.llm` only (no per-agent `llm.py`; the wrapper lives under
`curiosity/providers/`). v0.2 adds DeepSeek-primary + Anthropic-fallback resilience (Q3).

```python
from charter.llm_adapter import config_from_env, make_provider
from curiosity.providers.fallback import make_resilient_provider

primary = make_provider(config_from_env())            # DeepSeek (openai-compatible)
# fallback = make_provider(<anthropic config>)
resilient = make_resilient_provider(primary=primary, fallback=fallback)
```

`FallbackLLMProvider` falls back **only** on a transient (5xx / 429 / timeout) failure; a permanent
error (401, bad model_pin) propagates. `provider_used` + `fallback_count` are recorded per call.
Per **H4** most scan windows detect no gaps and skip the LLM entirely (`llm_skipped=True`).
