# ADR-006 — One `OpenAICompatibleProvider` subsumes vLLM, Ollama, OpenAI, and most third-party API providers

- **Status:** accepted
- **Date:** 2026-05-09
- **Authors:** AI/Agent Eng, Architect
- **Stakeholders:** every agent author; platform / edge engineers; security & compliance
- **Amends:** [ADR-003 — LLM provider strategy](ADR-003-llm-provider-strategy.md)

## Context

[ADR-003](ADR-003-llm-provider-strategy.md) named three concrete provider implementations: `AnthropicProvider` (Phase 1a), `VLLMProvider` (Phase 1c–2), `OllamaProvider` (Phase 2 / dev convenience). Implementation experience changed the right shape:

- **vLLM serves an OpenAI-compatible Chat Completions endpoint** at `/v1/chat/completions`. The same `openai` Python client works against it without modification.
- **Ollama serves an OpenAI-compatible endpoint** at `:11434/v1`. Same client works.
- **Most other API providers** — OpenAI itself, OpenRouter, Together AI, Fireworks, Groq, DeepSeek, llama.cpp server, LM Studio — all expose the same Chat Completions wire format.

Building three (or more) providers that all wrap the same SDK with cosmetic differences would be N×duplication of retry logic, audit emission, and response mapping for zero behavioral gain.

## Decision

Implement **one `OpenAICompatibleProvider`** in `packages/charter/src/charter/llm_openai_compat.py`. Configure with `base_url` + `api_key` to target any OpenAI-compatible service. Set `provider_id` to label audit entries clearly.

Ship two `@classmethod` convenience constructors for the most common dev / sovereign-deployment paths:

| Constructor                                    | Default `base_url`          | Default `model_class` | `provider_id`  | Use case                                                                   |
| ---------------------------------------------- | --------------------------- | --------------------- | -------------- | -------------------------------------------------------------------------- |
| `OpenAICompatibleProvider.for_vllm_local(...)` | `http://localhost:8000/v1`  | `WORKHORSE`           | `"vllm-local"` | Self-hosted GPU server in customer cluster (sovereign / FedRAMP-High path) |
| `OpenAICompatibleProvider.for_ollama(...)`     | `http://localhost:11434/v1` | `EDGE`                | `"ollama"`     | Edge plane lightweight reasoning; air-gap; developer laptop                |

Bare `OpenAICompatibleProvider(model_class=..., api_key=...)` (no `base_url`) targets OpenAI proper. Other compatible services (OpenRouter, Together, etc.) are configured with explicit `base_url` + `provider_id` arguments.

`AnthropicProvider` stays separate ([ADR-003](ADR-003-llm-provider-strategy.md), [`llm_anthropic.py`](../../../packages/charter/src/charter/llm_anthropic.py)) because Anthropic's wire format and content-block model genuinely differ from OpenAI's.

Both providers are shipped as **optional extras** of `nexus-charter` so OSS consumers don't transitively pull either SDK:

```toml
anthropic = ["anthropic>=0.36.0", "tenacity>=9.0.0"]
openai-compatible = ["openai>=1.50.0", "tenacity>=9.0.0"]
```

## Consequences

### Positive

- **Five "providers" worth of coverage in one class.** Adding OpenRouter / Together / Fireworks / Groq / DeepSeek / a customer's private vLLM deployment is a config change, not a code change.
- **The sovereign / air-gap deployment path becomes real today.** The Phase-4 air-gap commitment in [`platform_architecture.md §1.5`](../../architecture/platform_architecture.md#L163) was structurally blocked on having a self-hosted-LLM track; it now has one (`for_vllm_local()` / `for_ollama()`). The runtime risk listed as #1 in [system-readiness.md](../system-readiness.md) is partially retired (capability lands; eval-parity gating still needed).
- **Convenience constructors codify operational defaults.** `for_ollama()` defaults to `ModelTier.EDGE`; `for_vllm_local()` defaults to `ModelTier.WORKHORSE`. Right defaults for the common cases.
- **Provider-neutral audit shape preserved.** All audit entries carry `provider_id`, `model_pin`, token counts. Downstream consumers (Meta-Harness, audit verifier, eval framework) don't need to special-case provider source.
- **Single retry / failure-mode codebase.** Tenacity policy + retryable-vs-non-retryable error classification lives in one place per SDK family (Anthropic, OpenAI). N=2 instead of N=many.

### Negative

- **OpenAI-compatibility is sometimes superficial.** Not every endpoint claiming compatibility implements every parameter (e.g., some local servers ignore `stop` sequences; some return non-OpenAI `usage` shapes; some emit malformed JSON in tool_call arguments). The provider tolerates malformed tool-call JSON via a `_raw` fallback; other quirks bubble up as test failures when a target endpoint is added.
- **`tools` param shape varies more than `messages` does.** Some compatible servers don't support tool-calling at all. Caller is responsible for matching tool-use to a compatible model+endpoint pairing.

### Neutral / unknown

- A separate `BedrockProvider` (AWS) is still pending — Bedrock has its own SDK shape. Not blocked by this ADR.
- Whether to add a small provider registry (`register_provider("anthropic", ...)`) for the agent driver to resolve `tier → concrete LLMProvider` from config: deferred to Task 10 when the agent driver actually needs it.

## Alternatives considered

### Alt 1: Three separate provider classes (`OpenAIProvider`, `VLLMProvider`, `OllamaProvider`)

- Why rejected: 3× the retry / audit / mapping code with cosmetic-only differences. Future maintenance multiplies linearly. Convenience-constructor pattern gives the same ergonomics with N=1 implementation.

### Alt 2: Subclass `OpenAICompatibleProvider` for each target

- Why rejected: subclasses imply behavioral specialization; in our case the only differences are defaults (base_url, api_key, provider_id, model_class). Classmethod constructors express that more honestly than inheritance.

### Alt 3: Native Ollama `/api/chat` endpoint instead of its `/v1/` OpenAI alias

- Why rejected: Ollama's native API is a separate wire format with its own quirks; the OpenAI alias is supported and stable. One less mapping layer to maintain.

### Alt 4: Use LangChain / LiteLLM as the abstraction layer

- Why rejected: an additional dependency surface and a parallel notion of "provider" that we then have to map our `LLMProvider` Protocol over. Direct SDK use is shorter, easier to audit, and keeps the charter package's dep surface minimal.

## References

- Implementation: [`packages/charter/src/charter/llm_openai_compat.py`](../../../packages/charter/src/charter/llm_openai_compat.py)
- Tests: [`packages/charter/tests/test_llm_openai_compat.py`](../../../packages/charter/tests/test_llm_openai_compat.py)
- Companion: [ADR-003 LLM provider strategy](ADR-003-llm-provider-strategy.md), [ADR-005 async tool wrapper convention](ADR-005-async-tool-wrapper-convention.md)
- Sister provider: [`packages/charter/src/charter/llm_anthropic.py`](../../../packages/charter/src/charter/llm_anthropic.py)
- Risk #1 in [`docs/_meta/system-readiness.md`](../system-readiness.md) — sovereign / air-gap implementability — partially retired by this ADR.
