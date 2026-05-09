# ADR-003 — LLM provider strategy: tiered, abstracted, sovereign-capable

- **Status:** accepted
- **Date:** 2026-05-09
- **Authors:** AI/Agent Eng, Architect
- **Stakeholders:** every agent author; platform / edge engineers; security & compliance

## Context

The architecture and build roadmap currently hard-bind every reasoning call to the Anthropic API: `LLM Service: Anthropic API (Claude Sonnet primary)` ([`platform_architecture.md:187`](../../architecture/platform_architecture.md#L187)) with versions pinned in the charter (`claude-sonnet-4-5 / opus-4-5 / haiku-4`). Self-hosted LLMs appear in [`PRD.md:1202`](../../strategy/PRD.md#L1202) only as a _detection target_, never as runtime infrastructure.

This creates four unresolved tensions:

1. **Architecture inverts its own thesis.** The runtime charter (NLAH + file-backed state + execution contracts + eval gates) exists _precisely_ to make smaller, controllable models reliable for production work. Running that disciplined harness on top of frontier Anthropic models pays frontier prices for problems the harness was designed to make smaller models good enough for.
2. **Sovereignty / air-gap is structurally impossible** with API-only inference. The architecture promises FedRAMP High (Phase 5), IL5, and air-gap deployment ([`§1.5`](../../architecture/platform_architecture.md#L163)) — these are incompatible with mandatory egress to Anthropic.
3. **Vendor concentration risk is mis-sized** ([§9 row 8](../../architecture/platform_architecture.md#L903) lists "Major LLM provider outage" as Likelihood: Low). Anthropic incidents through 2025 say otherwise. The "OpenAI fallback" mitigation isn't built.
4. **Provider lock-in propagates through every agent.** [`packages/agents/cloud-posture/pyproject.toml`](../../../packages/agents/cloud-posture/pyproject.toml) imports `anthropic` directly. Without abstraction, agent #1's choice becomes 18 agents' choice.

The decision is overdue: F.3 Task 9 ("LLM client wrapper (Anthropic) with retry") is two tasks away. Whatever ships first becomes the de facto API.

## Decision

Adopt a **three-tier model policy** behind a single **`LLMProvider` interface**, defined in `packages/charter` and consumed by every agent. No agent imports `anthropic` (or any other vendor SDK) directly.

| Tier          | Use cases                                                                                                       | Model class                              | Hosted where                                               | Provider examples                                                            |
| ------------- | --------------------------------------------------------------------------------------------------------------- | ---------------------------------------- | ---------------------------------------------------------- | ---------------------------------------------------------------------------- |
| **Frontier**  | Synthesis Agent, Investigation Agent root reasoning, Meta-Harness NLAH rewrites, customer-facing chat synthesis | Top-tier proprietary                     | Control plane only                                         | Anthropic Claude Opus / Sonnet via API                                       |
| **Workhorse** | The 18 detection-agent NLAH executions; routine triage; Tier-3 remediation drafting                             | Mid-tier proprietary OR self-hosted ~70B | Control plane (SaaS customers); edge (sovereign customers) | Anthropic Haiku **or** Llama 3.3 70B / Qwen 2.5 72B / Mistral Large via vLLM |
| **Edge**      | Edge-plane "lightweight reasoning"; air-gap; IL5 / FedRAMP-High deployments                                     | Self-hosted small (7–14B)                | Edge plane only                                            | Llama 3.1 8B, Qwen 2.5 7B, Phi-4 14B via vLLM or llama.cpp                   |

The charter pins **tier**, not vendor. A contract specifies `tier: workhorse`; the runtime resolves tier → concrete `LLMProvider` per tenant deployment profile.

`LLMProvider` interface (in `packages/charter/src/charter/llm.py`, to be added):

```python
class LLMProvider(Protocol):
    async def complete(
        self,
        prompt: str,
        system: str | None = None,
        max_tokens: int,
        temperature: float = 0.0,
        stop: list[str] | None = None,
        tools: list[ToolSchema] | None = None,
        model_pin: str,           # exact ID, audited
    ) -> LLMResponse: ...

    @property
    def provider_id(self) -> str: ...   # e.g. "anthropic", "vllm-local"

    @property
    def model_class(self) -> ModelTier: ...  # frontier / workhorse / edge
```

Initial implementations: `AnthropicProvider` (Phase 1a), `VLLMProvider` (Phase 1c–2), `OllamaProvider` (Phase 2 / dev convenience). All three live behind the same interface; the charter chooses one at invocation time based on the contract's `tier` and the deployment's `provider_map`.

Provider swap is a config change, not a code change. Eval-suite parity (cross-provider equivalence) is the gate.

## Consequences

### Positive

- The charter's portability promise is cashed: F.1 / F.2 / F.6 stay vendor-neutral.
- Air-gap, sovereign, and FedRAMP-High deployments become a deployment-config decision (`provider_map` substitutes vLLM-local for the workhorse + edge tiers), not a separate codebase.
- Cost optimization is now mechanical: route Haiku-class workloads to a self-hosted 70B once eval parity is proven; frontier customers stay on Anthropic by default.
- Vendor outage mitigation is real, not aspirational: the same agent code can run on a fallback provider with no rebuild.
- Per-customer routing becomes possible (regulated customer → vLLM-local; SaaS customer → Anthropic), which is the only honest path to the compliance roadmap.

### Negative

- Eval-parity gating is non-trivial. A workhorse swap (Haiku → Llama 3.3 70B) must be proven on the per-agent eval suite before customer rollout. F.2 must explicitly support cross-provider runs.
- Self-hosted inference adds GPU operations cost that the current cost model in [`§7.1`](../../architecture/platform_architecture.md#L644) does not include. Acceptable: those numbers are already optimistic and need revision.
- Latency profile differs across providers. Some agents will need contract-level tolerance bands (acceptable max token-generation latency) before swap.

### Neutral / unknown

- The exact local model selection per tier is deferred to a spike in Phase 1b (P0.7 expansion). The interface choice is independent of the model choice.
- "Frontier" tier may always remain proprietary API; that is acceptable provided the workhorse + edge tiers remove the sovereignty blocker.

## Alternatives considered

### Alt 1: Anthropic-only through Phase 1, defer provider abstraction

- Why rejected: every agent that ships will inherit Anthropic-shaped assumptions. Refactor cost grows linearly with agent count; cheapest fix is at agent #1.

### Alt 2: Multi-provider routing without tiering (free-for-all)

- Why rejected: agents would specify vendors, defeating portability. Tiers are the abstraction that lets the charter pick the right model class without leaking provider details into the NLAH.

### Alt 3: Self-host everything from day one

- Why rejected: Phase 1a is foundation work; introducing vLLM ops + GPU fleet now adds blast-radius before product-market fit. Tiering keeps Anthropic as the path of least resistance for SaaS customers and reserves self-hosting for the deployments that actually require it.

## References

- Plan: [`docs/superpowers/plans/2026-05-08-f-3-cloud-posture-reference-nlah.md`](../../superpowers/plans/2026-05-08-f-3-cloud-posture-reference-nlah.md) — Task 9 (LLM client wrapper) must implement against this interface, not directly against Anthropic SDK.
- Counterpart: [ADR-004](ADR-004-fabric-layer.md) — `LLMProvider` is invoked over the in-process boundary; cross-service routing happens through the fabric.
- Counterpart: [ADR-005](ADR-005-async-tool-wrapper-convention.md) — `LLMProvider.complete` is async by definition.
- To-do: P0.7 spike scope expands to include "self-hosted workhorse model selection + eval parity methodology."
