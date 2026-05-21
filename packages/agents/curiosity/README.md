# `nexus-curiosity-agent`

Curiosity Agent — **D.12**; **fifth of the 7 unbuilt agents** under the [2026-05-20 Path-B-breadth-first operating rule](../../../docs/superpowers/sketches/2026-05-20-agent-version-roadmaps.md); **fifteenth under [ADR-007](../../../docs/_meta/decisions/ADR-007-cloud-posture-as-reference-agent.md)** (F.3 / D.1 / D.2 / D.3 / F.6 / D.7 / D.4 / multi-cloud-posture / k8s-posture / A.1 / D.5 / D.8 / D.6 / D.13 / **D.12**). **The first generative agent in the fleet** — emits hypotheses about what might be under-scanned, not findings about what was scanned. **The first publisher on the `claims.>` substrate** introduced by [ADR-012](../../../docs/_meta/decisions/ADR-012-claims-subject-namespace.md).

> **Bootstrap (Task 1) — 2026-05-21.** Package scaffold + pyproject + smoke tests only. No detector, no hypothesizer, no driver yet. See [`docs/superpowers/plans/2026-05-21-d-12-curiosity-v0-1.md`](../../../docs/superpowers/plans/2026-05-21-d-12-curiosity-v0-1.md) for the full 16-task plan.

## Scope (v0.1)

- **3 emit directions per run**:
  - `SemanticStore` entity (`entity_type="hypothesis"`).
  - `claims.>` fabric publish on `claims.tenant.<tid>.agent.curiosity` (dogfoods ADR-012).
  - `hypotheses.md` workspace markdown for operator review.
- **1 deterministic gap detector**: region-gap (≥10 assets + zero findings in 30d).
- **Single LLM call per run**; max 5 hypotheses emitted (budget cap).
- **Stub-LLM eval harness** keeps the eval suite deterministic + offline.
- **Live-LLM smoke test** gated by `NEXUS_LIVE_LLM=1`.
- **Single-tenant** (`semantic_store=None` + `js_client=None` opt-in default).
- **No probe-directive consumer integration in v0.1** — D.7/D.5/D.8 wire-up lands in those agents' v0.2 plans.

## Q6 invariant (carried through from D.5 + D.13)

D.12 reads SemanticStore which may carry D.5-derived classifier labels (per the ADR-012 + D.13 Q6 contract). The LLM-generated hypothesis text MUST NOT reintroduce classifier-shaped substrings.

**Reuses D.13's reviewer.** Task 7 wires `synthesis.reviewer._scan_classifier_labels` as the regex pass over the rendered hypothesis text + probe directive rationale. Eval case 05 is the WI-2 regression probe.

## ADR-007 conformance

D.12 is the **15th** agent under the reference template, **11th** shipped natively against v1.2. Inherits v1.1 (LLM adapter via `charter.llm_adapter`; no per-agent `llm.py`) and v1.2 (NLAH loader is a 21-LOC shim over `charter.nlah_loader`, lands in Task 11). Also the first agent to use the new ADR-012 substrate (`claims_subject` + `CLAIMS_STREAM` + `JetStreamClient` with `agent_id="curiosity"`).

## Quick start

Package is currently at Bootstrap stage (Task 1). Sibling-state reader / detector / hypothesizer / driver / CLI land in Tasks 3 / 4 / 6 / 10 / 13. To run the smoke tests:

```bash
uv run pytest packages/agents/curiosity -q
```

## License

BSL 1.1 per [ADR-001](../../../docs/_meta/decisions/ADR-001-monorepo-bootstrap.md). Substrate this agent consumes (`charter`, `shared`, `eval-framework`, `synthesis`, `cloud-posture`, `compliance`, `threat-intel`) is Apache 2.0; the agent itself is BSL.
