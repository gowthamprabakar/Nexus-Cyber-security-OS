# `nexus-synthesis-agent`

Synthesis Agent — **D.13**; **fourth of the 7 unbuilt agents** under the [2026-05-20 Path-B-breadth-first operating rule](../../../docs/superpowers/sketches/2026-05-20-agent-version-roadmaps.md); **fourteenth under [ADR-007](../../../docs/_meta/decisions/ADR-007-cloud-posture-as-reference-agent.md)** (F.3 / D.1 / D.2 / D.3 / F.6 / D.7 / D.4 / multi-cloud-posture / k8s-posture / A.1 / D.5 / D.8 / D.6 / **D.13**). Customer-facing narration: synthesizes findings + investigations + compliance reports into human-readable LLM-narrated summaries.

**D.13 is the first agent that actually calls the LLM in its hot path** (prior agents plumb `llm_provider` through their drivers but never invoke it).

> **Bootstrap (Task 1) — 2026-05-21.** Package scaffold + pyproject + smoke tests only. No reader, no narrator, no driver yet. See [`docs/superpowers/plans/2026-05-21-d-13-synthesis-v0-1.md`](../../../docs/superpowers/plans/2026-05-21-d-13-synthesis-v0-1.md) for the full 16-task plan.

## Scope (v0.1)

- **2 narrative artifacts**: `narrative.md` (sectioned per-finding-class) + `executive_summary.md` (1-paragraph C-suite digest).
- **3 sibling-workspace sources** (read-only, operator-pinned via flags):
  - `--investigation-workspace` — D.7 Investigation conclusions (narrative spine).
  - `--compliance-workspace` — D.6 Compliance posture (compliance section).
  - `--cloud-posture-workspace` — F.3 Cloud Posture (technical-details fallback).
- **2 LLM calls per run**: outline call (structured JSON) → per-section narration. Both seeded `temperature=0.0`; model pinned via `envelope.model_pin`. 3 prompt templates loaded via `importlib.resources`.
- **Stub-LLM eval harness** keeps the eval suite deterministic + offline.
- **Live-LLM smoke test** gated by `NEXUS_LIVE_LLM=1`.
- **Single-tenant** (`semantic_store=None` opt-in default).
- **No OCSF emit** in v0.1 (deferred to v0.2 pending a `class_uid` ADR).

## Q6 invariant (carried through from D.5)

**Two-layer defence against classifier-substring leakage via LLM hallucination:**

1. **Stage 2 ENRICH context bundle carries structured fields only** — finding IDs, severities, control IDs, classifier _labels_ (not matched substrings).
2. **Stage 4 REVIEW regex-guards the rendered narrative** for classifier patterns (SSN, credit_card, AWS-access-key, JWT). On violation: reject + retry with `q6_violation_retry` hint.

Eval case 007 (`no_classifier_substrings`) is the regression probe.

## ADR-007 conformance

D.13 is the **14th** agent under the reference template, **10th** shipped natively against v1.2. Inherits v1.1 (LLM adapter via `charter.llm_adapter`; no per-agent `llm.py`) and v1.2 (NLAH loader is a 21-LOC shim over `charter.nlah_loader`, lands in Task 10).

## Quick start

Package is currently at Bootstrap stage (Task 1). Reader / narrator / driver / CLI land in Tasks 3 / 6 / 9 / 12. To run the smoke tests:

```bash
uv run pytest packages/agents/synthesis -q
```

## License

BSL 1.1 per [ADR-001](../../../docs/_meta/decisions/ADR-001-monorepo-bootstrap.md). Substrate this agent consumes (`charter`, `investigation`, `compliance`, `cloud-posture`, `eval-framework`) is Apache 2.0; the agent itself is BSL.
