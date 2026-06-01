# A.4 Meta-Harness v0.2.5 — Skill Optimization Brainstorm

**Date locked:** 2026-05-30
**Status:** CLOSED (all 8 questions resolved)
**Label:** LOW-RISK (doc-only canonical artifact)
**Context:** This cycle closes the prerequisite gap identified in
[hermes-self-evolution-adoption-2026-05-23.md](../../_meta/hermes-self-evolution-adoption-2026-05-23.md)
(PR #195) §4.1 — it plugs **DSPy + GEPA** into the G1 + G2 foundation.

---

## Premise

v0.2.5 is the **optimization engine**. The dependency chain is now two-thirds
built: **G1 measured** (confidence-weighted composite effectiveness score per
deployed skill), **G2 selected** (the LLM reads G1-enriched Level 0 metadata and
picks effective skills per run). **v0.2.5 optimizes** — it continuously compiles
agent prompts with DSPy and evolves them with GEPA, using G1's effectiveness
score as the `metric=` GEPA optimizes against. Without v0.2.5, the
compounding-learning loop has a measurement layer and a selection layer but no
improvement layer; skills are scored and chosen but never made better.

**Strategic references:**

- [hermes-pattern-absorption-2026-05-22.md](../../_meta/hermes-pattern-absorption-2026-05-22.md) (PR #175) — Hermes nectar N1-N6 + landing map.
- [dspy-gepa-prompt-optimization-2026-05-22.md](../../_meta/dspy-gepa-prompt-optimization-2026-05-22.md) (PR #181) — DSPy+GEPA strategic analysis; v0.2.5 sequencing.
- [hermes-self-evolution-adoption-2026-05-23.md](../../_meta/hermes-self-evolution-adoption-2026-05-23.md) (PR #195) — gap analysis; G1 → G2 → v0.2.5 → Wave 1 sequencing.

**Foundation closures this cycle builds on:**

- [G1 effectiveness-scoring verification record](../../_meta/g1-effectiveness-scoring-verification-2026-05-25.md) — the metric.
- [G2 skill-selection verification record](../../_meta/g2-skill-selection-verification-2026-05-30.md) — the selector.

> **Path note:** the G1 closure record is dated **2026-05-25** (not 2026-05-24, as
> some upstream references state). The 2026-05-25 file is the canonical one.

---

## Honest preface — ADR-011 cadence gap caught and resolved

This brainstorm was originally conducted via **conversational state across
multiple prior Claude sessions but never committed as a canonical artifact.** The
Hermes adoption doc (PR #195) referenced "v0.2.5 brainstorm OPEN," but the
brainstorm doc itself **did not exist on disk** — and its recorded resume-point
was itself inconsistent (one place said "resolutions 1-3 locked; Q4-Q8 pending,"
another said "paused at Q7").

The gap was caught during the **2026-05-30** brainstorm-resumption attempt: an
attempt to "resume at Q7" from session memory was checked against the repo
(`git log --all --diff-filter=A -- "*brainstorm*"` and `find docs -name
"*brainstorm*"`) — both confirmed **no committed brainstorm doc ever existed**,
and no G1/G2 brainstorm-doc precedent existed either (only plan docs +
verification records were committed for those cycles).

**Resolution:** a fresh, grounded brainstorm — anchored in the committed
strategic docs above + the **15 carry-forward candidates** pulled from the G1 and
G2 verification records — locked all 8 questions on 2026-05-30. **This doc is the
canonical source of truth** for the v0.2.5 plan doc and execution.

**Lesson for future cycles:** follow the ADR-011 cadence strictly — the
brainstorm doc is committed **before** plan-doc drafting begins, not
reconstructed afterward.

---

## Resolutions

### Q1 — LLM provider for v0.2.5 compilation

**Resolution:** v0.2.5 compilation uses **DeepSeek API V4 Pro** via
`OpenAICompatibleProvider` (per ADR-006). **Anthropic is the locked strategic
production target**, deferred until API-key acquisition. DeepSeek is the
development/test path; Anthropic is the deployment target.

- **ADR-006 amended in v0.2.5** to list DeepSeek as a supported provider.
- Per-customer model configuration **deferred to v0.3+** (blocked on the SET LOCAL
  tenant-RLS substrate fix).
- **Switch-validation task** added to the plan: before closure, **one compilation
  cycle must run on Anthropic** to validate that compiled prompts behave
  correctly on the production target model. **This task BLOCKS v0.2.5 closure on
  Anthropic key acquisition.**

### Q2 — GEPA optimizer parameters

**Resolution:** GEPA default `auto="medium"` with an **eval-budget cap of max 50
trials per compilation**. Per-agent override allowed in the plan doc.

- **Cost expectation:** ~**$15-35/month** for 17 agents at weekly compilation on
  DeepSeek — far below the strategic doc's ~$340-850/month Anthropic estimate.

### Q3 — Stage 7 SKILL_CREATE DSPy migration shape

**Resolution:** Stage 7 ships a **parallel implementation** — the DSPy-compiled
compositor runs **alongside** the existing single-LLM-call composer. The
eval-gate scores both outputs per skill creation; the **higher-scoring output is
persisted**.

- Provides automatic A/B quality data (satisfies the Q8 quality-delta requirement
  as a side effect).
- The legacy single-LLM-call path is the **CF #2 graceful-degradation fallback**
  if DSPy compilation fails.
- 2× LLM cost per skill creation is acceptable at DeepSeek dev pricing.
- v0.3 may switch to DSPy-only once reliability is proven across multiple cycles.

### Q4 — Compilation cadence

**Resolution:** **Hybrid** — event-driven **and** scheduled. All triggers fire
independently.

- **Event-driven triggers:** effectiveness score drops below **0.4** for any
  deployed skill (configurable); **10+** new skills accumulated since last
  compilation (configurable); operator CLI manual trigger.
- **Scheduled trigger:** weekly cron per agent (configurable per agent, default
  ON).
- Each compilation is **eval-gated before deployment** per the existing
  skill-eval-gate pattern (A.4 v0.2 Task 8).
- **Compilation locks per-agent** — no concurrent compilations of the same agent.

### Q5 — GEPA `metric=` ↔ G1 effectiveness API integration

**Resolution:** v0.2.5 adds a **`gepa_metric` adapter layer** wrapping
`get_effectiveness_score()` for GEPA's `metric=` parameter. (Grounded in the
2026-05-30 read-only API verification of the committed G1 code.)

- **(a) None / zero-confidence handling — SKIP.** Examples where the score is
  `None` or `confidence == 0.0` are excluded from GEPA training data; they
  re-enter the pool when evidence accumulates. Matches the G1 schema's design
  intent ("GEPA compilation naturally ignores zero-confidence signals").
- **(b) Confidence handling — MODULATE.** Pass `global_score × confidence` to
  GEPA. Mirrors G2's persona composite rule (effectiveness × confidence) —
  consistent math across the selection and optimization layers.
- **(c) Textual reflection — USE operator notes.** The adapter reads operator
  feedback notes from the ratings sidecar at compilation start, caches them in
  memory for the cycle, and assembles the reflection string as
  `reason.value` + axes breakdown + operator notes (when present). Preserves
  GEPA's natural-language reflection advantage.
- **Module location:** new helper `meta_harness.gepa_adapter` (consumer code; no
  substrate touch).
- **Failure modes:** the adapter handles G1 read failures per the CF #2 pattern —
  an exception during sidecar read → log an audit event, return a tuple signaling
  "no metric available," GEPA skips the example. No crash.
- **Implementation cost:** ~1 plan task (~half-day for adapter + tests).
- **Future (v0.3):** revisit (a) — once production data exists, consider whether
  brand-new skills should get neutral-0.5 warmup treatment instead of skip.

> **API ground truth (verified 2026-05-30, committed code):**
> `get_effectiveness_score(skill_id, agent_id, *, workspace_root, tenant_id="default")
-> EffectivenessScore | None`. Returns a **pydantic model** (not a scalar):
> `global_score: float | None`, `confidence: float`, `axes_breakdown` (adoption /
> outcome / feedback, each `{score, confidence}`), `reason: EffectivenessReason |
None`, `by_agent` / `by_tenant` maps. Returns **`None`** on absent / unparseable
> / wrong-tenant sidecar (no raise, no sentinel). Composite weights
> (0.25 / 0.35 / 0.40) are **module constants**, not runtime parameters (see Q7
> Item 3 → v0.3). Hence the adapter is **required** — the API does not slot into
> GEPA's `float | tuple[float, str]` contract directly.

### Q6 — Per-customer compilation scope

**Resolution:** **Single-tenant compilation only** in v0.2.5. Per-customer
compilation is **entirely deferred to v0.3+** (blocks on the SET LOCAL tenant-RLS
substrate fix). Schema design for per-customer compilation is **NOT done in
v0.2.5** — to avoid wasted work if the SET LOCAL fix changes the data shape. The
v0.2.5 verification record will explicitly note this as a deferred-by-design
carry-forward.

### Q7 — Carry-forward triage (15 items)

The 15 candidates pulled from the G1 + G2 verification records, triaged:

**LAND in v0.2.5 (3 items):**

| #   | Source    | Item                                                                                            |
| --- | --------- | ----------------------------------------------------------------------------------------------- |
| 1   | G1-CF4    | Retrofit the CF #2 graceful-degradation pattern to `skill_lifecycle.py` `_safely` helpers       |
| 2   | G1-CF8    | DSPy+GEPA — wire G1's metric/API into the GEPA teleprompter (**this is v0.2.5's core mission**) |
| 15  | G2 / WI-6 | Programmatic byte-identity guard test for the NLAH "Skill selection guidance" section           |

**DEFER to v0.3 / future cycle (10 items):**

| #   | Source      | Item                                  | Destination                                |
| --- | ----------- | ------------------------------------- | ------------------------------------------ |
| 3   | G1-CF1 / G2 | Per-agent effectiveness weight tuning | v0.3                                       |
| 4   | G1-CF2 / G2 | Scheduled effectiveness aggregation   | v0.3 Curator                               |
| 5   | G1-CF3      | Per-tenant effectiveness isolation    | blocked on SET LOCAL substrate fix         |
| 6   | G1-CF5      | Effectiveness-based skill pruning     | v0.3 Curator                               |
| 7   | G1-CF6      | UI dashboard                          | Phase 2 Surface track                      |
| 8   | G1-CF7      | Cross-agent effectiveness comparison  | v0.3 Curator                               |
| 9   | G2          | Selection dispatcher implementation   | dedicated agent-runtime cycle after v0.2.5 |
| 10  | G2          | `skill.selected` audit event          | future, if production data shows need      |
| 11  | G2          | Per-tool-call selection granularity   | v0.3+                                      |
| 12  | G2          | Cross-agent compositional selection   | future cycle                               |

**NOT BUILT by design (2 items):**

| #   | Source | Item                      | Rationale                 |
| --- | ------ | ------------------------- | ------------------------- |
| 13  | G2-Q2  | Embeddings infrastructure | G2-Q2 Hermes-pattern lock |
| 14  | G2-Q2  | RAG / vector store        | G2-Q2 Hermes-pattern lock |

### Q8 — Closure criteria for v0.2.5

**Resolution:** v0.2.5 closure requires **ALL of the following**:

1. **Verification record** matching the G1/G2 shape — execution table, brainstorm
   resolutions, watch-items, drift events, carry-forwards.
2. **Quantitative quality delta** — at least one v0.2 hand-written skill
   regenerated via DSPy+GEPA with a measurable quality improvement documented (or
   an honest no-delta finding, including a follow-up analysis of why).
3. **End-to-end demo** — one complete agent task run end-to-end with
   DSPy+GEPA-compiled prompts, with the documented trace stored in the
   verification record's appendix.
4. **Switch-validation (from Q1)** — one compilation cycle on **Anthropic** before
   closure (blocks on Anthropic key acquisition).

---

## Sequencing implications (for the future operator)

- The **v0.2.5 plan doc PR may now open**, referencing this brainstorm doc as its
  source of truth.
- v0.2.5 task PRs execute per the ADR-011 cadence (**~12-16 tasks** estimated:
  ~2 SAFETY-CRITICAL substrate, ~6 core integration, ~3 carry-forward, ~3
  validation/closure).
- v0.2.5 closure (verification record per Q8) follows the G1/G2 closure pattern.
- After v0.2.5 closes, **Wave 1 (F.3 Cloud Posture v0.2) opens.**

---

## What this doc IS / IS NOT

**IS:** the canonical, committed record of the 8 locked v0.2.5 brainstorm
resolutions; the source of truth the v0.2.5 plan doc draws from; an honest
disclosure of the ADR-011 cadence gap that produced it.

**IS NOT:** a plan doc (the plan doc is the next artifact, PR #176-shape); a code
change; an ADR amendment (ADR-006 DeepSeek + ADR-007 v1.5 land **inside** v0.2.5,
not here).
