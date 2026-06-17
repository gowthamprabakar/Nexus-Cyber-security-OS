# Hermes Phases 2-5 — v0.4 Stage 2 brainstorm (DSPy skill-improvement meta-harness)

**Date:** 2026-06-18 · **Stage:** 2 (closure workstream, after D.10 + D.11) · **Status:** FOR OPERATOR REVIEW
Hermes = the self-improving skill loop on the A.4 meta-harness. **Phase 1 (skill _proposal_) shipped in v0.3** (C-2/C-3 verified, #703). This brainstorm maps Phases 2-5.

## 1. Where Phase 1 left us (recon, 2026-06-18)

The DSPy machinery is **built and live but default-OFF** (`NEXUS_DSPY_PRODUCTION` unset):

- `charter/dspy_compiler.py` — `DSPyCompiler` (provider-agnostic GEPA bridge, ADR-006). **Substrate.**
- `meta_harness/gepa_adapter.py` — `GEPAMetricAdapter` (G1 effectiveness → GEPA metric).
- `meta_harness/dspy_skill_creator.py` — DSPy Stage-7 composer + `adjudicate_pass_rates` (deterministic: DSPy wins only if it _strictly_ beats legacy).
- `meta_harness/compilation_cadence.py` — `CompilationCadenceController` (event-driven + cron; Gate 2 volume cadence **live**).
- A.4 `agent.py` — 8-stage pipeline; Stages 6-7 (skill trigger/create) gated default-OFF.

**The load-bearing blocker:** **T2 trace persistence is NOT built.** Deployed `Skill`s carry only a provenance hash, not their originating traces → every compilation gets a 1-example trainset → GEPA produces no optimization signal (A.4 v0.2.5 quality-delta doc measured ~0 delta). Until T2 exists, flipping the production flag is pointless. Secondary gates: **Gate 3** (quality cadence, deferred from v0.2.5) + **Task-14** (Anthropic switch-validation).

## 2. Phase map (operator framing) vs current state

| Phase | Operator framing                               | Current state                                                                                    | Net-new work                                                                                                                                                                                                                       |
| ----- | ---------------------------------------------- | ------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **2** | Adjudication eval framework (Anthropic-style)  | Adjudication is a **deterministic pass-rate comparator** (`adjudicate_pass_rates`); no LLM-judge | Add an **LLM-judge** adjudication layer (rubric-scored skill quality) _above_ the pass-rate floor; reuse `charter.llm` + the hoisted LLM invariants (categorical_only / bounded_retry)                                             |
| **3** | Cross-agent skill sharing                      | Skills are per-agent (proposed by D.7/D.12/D.13, deployed per target)                            | A cross-agent **skill registry** query + a **portability adjudication** ("does skill X, proposed on agent A, apply to agent B?") before cross-deploy                                                                               |
| **4** | T2 trace persistence + DSPy cadence activation | T2 **not built**; cadence controller live but starved; flag default-OFF                          | **Build T2** (persist originating traces with `Skill` entities in SemanticStore — likely a charter.memory model change → **substrate**); assemble multi-example trainsets; then **activate** the cadence + flip the flag behind it |
| **5** | Skill deprecation + lifecycle                  | Skills deploy + score (G1 effectiveness); no deprecation path                                    | Effectiveness-driven **deprecation/prune** (stale + low-G1 skills retired), closing the create→measure→retire lifecycle                                                                                                            |

## 3. Proposed v0.4 sequencing (DEPTH-FIRST)

**Phase 4 first — it's the unblock.** Without T2, Phases 2/3 optimize nothing. Recommend:

1. **Phase 4a — T2 trace persistence** (substrate: SemanticStore `Skill`↔`Trace` model + trainset assembly). Per-PR review (touches charter.memory).
2. **Phase 4b — cadence activation** behind the existing controller; flip `NEXUS_DSPY_PRODUCTION` **only after** a real multi-example trainset produces a measurable GEPA delta (else stays OFF — honest). Gate 3 quality cadence added here.
3. **Phase 2 — LLM-judge adjudication** (net-new eval layer; pass-rate stays the safety floor, judge adds qualitative ranking).
4. **Phase 5 — deprecation/lifecycle** (effectiveness-threshold retire).
5. **Phase 3 — cross-agent sharing** (the most speculative; portability-safety heavy) → consider **v0.5** unless you want it in v0.4.

Rationale: 4 unblocks the loop; 2 raises adjudication quality; 5 closes the lifecycle; 3 is the riskiest (cross-agent skill bleed) and benefits from a working single-agent loop first.

## 4. Swiss bar

Real backends (DSPy gated behind `NEXUS_DSPY_PRODUCTION` + the optional-dep contract — no top-level `import dspy`); real e2e through an in-memory SemanticStore for T2; LLM-judge behind `charter.llm` with the categorical_only/bounded_retry invariants; **no auto-flip** of the production flag without a measured delta (the honesty gate). T2 is the one **substrate** touch (charter.memory) → ADR + per-PR review; everything else seal-empty.

## 5. Open questions for the operator (Q-set)

- **Q1 — v0.4 phase scope.** _Rec: Phase 4 (T2 + cadence) + Phase 2 (LLM-judge) + Phase 5 (deprecation) in v0.4; Phase 3 (cross-agent sharing) → v0.5._ Or all four in v0.4?
- **Q2 — production-flag flip.** After T2 + a measured GEPA delta, do we **flip `NEXUS_DSPY_PRODUCTION=1`** (per-tenant gated) in v0.4, or keep default-OFF pending Task-14 Anthropic validation? _Rec: keep default-OFF; ship the capability + the measured-delta report; flip is a separate operator go._
- **Q3 — T2 substrate.** T2 needs a `Skill`↔originating-`Trace` model in `charter.memory` (a substrate change → ADR + per-PR review). Confirm OK to touch the substrate for T2 (it's the only way to un-starve GEPA).
- **Q4 — Phase 2 adjudication shape.** LLM-judge as an **additional** gate above the deterministic pass-rate floor (pass-rate still required; judge ranks ties / adds rubric), or replace pass-rate? _Rec: additive — pass-rate stays the hard floor._
- **Q5 — Gate 3 quality cadence.** Activate the quality-threshold compile trigger in Phase 4b? _Rec: yes, alongside the volume cadence._
- **Q6 — Phase 5 deprecation.** Effectiveness-threshold **auto-deprecate** (with audit) vs **operator-gated** retire? _Rec: auto-flag + operator-gated retire (safety default, mirrors A.1)._
- **Q7 — multi-cloud-posture rename number** (parallel side task). The directive delegated "pick a clean number"; the catalogue self-contradicts. With compliance → **D.9** (you specified) and AppSec already **D.14**, the freed slots are **D.6** (compliance vacates) — \*Rec: multi-cloud-posture → **D.6\***. Confirm, or name another. (Compliance D.6→D.9 ships now as a light self-merge PR; MCP waits on this pick.)
- **Q8 — review mode.** _Rec: per-PR review on the T2 substrate PR (Phase 4a); self-merge cascade for the rest._

## 6. Non-goals (v0.4)

- Auto-flipping the production flag without a measured delta (honesty gate).
- Cross-agent skill sharing (Phase 3) if Q1 defers it to v0.5.
- Replacing the deterministic pass-rate floor (Q4 keeps it).
- Background daemon for the cadence (stays event-driven + lazy-cron, the v0.3 design).
