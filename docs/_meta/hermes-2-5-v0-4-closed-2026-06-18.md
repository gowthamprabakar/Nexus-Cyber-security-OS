# Hermes Phases 2–5 — v0.4 Stage 2 close record

_2026-06-18 · DSPy skill-improvement meta-harness · Hermes Phase 1 (v0.3) → Phases 2/4/5 (v0.4)_

## Scope delivered (operator Q1: Phases 4 + 2 + 5 in v0.4; Phase 3 → v0.5)

| Phase    | What                                                                                         | PR         |
| -------- | -------------------------------------------------------------------------------------------- | ---------- |
| **4a**   | T2 trace persistence substrate — charter `SkillTraceStore` + ADR-021 (per-PR review)         | #752       |
| **4a-2** | meta-harness record-at-deploy + `build_compilation_trainset_from_store` (the GEPA un-starve) | #753       |
| **4b**   | cadence activation + Gate 3 formal flip-criterion (`dspy_flip_gate`)                         | #754       |
| **2**    | LLM-judge adjudication, additive above the pass-rate floor (`skill_judge`)                   | #755       |
| **5**    | skill deprecation dual-trigger + sunset (`skill_deprecation`)                                | #756       |
| **3**    | cross-agent skill sharing                                                                    | **→ v0.5** |

## The load-bearing unblock (T2)

Before T2, every compilation assembled a 1-example trainset (the current trigger's brand-new,
always-unscored skill, which the Q5-a pre-filter correctly drops) → GEPA produced no signal →
flipping `NEXUS_DSPY_PRODUCTION` was pointless. Phase 4a persisted each deployed skill's
**originating trace** (`compose_skill_prompt(trigger)`) keyed `(agent_id, skill_id)` over the
SemanticStore entities table (entity_type `skill_trace`, no migration — ADR-021 Option A); Phase
4a-2 wired record-at-deploy + a from-store trainset builder. Multi-example trainsets are now real.

## Flag posture — no production by faith (Q2/Q5)

`NEXUS_DSPY_PRODUCTION` stays **default-OFF** in v0.4. Gate 3 (`dspy_flip_gate`) codifies _when_
a flip is authorized as a pure evidence-in/verdict-out evaluation — four criteria, all must hold:
Gate 1 T2 (✅ met), Gate 2 volume cadence (✅ met), **Gate 3 measured GEPA delta ≥ 0.05 over ≥ 3
agents (❌ not met — no measurement run yet)**, Task-14 Anthropic validation (❌ not met). Default
evidence → NOT AUTHORIZED. The flip remains a separate operator go.

The LLM-judge (Phase 2) has its own `NEXUS_DSPY_LLM_JUDGE` flag (also default-OFF), a no-op
unless the DSPy path is itself enabled.

## Design invariants held

- **Pass-rate stays the hard floor (Q4).** The LLM-judge is consulted _only_ on a pass-rate tie
  and can shift _only_ toward DSPy — never demotes a winner, never rescues a regression. Reuses
  the canonical `nexus_runtime.llm_invariants` (`assert_categorical_only` + `assert_bounded_retry`);
  any error/unparseable/contract-violation → abstain (legacy default).
- **Deprecation is advisory.** Dual-trigger (time `STALE_AGE` OR performance `LOW_EFFECTIVENESS`)
  - 14d sunset → EXPIRED recommendation. Never auto-archives (mirrors F.6 no-auto-repair + A.1
    default-recommend). Age anchored to first-observation (honest lower bound).
- **Substrate discipline.** Only Phase 4a touched substrate (charter.memory) → ADR-021 +
  per-PR review (#752). Phases 4a-2/4b/2/5 are seal-empty consumer/leaf code, self-merged.

## Verification

Touched packages green together: meta-harness + charter `test_skill_trace` + runtime — 748 pass
/ 2 skip (live DSPy/pipeline tests gated). ruff + mypy clean. Each PR's CI `python-tests` (full
repo, `--all-extras`) passed. (Local-only: pruned dev-extras like `respx` make some other
packages' tests uncollectable locally — environmental, not a code regression.)

## Carried to v0.5

- Phase 3 cross-agent skill sharing.
- A measurement run to feed Gate 3 `FlipEvidence.measured_quality_delta` + Task-14 Anthropic
  validation → then the operator decides the flip.
- T2 native table (vs the entities-API Option A); persisted deploy timestamp for deprecation age.
