# Hermes Phase 4b — cadence activation + Gate 3 formal flip-criterion

_2026-06-18 · v0.4 Stage 2 · self-merge (no substrate touch)_

## What shipped

1. **Compilation cadence — activated (un-starved).** The
   `CompilationCadenceController` (v0.2.5 Task 7a) has been live since v0.2.5 but _starved_:
   every compilation could only assemble a 1-example trainset, so it produced no GEPA signal.
   Phase 4a / 4a-2 (#752, #753) shipped T2 trace persistence + the record-at-deploy /
   trainset-from-store wiring, so the cadence now drives **real multi-example** compilations.
   No new cadence code was needed — the controller was complete; T2 made it load-bearing.
   The cadence remains the v0.3 design: event-driven (effectiveness-drop / skill-threshold /
   manual) + lazy weekly cron, **no background daemon**.

2. **Gate 3 — formal flip-criterion** (`meta_harness/dspy_flip_gate.py`). A pure, evidence-in
   / verdict-out evaluation of _when an operator may flip_ `NEXUS_DSPY_PRODUCTION=1`. It never
   reads or mutates the env flag and never flips anything — it exists so the flip is decided
   against measured evidence, not faith.

## The flip criteria (all must hold)

| Gate                                      | Criterion                                                                             | Status (2026-06-18)                     |
| ----------------------------------------- | ------------------------------------------------------------------------------------- | --------------------------------------- |
| **Gate 1 — T2 trace persistence**         | `SkillTraceStore` + record-at-deploy + trainset-from-store                            | ✅ met (#752/#753)                      |
| **Gate 2 — volume cadence live**          | `CompilationCadenceController` wired                                                  | ✅ met (v0.2.5 Task 7a)                 |
| **Gate 3 — measured GEPA quality delta**  | measured eval-gate delta ≥ `0.05` over ≥ `3` agents from real multi-example trainsets | ❌ **not met** — no measurement run yet |
| **Task-14 — Anthropic switch-validation** | operator-recorded provider validation                                                 | ❌ not met                              |

`evaluate_flip_readiness()` with default evidence returns **NOT AUTHORIZED** — absence of
measurement is not permission. `render_flip_status_markdown()` produces the operator-facing
status report (the capability the v0.4 directive asked for).

## Why the flag stays default-OFF

Per the operator's v0.4 answers (Q2 / Q5): ship the **capability**, keep
`NEXUS_DSPY_PRODUCTION` default-OFF, and treat the flip as a **separate operator go** once
Gate 3 (a measured delta) and Task-14 (Anthropic validation) are satisfied. This is the
no-production-by-faith rule made executable: the gate refuses to authorize today, and will
keep refusing until a measurement run records a real delta. Gate 3 is intentionally **separate
from the flag default** (Q5) — the default-OFF posture is unconditional in v0.4; the gate
governs the _future_ flip.

## Next (out of scope here)

- A measurement run that compiles against real multi-example trainsets and records the delta →
  feeds `FlipEvidence.measured_quality_delta` / `measured_delta_agent_count`.
- Task-14 Anthropic switch-validation (operator).
- When both land, `evaluate_flip_readiness(...)` flips to AUTHORIZED — and the operator decides.
