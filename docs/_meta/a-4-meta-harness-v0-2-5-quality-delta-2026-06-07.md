# A.4 Meta-Harness v0.2.5 — Quality-Delta Report (Task 12, Q8 #2)

- **Date:** 2026-06-07
- **Cycle:** A.4 Meta-Harness v0.2.5 (skill optimization — DSPy + GEPA)
- **Task:** 12 — quality-delta measurement (brainstorm Q8 requirement #2)
- **Methodology:** γ-hybrid — honest no-delta finding grounded in the Task 7b live evidence + a reproducible A/B methodology documented for v0.3
- **Role:** appendix to the Task 15 verification record
- **Status:** **empirical no-delta** (within noise); root cause documented; v0.3 unblock path identified

---

## 1. Executive summary

v0.2.5 ships a **production-ready** DSPy + GEPA skill-optimization pipeline (cadence → per-agent lock → compile → eval-gate adjudication → winner persistence, all behind the default-OFF `NEXUS_DSPY_PRODUCTION` flag). On the question Q8 asked — _does a GEPA-compiled skill beat the legacy hand-composed skill?_ — the **honest empirical answer for v0.2.5 is: no measurable delta.**

The no-delta is **not** a defect in the pipeline plumbing (which is verified end-to-end). It has **two documented root causes**, both of which gate _optimization quality_, not _architectural soundness_:

1. **The GEPA metric is prediction-invariant (primary).** Per the Q5 lock, the metric returns the trainset skill's _stored_ G1 effectiveness (`global_score × confidence`), looked up by `skill_id`, and explicitly ignores the GEPA-proposed candidate. So GEPA sees an identical reward for every prompt variant → **no within-run optimization gradient**, independent of trainset size.
2. **The production trainset is 1-example (T2, compounding).** Originating traces are not persisted with deployed skills, so the factory can only assemble a single-example trainset → no diversity even if the metric were prediction-sensitive.

Both are addressable in v0.3 (see §6). v0.2.5 closes with **documented constraint honesty** rather than synthetic numbers.

---

## 2. Methodology

**Baseline corpus note.** A.4 does not ship a static library of hand-written skills (`nlah/skills/` is empty; no committed `SKILL.md` artifacts). Skills are **generated at runtime** from agent traces. So "regenerate a v0.2 hand-written skill" maps to: run the **legacy** composer and the **DSPy** composer on the _same_ trace and compare — exactly the Stage-7 parallel path (Tasks 5/6) exercised live in Task 7b. _(This corpus assumption in the original Task 12 directive was corrected pre-implementation — drift event #9.)_

**Chosen subject.** The **investigation** agent's cross-account `AssumeRole`-chain privilege-escalation trace — the trace used in the Task 5 and Task 7b live runs. Investigation is the only agent driven live this cycle **and** it has a registered real eval runner (`investigation.eval_runner:InvestigationEvalRunner`) plus **10 deterministic eval cases**, so the eval-gate can score candidates reproducibly.

**A/B definition (the intended measurement).**

|           | Baseline                                                             | DSPy candidate                                 |
| --------- | -------------------------------------------------------------------- | ---------------------------------------------- |
| Producer  | legacy single-LLM composer (`write_skill_candidate`)                 | GEPA-compiled composer (`compilation_factory`) |
| Input     | the investigation IAM trace                                          | same trace, same `agent_id`, same `skill_id`   |
| Score     | `candidate_pass_rate` via `run_skill_eval_gate` (Option-B, 10 cases) | same eval-gate                                 |
| **Delta** | —                                                                    | `dspy_pass_rate − legacy_pass_rate`            |

**Reproducible harness:** `InvestigationEvalRunner` + the Task 7b factory + a cadence trigger. This A/B is re-runnable verbatim once v0.3 lands the unblocks in §6.

---

## 3. Empirical measurement (Task 7b live evidence)

Rather than spend a predetermined-outcome live run, this report grounds the finding in the **already-captured** Task 7b operator live run (see PR #234 and its verification comment):

- **Runtime:** 1h 13m (4,439.85 s) before deliberate operator interruption (Ctrl+C).
- **Scale:** **30 GEPA iterations**, ~175 rollouts against real DeepSeek V4 Pro.
- **Cost:** ~$0.07 total (DeepSeek pricing is negligible).
- **GEPA metric across all 30 iterations:** **flat 0.72** — `Average Metric ≈ 2.16 / 3 = 72.0%`, with **zero improvement** iteration-over-iteration.
- **Trainset:** **1 example** (factory logged `single_example_trainset`).
- **CF #2:** the interruption was caught → factory returned `None` → legacy would proceed; lock released cleanly.

The decisive number: **0.72 = 0.80 × 0.90**, i.e. _exactly_ the seeded skill's `global_score (0.80) × confidence (0.90)`. GEPA never moved the metric off the seeded skill's stored effectiveness.

---

## 4. Delta finding

**No measurable quality delta.** GEPA produced **no improvement in its own optimization metric** across 30 iterations — the compiled compositor is, for scoring purposes, indistinguishable from the base compositor. The eval-gate `candidate_pass_rate` A/B (the §2 table) was **not** run live this cycle (the 7b live test exercises the factory, not adjudication); the no-delta conclusion is therefore **inferred** from GEPA's flat metric (a direct, strong signal that no optimization occurred), and the eval-gate A/B is documented as the v0.3 reproducible measurement.

Plainly: with the current metric and a 1-example trainset, the DSPy candidate's quality tracks the legacy baseline; neither is pushed above the seeded 0.72. Any eval-gate pass-rate difference would be **text-variation noise**, not systematic optimization.

---

## 5. Root-cause analysis

### 5.1 Primary — the GEPA metric is prediction-invariant

`GEPAMetricAdapter.__call__` (Q5 lock, `gepa_adapter.py`) computes `modulated = score.global_score * score.confidence` from the trainset skill's **stored** G1 effectiveness (looked up by `skill_id`) and **ignores the `prediction`** GEPA proposes (the docstring is explicit: _"prediction … unused — the metric is the skill's G1 effectiveness, not the prediction's correctness."_).

Consequence: for a fixed trainset, **every** prompt variant GEPA tries yields the **same** reward (each example's historical effectiveness). GEPA's within-run search has **no gradient to climb** → it converges to the base prompt immediately → flat metric. This holds **regardless of trainset size**.

This is a faithful consequence of the Q5 design (effectiveness-as-metric), surfaced empirically — not a plumbing bug. It means within-run GEPA optimization needs a **prediction-sensitive** reward (one that scores the _produced_ `skill_md`, e.g. eval-gating the produced candidate), distinct from the historical-effectiveness label.

### 5.2 Compounding — 1-example trainset (T2)

Even with a prediction-sensitive metric, the production trainset is **1 example**: the current trigger's skill is brand-new (unscored → dropped by the Q5-a pre-filter), and **originating traces are not persisted** with deployed skills, so no multi-example trainset can be assembled. No diversity ⇒ no robust reflective optimization. (Consistent with the Q5-a intent: skills without scored history are excluded from the trainset.)

---

## 6. v0.3 unblock path

To convert this no-delta into a measurable delta, v0.3 should address **both** causes:

1. **Prediction-sensitive optimization reward.** Give GEPA a reward that scores the _produced_ candidate (e.g. eval-gate the produced `skill_md` and use `candidate_pass_rate`), so prompt variants are actually differentiated. Keep the G1 effectiveness signal for cross-cycle selection, but it cannot serve as the within-run gradient.
2. **Persist originating traces.** Sidecar pattern, e.g. `.nexus/deployed-skills/<agent>/<skill_id>/origin-trace.json`, written by `skill_lifecycle` at deployment. Enables multi-example trainsets. _Backfill caveat:_ existing skills have no trace; benefit accrues as new skills deploy.

With both, the §2 A/B harness re-runs unchanged and is expected to show a genuine, measurable delta.

---

## 7. Production-rollout implication

- `NEXUS_DSPY_PRODUCTION` remains **default-OFF**. The architecture is production-ready; _optimization quality_ is gated on the §6 v0.3 work.
- Two independent readiness gates for the flag flip: **provider readiness** (Task 14 Anthropic switch-validation) and **optimization readiness** (v0.3 prediction-sensitive metric + trace persistence). v0.2.5 satisfies neither's quality dimension yet — flipping the flag today would run a verified pipeline that produces no quality improvement at small DeepSeek cost.

---

## 8. Reproducible methodology for v0.3

When §6 lands, re-run the §2 A/B verbatim: legacy-compose and DSPy-compile the investigation IAM trace, eval-gate both via `InvestigationEvalRunner` over its 10 cases, report `dspy_pass_rate − legacy_pass_rate` with per-case breakdown. Expected v0.3 outcome: a measurable delta once GEPA has both a prediction-sensitive reward and a diverse trainset.

---

## Appendix — sources

- Task 7b live evidence: **PR #234** + its verification comment (1h13m / 30 iterations / flat 0.72 / ~$0.07).
- T2 limitation: `compilation_factory.py` module docstring; [v0.2.5 deferred follow-ups memory].
- Q5 metric design: `gepa_adapter.py` (`global_score × confidence`, `prediction` unused).
- Drift events #1–#9: to be consolidated in the Task 15 verification record (this report = #9's pre-implementation correction of the static-corpus assumption).
