# A.4 Meta-Harness v0.2.5 — End-to-End Demo Runbook (Task 13, Q8 #3)

- **Date:** 2026-06-07
- **Cycle:** A.4 Meta-Harness v0.2.5 (skill optimization — DSPy + GEPA)
- **Task:** 13 — end-to-end demo (brainstorm Q8 requirement #3)
- **Audience:** operators, design partners, future v0.3 contributors
- **Provider:** DeepSeek (existing). **Anthropic switch-validation (Task 14) deferred to v0.3.**

---

## 1. Purpose

This runbook walks one runnable demonstration of the v0.2.5 skill-optimization
pipeline end-to-end against **real DeepSeek**: cadence fires → per-agent lock →
DSPy/GEPA compile → a `SkillCandidate` materialised at the canonical shadow path
→ lock released → cadence state advanced, with CF #2 graceful-degradation at
every failure point.

**It proves the architecture and plumbing — not optimization quality.** Per the
Task 12 quality-delta report, GEPA optimization is currently flat (no measurable
delta) for two documented reasons (drift #10: the Q5 metric is prediction-invariant;
T2: 1-example trainsets from missing trace persistence). Both are v0.3 work. This
demo is an **architectural integrity** demonstration; see §4 for the honest
boundary.

---

## 2. Prerequisites

- Repo checked out at the v0.2.5 close commit; working dir = `<repo>/`.
- Python env via `uv` (the repo's toolchain); the `[dspy]` extra installed
  (`uv sync --all-extras --all-packages`).
- A **DeepSeek** API key exported (read only from the env — never committed):

  ```sh
  export NEXUS_LLM_API_KEY=<your-deepseek-key>
  # optional overrides (defaults shown):
  # export NEXUS_LLM_BASE_URL=https://api.deepseek.com/v1
  # export NEXUS_LLM_MODEL_PIN=deepseek-chat
  ```

- **NOT required:** an Anthropic key — Task 14 (Anthropic switch-validation) is
  deferred to v0.3.

---

## 3. Demo sequence — happy path (~5–7 min)

The demo is the **gated live pipeline test**, which is self-contained: it seeds a
scored skill + a manual cadence trigger in a throwaway workspace, builds the
factory, and drives the full path. The GEPA budget is capped to a smoke size
(drift #8) so the run is ~5–7 min, not ~5 h.

**Step 1 — run the live pipeline.**

```sh
NEXUS_LIVE_DSPY=1 NEXUS_LLM_API_KEY=$NEXUS_LLM_API_KEY \
  uv run pytest packages/agents/meta-harness/tests/test_full_pipeline_live.py -v -s
```

(Without `NEXUS_LIVE_DSPY=1` the test **skips** — that's the CI-safe default.)

**Step 2 — observe the result line.** On success you'll see:

```
[LIVE PIPELINE] cadence=manual lock=ok compiled=ok materialized=ok \
  skill_id=iam-privesc/aws_iam_privesc_via_assumed_role duration=<X>s model=deepseek-chat
[LIVE PIPELINE] DSPy SKILL.md (first 400 chars): ...
PASSED
```

This confirms, in order: the manual cadence trigger fired → the per-agent lock
was acquired → a DSPy program compiled against DeepSeek → its output was
materialised into a `SkillCandidate` at the legacy canonical shadow path → the
lock was released and cadence state advanced (the test asserts each).

**Step 3 — observe the structured cadence/factory logs** (with `-s`): lines like
`compilation_cadence.decision`, `compilation_cadence.lock_acquired`,
`compilation_factory.single_example_trainset`, `compilation_factory.candidate_produced`.
The `single_example_trainset` warning is **expected** (T2 — see §4).

> The test runs in a pytest `tmp_path` workspace, so the materialised
> `SKILL.md` + audit entries live under that temp dir for the run's duration; the
> `[LIVE PIPELINE]` line + structured logs are the durable observability surface.

**Step 4 — demonstrate CF #2 fallback (optional).** Unset the key and re-run:

```sh
unset NEXUS_LLM_API_KEY
NEXUS_LIVE_DSPY=1 uv run pytest packages/agents/meta-harness/tests/test_full_pipeline_live.py -v -s
```

The test **skips** (its gate requires the key). To see the _fallback logic_
itself, run the offline factory tests — they assert that a cadence-no / lock-busy
/ empty-trainset / compile-error all return `None` so the legacy path proceeds:

```sh
uv run pytest packages/agents/meta-harness/tests/test_compilation_factory.py -v
```

---

## 4. Honest scope — what this demo does and does not prove

**Proves (architecture + plumbing):**

- Cadence evaluation + per-agent lock (acquire / release / no double-compile).
- DSPy compile against real DeepSeek through the charter-bound LM (PR #231).
- Materialisation of the compiled output into a `SkillCandidate` at the canonical
  path (clean overwrite for apples-to-apples eval).
- CF #2 graceful-degradation: every failure mode returns `None` → legacy proceeds.
- Cadence-state persistence + structured-log observability.

**Does NOT prove (optimization quality — v0.3):**

- That a GEPA-compiled skill **beats** the legacy skill. It currently does not —
  see the [Task 12 quality-delta report](a-4-meta-harness-v0-2-5-quality-delta-2026-06-07.md):
  - **drift #10 (primary):** the Q5 metric returns the trainset skill's _stored_
    G1 effectiveness (`global_score × confidence`) and ignores the GEPA-proposed
    candidate → no within-run gradient → flat metric (the 7b run's `0.72 =
0.80 × 0.90`).
  - **T2 (compounding):** traces aren't persisted → 1-example trainset → no
    diversity.
- A flat GEPA score in the demo is **expected behaviour**, not a demo failure.

---

## 5. Troubleshooting

| Symptom                                               | Cause / action                                                                                                                                                    |
| ----------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Test reports `SKIPPED`                                | `NEXUS_LIVE_DSPY=1` and/or `NEXUS_LLM_API_KEY` not set — set both.                                                                                                |
| `compilation_factory.single_example_trainset` warning | **Expected** (T2). Not a failure.                                                                                                                                 |
| GEPA metric flat across iterations (e.g. `0.72`)      | **Expected** (drift #10). Not a failure — see §4 / Task 12 report.                                                                                                |
| Run takes far longer than ~7 min                      | The drift #8 budget cap (`max_metric_calls=10`) should bound it; check the test still injects the capped budget.                                                  |
| Factory returns `None` in production wiring           | Either `NEXUS_DSPY_PRODUCTION` is unset (default-OFF — see §6) or a CF #2 path fired (cadence-no / lock-busy / empty-trainset / compile-error) → legacy proceeds. |
| `import dspy` errors                                  | The `[dspy]` extra isn't installed — `uv sync --all-extras --all-packages`.                                                                                       |

---

## 6. Production-rollout status

- **`NEXUS_DSPY_PRODUCTION` is default-OFF** at v0.2.5 close. The _demo test_
  builds the factory directly; in **production**, `make_default_dspy_factory`
  wires the factory into `skill_lifecycle` **only** when
  `NEXUS_DSPY_PRODUCTION=1`. Unset → legacy-only, unchanged behaviour.
- **Three gates must clear before the flag flip** (all v0.3):
  1. **Task 14** — Anthropic switch-validation (deferred; provider readiness).
  2. **drift #10** — a prediction-sensitive optimization reward (score the
     produced `skill_md`, e.g. eval-gate it).
  3. **T2** — originating-trace persistence (multi-example trainsets).
- Flipping the flag today would run a **verified pipeline that produces no quality
  improvement** at small DeepSeek cost. v0.3 addresses all three gates, then the
  flip happens.

---

## 7. References

- [Task 12 quality-delta report](a-4-meta-harness-v0-2-5-quality-delta-2026-06-07.md) — drift #10 + T2 root cause.
- **PR #234** (Task 7b) — the factory + live-pipeline test + the 1h13m operator run.
- **PR #231** — charter LM-binding fix (compiled programs stay invocable).
- `packages/agents/meta-harness/tests/test_full_pipeline_live.py` — the demo test.
- `packages/agents/meta-harness/src/meta_harness/compilation_factory.py` — module docstring (rollout + T2).
