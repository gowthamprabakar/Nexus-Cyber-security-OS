# A.4 Meta-Harness v0.2.5 — Verification Record + Closure (Task 15, Q8 #1)

- **Date:** 2026-06-07
- **Cycle:** A.4 Meta-Harness v0.2.5 — skill optimization (DSPy + GEPA)
- **Plan:** [`2026-05-31-a-4-meta-harness-v0-2-5.md`](../superpowers/plans/2026-05-31-a-4-meta-harness-v0-2-5.md) (PR #225)
- **Brainstorm:** [`2026-05-30-v0-2-5-skill-optimization-brainstorm.md`](../superpowers/brainstorms/2026-05-30-v0-2-5-skill-optimization-brainstorm.md) (PR #224)
- **Closure status:** **CLOSED structurally** — 13/15 plan tasks shipped + 2 bonus PRs; **Task 14 deferred to v0.3** (documented deviation, §8); `NEXUS_DSPY_PRODUCTION` default-OFF.

---

## 1. Summary + closure status

v0.2.5 delivered a **production-ready, default-OFF** DSPy + GEPA skill-optimization pipeline for A.4 Meta-Harness: a provider-agnostic `charter.dspy_compiler` substrate, a G1-effectiveness GEPA metric adapter, a Stage-7 parallel composer with eval-gate adjudication, a hybrid compilation cadence with per-agent locking, and a candidate factory wiring it together behind the `NEXUS_DSPY_PRODUCTION` flag — with CF #2 graceful-degradation throughout and the full pipeline verified end-to-end against real DeepSeek.

**Closed structurally**, with two honest boundaries documented in this record:

- **Architecture is sound and verified; optimization _quality_ is not yet realized.** The pipeline produces no measurable quality delta today (drift #10 + T2 — §5, §8, [Task 12 report](a-4-meta-harness-v0-2-5-quality-delta-2026-06-07.md)).
- **Task 14 (Anthropic switch-validation), which the plan named a closure blocker, is consciously deferred to v0.3** on operator-acknowledged key-access grounds (§8).

The flag stays **default-OFF**; three v0.3 gates govern the eventual flip (§10).

**Headline metrics:** 14 PRs (#226–#239), all 5 CI checks green per PR; meta-harness suite **664 passed / 2 skipped**, charter suite **277 passed / 8 skipped**; substrate seal honored (WI-1); **13 drift events**, every one surfaced **before** the work it corrected shipped.

---

## 2. Execution table (Axis 1)

| PR       | Plan task                              | Merge SHA | Risk                | Note                                                  |
| -------- | -------------------------------------- | --------- | ------------------- | ----------------------------------------------------- |
| #226     | T1 — bootstrap                         | `deee960` | LOW                 | version bump + `[dspy]` optional group                |
| #227     | T2 — `charter.dspy_compiler` substrate | `939b95f` | **SAFETY-CRITICAL** | charter substrate (WI-1 trip by design)               |
| #228     | T3 — ADR-006/007 amendments            | `59e2249` | **SAFETY-CRITICAL** | substrate-doc (DeepSeek + v1.6 shape)                 |
| #229     | T4 — `gepa_adapter`                    | `b1b2051` | LOW                 | **also absorbs plan T8** (operator-notes cache, Q5-c) |
| #230     | T5 — Stage-7 parallel composer         | `5d3b80a` | LOW                 | incl. drift #1, #2, #4 corrections                    |
| **#231** | **BONUS** — charter LM-binding         | `e4e3799` | **SAFETY-CRITICAL** | drift #3 (β-2 separate PR)                            |
| #232     | T6 — eval-gate adjudication            | `433bea6` | LOW                 | drift #5 correction                                   |
| #233     | T7a — compilation cadence              | `ad874ca` | LOW                 | drift #6 split                                        |
| #234     | T7b — factory + live pipeline          | `a95e32f` | LOW                 | drift #7; **absorbs plan T9** (CF #2 integ / WI-5)    |
| **#235** | **BONUS** — drift #8 fix               | `54c264c` | LOW                 | test-only budget cap                                  |
| #236     | **plan T10** — G1-CF4 CF #2 retrofit   | `6fb1a05` | LOW                 | PR-stream labelled "T9" (numbering drift, §6)         |
| #237     | T11 — NLAH byte-identity guard         | `f5e1e25` | LOW                 | carry-forward Item 15 / G2-WI-6                       |
| #238     | T12 — quality-delta report             | `6d27c98` | LOW                 | doc; Q8 #2; drift #9, #10                             |
| #239     | T13 — end-to-end demo runbook          | `fa6128f` | LOW                 | doc; Q8 #3; drift #11                                 |

**12 plan-task PRs + 2 bonus.** Sequential #226–#239, no gaps (#225 = the plan-doc PR). **Plan T8 + T9 shipped without separate PRs** (absorbed by T4 + T7b — §6). **T14 deferred** (no PR; §8). **T15 = this record** (PR #240).

---

## 3. Brainstorm resolution recap (Q1–Q8)

| Q   | Lock                                                                          | Cycle outcome                                                               |
| --- | ----------------------------------------------------------------------------- | --------------------------------------------------------------------------- |
| Q1  | DeepSeek dev/test; Anthropic prod target                                      | ✅ DeepSeek validated end-to-end; Anthropic switch (T14) → v0.3             |
| Q2  | GEPA `auto="medium"`; bounded budget for tests                                | ✅ default in `dspy_compiler`; tests capped (drift #8)                      |
| Q3  | Stage-7 parallel composer; legacy = CF #2 fallback                            | ✅ Tasks 5/6; default-OFF keeps legacy primary                              |
| Q4  | Hybrid cadence (event + weekly cron) + per-agent lock                         | ✅ Task 7a                                                                  |
| Q5  | metric: (a) skip None/zero-conf, (b) modulate `score×conf`, (c) reflect notes | ✅ Task 4; (a)/(c) mechanism-corrected (drifts #1/#2); see drift #10 caveat |
| Q6  | single-tenant only (no per-customer)                                          | ✅ WI-6 (§4)                                                                |
| Q7  | carry-forward triage (15 items)                                               | ✅ §6                                                                       |
| Q8  | closure criteria (record / delta / demo / Anthropic)                          | ◐ #1/#2/#3 met; #4 (Anthropic) deferred (§8)                                |

---

## 4. Work-item invariants WI-1…WI-8 (Axis 4)

> **⚠️ Namespace disambiguation (drift #13).** The **plan's WI-1…WI-8** are _work-item invariants for this cycle_. They are a **different namespace** from the **carry-forward "WI" items** (e.g. **G2-WI-6** = the NLAH byte-identity guard, carry-forward Item 15, landed in #237). In particular **plan-WI-6 = "single-tenant compilation" ≠ G2-WI-6 (NLAH guard)**. Do not conflate them.

| WI (plan) | Definition                                                          | Status + evidence                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| --------- | ------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| WI-1      | Substrate seal except T2/T3                                         | ✅ `git diff origin/main -- packages/charter/ packages/shared/` empty on every non-substrate PR; tripped **by design** on #227/#228/#231 (the seal working). `shared/` untouched all cycle.                                                                                                                                                                                                                                                                               |
| WI-2      | 25-case G1/G2 eval suite, no regression                             | ✅ full suite green throughout; 25 eval cases intact.                                                                                                                                                                                                                                                                                                                                                                                                                     |
| WI-3      | DSPy deterministic in tests (stub + seed; real only in integration) | ✅ offline tests use fakes/seed; live tests gated behind `NEXUS_LIVE_DSPY=1`.                                                                                                                                                                                                                                                                                                                                                                                             |
| WI-4      | Backwards-compat; legacy path always available                      | ✅ default-OFF → legacy-only unchanged; Q3 parallel composer.                                                                                                                                                                                                                                                                                                                                                                                                             |
| WI-5      | CF #2 — DSPy failure never crashes Stage 7                          | ✅ Tasks 7b/#236; verified live (1h13m run's Ctrl+C → caught → legacy).                                                                                                                                                                                                                                                                                                                                                                                                   |
| WI-6      | **Single-tenant compilation** (no per-tenant surface)               | ✅ in substance — `grep tenant` across the compile modules surfaces **only** the inherited `tenant_id="default"` (from G1's `get_effectiveness_score`); **no non-default tenant literal; no per-customer branching**. _Caveat:_ the compile surfaces _carry_ a `tenant_id="default"` default-arg (inherited), so the plan's stricter "no `tenant_id` parameter" phrasing is imprecise — the invariant (single-tenant, default-only) holds; the no-param reading does not. |
| WI-7      | Operator approval gate preserved (first-of-class)                   | ✅ `skill_lifecycle` deploy path unchanged (`decide_auto_deployable` + notification).                                                                                                                                                                                                                                                                                                                                                                                     |
| WI-8      | Leaf-module discipline (`gepa_adapter` imports)                     | ✅ enforced by the leaf-discipline tests; Task 9 kept its CF #2 emit local.                                                                                                                                                                                                                                                                                                                                                                                               |

---

## 5. Drift events #1–#13 (Axis 2)

Every drift was surfaced **before** the work it corrected shipped — the cycle's investigate → surface → operator-decide → implement discipline. Kind tags: **[M]** empirical mechanism/architecture · **[D]** directive-assumption correction · **[T]** resource/test tuning.

| #   | Kind | Assumed                                        | Empirical reality                                                                                                                | Caught by             | Level       | Correction (layer)                              | Intent        | PR        |
| --- | ---- | ---------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- | --------------------- | ----------- | ----------------------------------------------- | ------------- | --------- |
| 1   | M    | Q5-a "skip" = adapter returns `None`           | `None` crashes GEPA (`int + None`)                                                                                               | offline spike         | pre-impl    | pre-filter trainset (adapter)                   | ✅            | #230      |
| 2   | M    | reflect = return `tuple[float,str]`            | tuple crashes DSPy evaluator                                                                                                     | live run #1           | pre-merge   | `ScoreWithFeedback` (adapter)                   | ✅            | #230      |
| 3   | M    | compiled program stays invocable               | LM lost after `compile()` (transient ctx)                                                                                        | live run #2           | pre-merge   | `compiled.set_lm` (charter)                     | ✅            | #231      |
| 4   | T    | read LM via `compiled.extract.lm`              | `extract` is ChainOfThought; LM on leaf                                                                                          | live run #3           | pre-merge   | `named_predictors()` (test)                     | n/a           | #230      |
| 5   | D    | `eval_gate.score(skill_md).global_score`       | gate is async, `SkillCandidate`-based, yields `candidate_pass_rate`                                                              | investigation         | pre-impl    | use `candidate_pass_rate`                       | ✅            | #232      |
| 6   | D    | Task 7 is one task                             | needs split (decision logic vs live wiring)                                                                                      | investigation         | pre-impl    | 7a / 7b split                                   | ✅            | #233/#234 |
| 7   | M    | factory ≈ "flip the stub"                      | overlay-isolation + no trainset source                                                                                           | investigation         | pre-impl    | R1 winner-restore + T2 + default-OFF            | ◐ (T2 caveat) | #234      |
| 8   | T    | live test inherits default GEPA budget         | ~5h vs ~5-7min                                                                                                                   | live run              | pre-closure | `max_metric_calls=10` (test)                    | n/a           | #235      |
| 9   | D    | a static v0.2 hand-written skill corpus exists | A.4 generates skills at runtime (`nlah/skills/` empty)                                                                           | investigation         | pre-impl    | methodology reframe (legacy-vs-DSPy on a trace) | ✅            | #238      |
| 10  | M    | GEPA metric optimizes the produced skill       | metric returns **stored** G1 effectiveness by `skill_id`, **ignores `prediction`** → no within-run gradient (`0.72 = 0.80×0.90`) | Task 12 analysis      | pre-closure | documented; v0.3 prediction-sensitive reward    | ◐ (deferred)  | #238      |
| 11  | D    | demo = export-flag/seed/verify-chain steps     | live test is self-contained; one command                                                                                         | drafting              | pre-impl    | runbook to runnable reality                     | ✅            | #239      |
| 12  | D    | guessed WI-1…WI-8 meanings                     | 5/8 wrong vs plan-doc                                                                                                            | Task 15 investigation | pre-impl    | use plan's actual WIs (§4)                      | ✅            | #240      |
| 13  | D    | one "WI-6"                                     | plan-WI-6 (single-tenant) ≠ G2-WI-6 (NLAH guard)                                                                                 | Task 15 investigation | pre-impl    | namespace disambiguation (§4)                   | ✅            | #240      |

**Pattern:** 8 caught pre-implementation, 3 pre-merge (live runs), 2 pre-closure. No drift reached production. Drifts #7 and #10 are the two with non-full intent preservation — both consciously deferred to v0.3 with documented unblock paths (§10).

---

## 6. Q7 carry-forward closure mapping (Axis 3)

**Numbering drift (documented).** The PR-stream task numbers drifted +1 from the plan doc because **plan T8 (operator-notes cache) was absorbed by T4** and **plan T9 (CF #2 integration / WI-5) was absorbed by T7b** — so the PR-stream "Task 9" (#236) is **plan-doc Task 10 (G1-CF4)**. This record uses **plan-doc** numbers.

**Landed (Q7 LAND items):**

- **Item 1 / G1-CF4** (CF #2 retrofit to `skill_lifecycle._safely` helpers) → **#236**.
- **Item 2 / G1-CF8** (DSPy+GEPA core mission — wire G1 metric into GEPA) → **Tasks 4–9 core** (#229, #230, #232, #233, #234; + absorbed T8/T9).
- **Item 15 / G2-WI-6** (NLAH byte-identity guard) → **#237**.

**Deferred by design (brainstorm Items 3–14):** per-agent weight tuning (3, v0.3) · scheduled aggregation (4, v0.3 Curator) · per-tenant isolation (5, blocked on SET LOCAL) · pruning (6, Curator) · UI dashboard (7, Phase-2) · cross-agent comparison (8, Curator) · selection dispatcher (9) · `skill.selected` audit (10) · per-tool-call granularity (11) · cross-agent compositional selection (12) · embeddings (13, not-built/Hermes) · RAG/vector store (14, not-built/Hermes). All retain their brainstorm destinations.

**New v0.3 carry-forwards surfaced this cycle (3):** see §10.

No G1/G2 carry-forward item is left unmapped.

---

## 7. Cross-agent regression sweep (Axis 6)

Methodology (plan line 111): the meta-harness 25-case suite + each **touched** agent's suite; full cross-agent dependency graph is explicitly a v0.3 consideration.

- **Packages touched this cycle** (`git diff deee960^1..origin/main`): **only** `packages/agents/meta-harness/`, `packages/charter/` (`dspy_compiler.py` + test), and `docs/`. **No other `packages/agents/*` changed** — the NLAH guard (#237) _reads_ the 17 personas, it does not edit them. `packages/shared/` untouched.
- **meta-harness suite:** 664 passed / 2 skipped (the 2 = gated live tests).
- **charter suite:** 277 passed / 8 skipped.
- **Conclusion:** no other agent could regress because none was modified; the two touched packages are green. Cross-agent isolation holds.

---

## 8. Q8 acceptance + Task-14 deferral deviation (Axis 5)

| Q8 req                               | Artifact                                                                     | Status               |
| ------------------------------------ | ---------------------------------------------------------------------------- | -------------------- |
| #1 verification record               | this document (PR #240)                                                      | ✅                   |
| #2 quality-delta report              | [Task 12](a-4-meta-harness-v0-2-5-quality-delta-2026-06-07.md) (#238)        | ✅ (honest no-delta) |
| #3 end-to-end demo                   | [Task 13 runbook](a-4-meta-harness-v0-2-5-demo-runbook-2026-06-07.md) (#239) | ✅                   |
| #4 Anthropic switch-validation (T14) | —                                                                            | **DEFERRED → v0.3**  |

**Documented deviation (operator-acknowledged).** The plan's Q8 and Task 14 state Anthropic switch-validation **"BLOCKS CLOSURE on Anthropic key acquisition."** The operator has **consciously deferred Task 14 to v0.3** on key-access grounds. v0.2.5 therefore closes **structurally**, with this deviation recorded explicitly — _not_ a silent skip. Rationale: (a) the Anthropic key is not accessible near-term; (b) drift #10 makes optimization-quality readiness a _separate_ v0.3 gate regardless of provider, so Task 14 alone would not unblock the production flag; (c) the architecture ships production-ready behind a default-OFF flag, so deferring provider-switch validation carries no production risk.

---

## 9. Production-rollout decision

- **`NEXUS_DSPY_PRODUCTION` = default-OFF** at v0.2.5 close. Production `skill_lifecycle` runs **legacy-only** unless the flag is set; the factory is wired only by `make_default_dspy_factory` when `NEXUS_DSPY_PRODUCTION=1`.
- **The flag flip is a v0.3 decision**, gated on the three readiness items in §10.

---

## 10. v0.3 carry-forward ledger

**New, from this cycle (the three flag-flip gates):**

1. **Task 14 — Anthropic switch-validation.** One compilation cycle on Anthropic to validate DeepSeek-developed prompts on the prod target. (Provider readiness.)
2. **Drift #10 — prediction-sensitive GEPA reward.** Give GEPA a reward that scores the _produced_ `skill_md` (e.g. eval-gate it), so prompt variants are differentiated — the G1 effectiveness signal cannot serve as the within-run gradient. (Optimization readiness.)
3. **T2 — originating-trace persistence.** Sidecar (e.g. `.nexus/deployed-skills/<agent>/<skill_id>/origin-trace.json`) written at deployment → multi-example trainsets. (Optimization readiness.)

**Carried from the brainstorm (Items 3–14):** v0.3 / v0.3 Curator / Phase-2 Surface / blocked-on-SET-LOCAL / not-built-by-design (Hermes) — per §6.

The §2 A/B harness ([Task 12](a-4-meta-harness-v0-2-5-quality-delta-2026-06-07.md) §8) re-runs verbatim once gates 2 + 3 land; a measurable delta is then expected.

---

## 11. Closure statement

A.4 Meta-Harness **v0.2.5 is CLOSED** (structural, 2026-06-07): a verified, production-ready skill-optimization pipeline shipped behind a default-OFF flag, with honest documentation of the two quality boundaries (drift #10, T2) and the one closure deviation (Task 14 → v0.3). Thirteen drift events were caught and corrected before shipping — the cycle's defining discipline. The production-flag flip and the optimization-quality work are the v0.3 mandate.

---

## Appendices

- **A.** [Task 12 — quality-delta report](a-4-meta-harness-v0-2-5-quality-delta-2026-06-07.md) (#238) — drift #10 + T2 root cause; v0.3 A/B methodology.
- **B.** [Task 13 — demo runbook](a-4-meta-harness-v0-2-5-demo-runbook-2026-06-07.md) (#239) — runnable end-to-end demo.
- **C.** [Plan doc](../superpowers/plans/2026-05-31-a-4-meta-harness-v0-2-5.md) (#225) · [Brainstorm](../superpowers/brainstorms/2026-05-30-v0-2-5-skill-optimization-brainstorm.md) (#224).
- **D.** Foundations: [G1 verification](g1-effectiveness-scoring-verification-2026-05-25.md) · [G2 verification](g2-skill-selection-verification-2026-05-30.md).
