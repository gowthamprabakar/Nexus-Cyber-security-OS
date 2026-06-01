# A.4 Meta-Harness v0.2.5 — Skill Optimization Plan

> **For agentic workers:** REQUIRED SUB-SKILL: use `superpowers:subagent-driven-development`
> (recommended) or `superpowers:executing-plans` to implement this plan task-by-task.
> Steps use checkbox (`- [ ]`) syntax. Pause for operator review after each numbered task.

**Date:** 2026-05-31
**Cycle status:** PLANNING
**Label:** LOW-RISK (plan doc; no code; no substrate)

**Goal:** Ship **A.4 v0.2.5 Skill Optimization** — the continuous prompt-optimization
layer. G1 measured (effectiveness scores), G2 selected (LLM picks effective skills
from enriched metadata); **v0.2.5 optimizes** — it compiles agent prompts with DSPy
and evolves them with GEPA, using G1's effectiveness score as the `metric=` GEPA
optimizes against. This closes the third prerequisite gap from the
[Hermes adoption doc](../../_meta/hermes-self-evolution-adoption-2026-05-23.md) §4.1,
the last one before Wave 1 agent v0.2 work can begin.

**Source of truth:** [v0.2.5 Skill Optimization Brainstorm](../brainstorms/2026-05-30-v0-2-5-skill-optimization-brainstorm.md)
(CLOSED, 8/8 questions locked). Every task below traces to a brainstorm resolution.

**References:**

- Brainstorm: [2026-05-30-v0-2-5-skill-optimization-brainstorm.md](../brainstorms/2026-05-30-v0-2-5-skill-optimization-brainstorm.md)
- Foundation closures: [G1 verification record](../../_meta/g1-effectiveness-scoring-verification-2026-05-25.md) · [G2 verification record](../../_meta/g2-skill-selection-verification-2026-05-30.md)
- Strategic: [Hermes absorption](../../_meta/hermes-pattern-absorption-2026-05-22.md) (PR #175) · [DSPy+GEPA optimization](../../_meta/dspy-gepa-prompt-optimization-2026-05-22.md) (PR #181) · [Hermes self-evolution adoption](../../_meta/hermes-self-evolution-adoption-2026-05-23.md) (PR #195)

> **Version note:** the meta-harness package is at **`0.2.2`** on `main` today (not
> `0.2.4`). Task 1's bump is therefore **`0.2.2` → `0.2.5`**.

> **ADR note:** the DeepSeek provider amendment lands in
> [ADR-006 (OpenAI-compatible provider)](../../_meta/decisions/ADR-006-openai-compatible-provider.md) —
> DeepSeek is an OpenAI-compatible endpoint, so ADR-006 is the correct home (the
> strategic docs' "ADR-006-llm-provider-strategy" reference is stale; provider
> _strategy_ is ADR-003).

---

## Architecture overview

```
┌─────────────────────────────────────────────────────────────────────┐
│ A.4 v0.2.5 Skill Optimization                                        │
│                                                                     │
│  charter.dspy_compiler (substrate, Task 2):                         │
│    thin wrapper over DSPy compilation; binds DSPy's dspy.LM to      │
│    charter.llm_adapter (provider-agnostic — anthropic /            │
│    openai-compatible incl. DeepSeek + vLLM). No provider lock-in.   │
│                                                                     │
│  meta_harness.gepa_adapter (consumer, Task 4):                      │
│    wraps G1 get_effectiveness_score() → GEPA metric=               │
│      SKIP   when score None or confidence == 0.0                    │
│      MODULATE  scalar = global_score × confidence                   │
│      REFLECT  reason.value + axes breakdown + operator notes        │
│    CF #2: read failure → audit event → "no metric" → GEPA skips     │
│                                                                     │
│  Stage 7 SKILL_CREATE (meta-harness, Task 5-6):                     │
│    DSPy-compiled compositor  ┐                                      │
│                              ├─ eval-gate scores both → keep winner │
│    legacy single-LLM-call    ┘  (legacy = CF #2 fallback)           │
│                                                                     │
│  Compilation cadence (Task 7):                                      │
│    event (score<0.4 / 10+ new skills / manual CLI) + weekly cron;   │
│    per-agent compile lock; each compile eval-gated before deploy.   │
└─────────────────────────────────────────────────────────────────────┘
```

DSPy programs become the canonical prompt shape (ADR-007 v1.5 amendment, Task 3);
hand-written NLAH prompts remain the fallback and the bootstrap for compilation.

## How the brainstorm resolutions shape this plan

| Resolution                                           | Shapes                                                                                                                   |
| ---------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------ |
| **Q1** DeepSeek dev / Anthropic prod target          | Task 1 (dep group), Task 3 (ADR-006 DeepSeek), Task 14 (Anthropic switch-validation — blocks closure on key acquisition) |
| **Q2** GEPA `auto="medium"`, 50-trial cap            | Task 2 (`dspy_compiler` defaults), Task 7 (per-agent override)                                                           |
| **Q3** Stage 7 parallel composer                     | Task 5 (parallel), Task 6 (eval-gate adjudication), Task 9 (legacy = CF #2 fallback)                                     |
| **Q4** hybrid cadence                                | Task 7 (event + scheduled + per-agent lock)                                                                              |
| **Q5** `gepa_metric` adapter (skip/modulate/reflect) | Task 4 (adapter), Task 8 (operator-notes cache)                                                                          |
| **Q6** single-tenant only                            | WI-6; no per-customer task (deferred to v0.3)                                                                            |
| **Q7** carry-forward triage                          | Task 10 (Item 1 / G1-CF4), Tasks 4-9 (Item 2 / G1-CF8 core), Task 11 (Item 15 / G2-WI-6)                                 |
| **Q8** closure criteria                              | Task 12 (quality delta), Task 13 (e2e demo), Task 14 (Anthropic switch), Task 15 (verification record)                   |

---

## Depends on (prior PRs / cycles)

- **G1** (effectiveness scoring) — `get_effectiveness_score()`, `EffectivenessScore`, the audit vocabulary. CLOSED.
- **G2** (skill selection) — `discover_agent_skills` enrichment, `SkillMetadataEntry` effectiveness fields, 17 personas, 25-case eval suite. CLOSED.
- **A.4 v0.2** — Stage 7 `skill_writer.py`, `skill_eval_gate.py` (Task 8 eval-gate pattern), `skill_registry.py` first-of-class operator gate, CLI.
- **charter.llm_adapter** (ADR-006) — provider-agnostic; `dspy_compiler` binds DSPy to it.

## Defers (explicitly out of scope — Q6 + Q7)

- ❌ **Per-customer / per-tenant compilation** — Q6; blocked on SET LOCAL tenant-RLS substrate fix → v0.3+. No schema work now (would be wasted if the fix changes data shape).
- ❌ **Curator work** (pruning, scheduled aggregation, cross-agent comparison) — Q7 Items 4/6/8 → v0.3 Curator.
- ❌ **Selection dispatcher** + **`skill.selected` audit event** — Q7 Items 9/10 → dedicated agent-runtime cycle / future.
- ❌ **Per-agent weight tuning** — Q7 Item 3 → v0.3.
- ❌ **Embeddings / RAG / vector store** — Q7 Items 13/14, NOT BUILT by design (G2-Q2 Hermes-pattern lock).
- ❌ **No new audit-action constants** — G1's 6-action vocabulary is sufficient (compile failures reuse `meta_harness.skill.effectiveness_error`).

---

## Cross-cutting concerns

1. **DeepSeek API key management.** Key lives in env var `NEXUS_DEEPSEEK_API_KEY` (consumed by `OpenAICompatibleProvider`). CI integration tests read it from a repo secret; unit tests use stub-LLM mode and need no key. **Actual key acquisition is the operator's responsibility.**
2. **Anthropic switch-validation acquisition path.** Task 14 blocks on an Anthropic API key (env `NEXUS_ANTHROPIC_API_KEY`). This is an explicit external dependency and a **closure blocker** — flagged here so it is acquired before the cycle tail.
3. **Dependency footprint.** DSPy + GEPA add ~40 transitive deps ([DSPy+GEPA doc](../../_meta/dspy-gepa-prompt-optimization-2026-05-22.md) §4.4). They install via an **optional-dependency group** (`nexus-meta-harness-agent[dspy]`) so substrate and non-A.4 agents do not inherit the footprint. `charter.dspy_compiler` imports DSPy lazily and degrades cleanly when the extra is absent.
4. **Compilation cost projection.** ~$15-35/month at DeepSeek pricing for 17 agents on weekly cadence (Q2). Documented for budget visibility; far below the ~$340-850/month Anthropic estimate.
5. **GEPA reproducibility.** `dspy_compiler` accepts a `seed` so compilation is reproducible in tests ([DSPy+GEPA doc](../../_meta/dspy-gepa-prompt-optimization-2026-05-22.md) §6 Risk 3). Unit tests run stub-LLM + fixed seed for byte-stability (WI-3).
6. **Cross-agent compilation coordination.** When one agent's prompts change, no downstream agent's eval suite may regress. Mechanism: Task 6's eval-gate runs the **target agent's** suite; the v0.2.5 verification record (Task 15) records a cross-agent regression sweep over the 25-case meta-harness suite + each touched agent's suite. (Full cross-agent dependency graph is out of scope; documented as a v0.3 consideration.)
7. **Carry-forward gap audit.** Each Q7 LAND item maps to a task: **Item 1 (G1-CF4) → Task 10**; **Item 2 (G1-CF8) → Tasks 4-9 (core)**; **Item 15 (G2-WI-6) → Task 11**. Task 15 (verification record) re-audits this mapping at closure.

---

## Risks

- **R1 — DSPy/GEPA dependency surface.** ~40 transitive deps. Mitigation: optional-dependency group; lazy import; `dspy_compiler` is a thin seam (Task 2).
- **R2 — Compiled prompts behave differently on Anthropic vs DeepSeek.** Mitigation: Task 14 switch-validation is a hard closure gate.
- **R3 — DSPy compilation non-determinism in tests.** Mitigation: stub-LLM + seed (WI-3); real-provider runs are integration-only.
- **R4 — Compilation failure breaks Stage 7.** Mitigation: parallel composer; legacy path is the CF #2 fallback (Tasks 5/9, WI-5).
- **R5 — GEPA metric mismatch with G1 API.** Mitigation: explicit adapter (Task 4) per the Q5 ground-truth verification; not a direct slot-in.
- **R6 — Substrate bloat.** Mitigation: only Tasks 2-3 touch `packages/charter/`; WI-1 seal everywhere else.

---

## Tasks 1-15

### Milestone 1 — Bootstrap + ADRs (~3 tasks, mixed risk)

| Task | Risk                | Title                                                            | Description                                                                                                                                                                                                                                                                                                                                                       |
| ---- | ------------------- | ---------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Plan | —                   | v0.2.5 plan doc                                                  | This document. Merged as LOW-RISK doc-only PR.                                                                                                                                                                                                                                                                                                                    |
| 1    | LOW-RISK            | Bootstrap v0.2.5 — version bump + dependency group + smoke tests | Bump `0.2.2` → `0.2.5` in `pyproject.toml`. Add DSPy + GEPA under optional group `[project.optional-dependencies] dspy = [...]`. Smoke tests: v0.2.5 imports, 25 eval cases still load (no regression), lazy-import probe (package imports without the `dspy` extra), import-linter rule for `gepa_adapter` leaf discipline. ~12 smoke tests.                     |
| 2    | **SAFETY-CRITICAL** | `charter.dspy_compiler` substrate module                         | Thin wrapper over DSPy compilation. Binds `dspy.LM` to `charter.llm_adapter` (provider-agnostic — anthropic / openai-compatible incl. DeepSeek). Defaults `auto="medium"`, 50-trial cap (Q2); accepts `seed` (R3). Lazy DSPy import; clean error when extra absent. Substrate touch — WI-1 expected. NO auto-merge; verify against merged-branch HEAD. ~12 tests. |
| 3    | **SAFETY-CRITICAL** | ADR amendments — ADR-006 DeepSeek + ADR-007 v1.5                 | ADR-006 (OpenAI-compatible provider): add **DeepSeek** as a supported provider (endpoint + env var). ADR-007 v1.5: add **"DSPy program as canonical prompt shape"** ([DSPy+GEPA doc](../../_meta/dspy-gepa-prompt-optimization-2026-05-22.md) §4.4). Docs-only substrate touch (ADRs live under `docs/_meta/decisions/`). NO auto-merge.                          |

### Milestone 2 — Core integration (~6 tasks, LOW-RISK)

| Task | Risk     | Title                                   | Description                                                                                                                                                                                                                                                                                                     |
| ---- | -------- | --------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 4    | LOW-RISK | `meta_harness.gepa_adapter` module      | Wrap `get_effectiveness_score()` for GEPA `metric=` per Q5: **SKIP** None/zero-confidence; **MODULATE** scalar = `global_score × confidence`; **REFLECT** = `reason.value` + axes breakdown + operator notes. Returns `tuple[float, str]` or a "no-metric" signal so GEPA skips. Leaf-module (WI-8). ~12 tests. |
| 5    | LOW-RISK | Stage 7 parallel composer               | DSPy-compiled compositor runs alongside the legacy single-LLM-call composer (Q3). Both produce candidate skills for the same trace. Legacy path is always available (Q3 / WI-4). ~10 tests.                                                                                                                     |
| 6    | LOW-RISK | Eval-gate adjudication (DSPy vs legacy) | Score both Stage-7 outputs via the existing `skill_eval_gate` (A.4 v0.2 Task 8); **higher-scoring output persists**. Both scores logged to the audit chain (existing vocabulary). Produces automatic A/B data for Task 12. ~10 tests.                                                                           |
| 7    | LOW-RISK | Compilation cadence                     | Hybrid triggers (Q4): event-driven (effectiveness < 0.4 configurable / 10+ new skills configurable / operator CLI) + weekly cron per agent (configurable, default ON). **Per-agent compilation lock** (no concurrent compiles of one agent). Each compile eval-gated before deploy. ~12 tests.                  |
| 8    | LOW-RISK | Operator-notes cache layer              | Read operator feedback notes from the ratings sidecar **at compilation start**, cache in memory for the cycle (Q5-c). Feeds `gepa_adapter`'s reflection string. ~8 tests.                                                                                                                                       |
| 9    | LOW-RISK | CF #2 graceful-degradation integration  | DSPy compilation failure → fall back to legacy composer + emit `meta_harness.skill.effectiveness_error` (existing action). Stage 7 never crashes (WI-5). ~8 tests.                                                                                                                                              |

### Milestone 3 — Carry-forward LANDs (~2 tasks, LOW-RISK)

| Task | Risk     | Title                                                      | Description                                                                                                                                                                               |
| ---- | -------- | ---------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 10   | LOW-RISK | Carry-forward Item 1 (G1-CF4) — CF #2 retrofit             | Retrofit the CF #2 graceful-degradation pattern to `skill_lifecycle.py` `_safely` helpers. Pattern proven in G1/G2; apply consistently. ~8 tests.                                         |
| 11   | LOW-RISK | Carry-forward Item 15 (G2-WI-6) — NLAH byte-identity guard | Programmatic test asserting the "Skill selection guidance" section is **byte-identical** across all 17 agent personas (single md5). Closes the by-hand-only gap from G2 Task 6. ~3 tests. |

### Milestone 4 — Validation + closure (~4 tasks, LOW-RISK)

| Task | Risk     | Title                                 | Description                                                                                                                                                                                                                                                                               |
| ---- | -------- | ------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 12   | LOW-RISK | Quality-delta task (Q8 #2)            | Regenerate one v0.2 hand-written skill via DSPy+GEPA; document the measurable quality delta (or an **honest no-delta** finding + analysis of why). Uses Task 6's A/B data.                                                                                                                |
| 13   | LOW-RISK | End-to-end demo (Q8 #3)               | One full agent task run end-to-end with DSPy+GEPA-compiled prompts; store the documented trace in the verification record's appendix.                                                                                                                                                     |
| 14   | LOW-RISK | Anthropic switch-validation (Q1 + Q8) | **ONE** compilation cycle on the Anthropic API to validate DeepSeek-developed prompts behave correctly on the production target. **BLOCKS CLOSURE on Anthropic key acquisition** (cross-cutting #2).                                                                                      |
| 15   | LOW-RISK | Verification record + closure (Q8 #1) | v0.2.5 verification record at `docs/_meta/v0-2-5-skill-optimization-verification-2026-XX-XX.md` (date at closure): execution table, brainstorm resolutions, WI-1…WI-8, drift events, carry-forwards, cross-agent regression sweep, Q8 acceptance. Re-audits the Q7 carry-forward mapping. |

**Total: 15 tasks** (1 plan + 14 execution). Larger than G2 (8) due to substrate (Tasks 2-3), the 6-task core integration, and carry-forward LANDs.

---

## File map (target)

| Path                                                                                        | Task  | Note                               |
| ------------------------------------------------------------------------------------------- | ----- | ---------------------------------- |
| `packages/agents/meta-harness/pyproject.toml`                                               | 1     | version + `[dspy]` optional group  |
| `packages/charter/src/charter/dspy_compiler.py`                                             | 2     | **substrate** — new module         |
| `docs/_meta/decisions/ADR-006-openai-compatible-provider.md`                                | 3     | **substrate-doc** — DeepSeek       |
| `docs/_meta/decisions/ADR-007-cloud-posture-as-reference-agent.md`                          | 3     | **substrate-doc** — v1.5 amendment |
| `packages/agents/meta-harness/src/meta_harness/gepa_adapter.py`                             | 4     | new leaf module                    |
| `packages/agents/meta-harness/src/meta_harness/skill_writer.py` (or new `dspy_composer.py`) | 5     | parallel composer                  |
| `packages/agents/meta-harness/src/meta_harness/skill_eval_gate.py`                          | 6     | adjudication                       |
| `packages/agents/meta-harness/src/meta_harness/skill_compilation.py`                        | 7     | cadence (new)                      |
| `packages/agents/meta-harness/src/meta_harness/skill_lifecycle.py`                          | 9, 10 | CF #2 fallback + retrofit          |
| `packages/agents/meta-harness/tests/...`                                                    | all   | per-task tests                     |
| `docs/_meta/v0-2-5-skill-optimization-verification-2026-XX-XX.md`                           | 15    | closure record                     |

---

## Watch-items (carry-forward to verification record)

| WI   | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| ---- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| WI-1 | Substrate seal maintained **except Tasks 2-3** (`charter.dspy_compiler` + ADR amendments) — those are intentional substrate touches; every other task keeps `git diff origin/main -- packages/charter/ packages/shared/` empty.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| WI-2 | No regression in the G1/G2 eval suite — **25 cases pass throughout** v0.2.5.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| WI-3 | DSPy compilation **deterministic-by-construction in tests** — stub-LLM + seed for unit tests; real DeepSeek only in integration tests.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| WI-4 | **Backwards-compat** — existing v0.2 skills keep working without GEPA optimization; the legacy path is always available (Q3).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| WI-5 | **CF #2 graceful-degradation preserved** — DSPy failure never crashes Stage 7.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| WI-6 | **Single-tenant compilation — no per-tenant compilation surface** (Q6). Verified by: (1) the v0.2.5 public compile entry points (`meta_harness.gepa_adapter`, the compilation-cadence module) expose **no `tenant_id` parameter** — a unit test asserts their signatures take no tenant argument; (2) `grep -rn tenant` across the v0.2.5 modules (`charter.dspy_compiler`, `meta_harness.gepa_adapter`, `meta_harness.skill_compilation`) surfaces **only** the inherited `tenant_id="default"` from G1's `get_effectiveness_score` call — no per-customer branching; (3) effectiveness sidecars read during compilation carry `tenant_id == "default"` only (G1 schema invariant) — no compilation artifact writes a non-default tenant. |
| WI-7 | **Operator approval gate preserved** — first-of-class approval still required for compiled skills (A.4 v0.2 Task 15 pattern).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| WI-8 | **Leaf-module discipline** — `meta_harness.gepa_adapter` imports only from `effectiveness_store`, `nlah_loader`, `shared.skill_telemetry`, and the audit chain (no upward imports from lifecycle/writer/eval_gate).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |

---

## Done definition (Q8 closure criteria)

v0.2.5 is CLOSED only when **all** hold:

1. **Verification record** (Task 15) matching G1/G2 shape — execution table, brainstorm resolutions, WI-1…WI-8, drift events, carry-forwards.
2. **Quantitative quality delta** (Task 12) — ≥1 v0.2 skill regenerated via DSPy+GEPA with a documented measurable improvement (or an honest no-delta + analysis).
3. **End-to-end demo** (Task 13) — one full agent run with compiled prompts; trace in the record appendix.
4. **Anthropic switch-validation** (Task 14) — one compilation cycle on Anthropic; **blocks closure on key acquisition**.

All 15 tasks merged per ADR-011. WI-1…WI-8 verified. Carry-forward mapping (Items 1, 2, 15) confirmed landed.

---

## ADR-011 cadence (per-task discipline)

- **One PR per task.** No bundling. Risk label set in the PR title at open time.
- **SAFETY-CRITICAL (Tasks 2, 3):** no auto-merge; verify against merged-branch HEAD; operator approval gate; expect the WI-1 substrate-seal guard to trip (it is the seal working).
- **LOW-RISK:** standard review; CI green on required checks (`typescript-tests`, `typescript`, `go`); `python-tests` green for non-substrate tasks.
- **Pause for operator review after each task PR opens.**
- Plan-doc merge unblocks **Task 1**.

## Reference template

Mirrors [G2 Skill Selection plan](2026-05-25-g2-skill-selection.md) and the
[G1 Effectiveness Scoring plan](2026-05-24-g1-effectiveness-scoring.md). Closure
follows the [G1](../../_meta/g1-effectiveness-scoring-verification-2026-05-25.md) /
[G2](../../_meta/g2-skill-selection-verification-2026-05-30.md) verification-record
pattern.
