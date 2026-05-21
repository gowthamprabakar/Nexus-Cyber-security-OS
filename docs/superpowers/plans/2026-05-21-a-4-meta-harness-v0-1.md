# A.4 — Meta-Harness Agent v0.1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Pause for review after each numbered task.

**Goal:** Ship the **Meta-Harness Agent** (`packages/agents/meta-harness/`) — the **sixth of the 7 unbuilt agents** under the [Path-B-breadth-first operating rule](../sketches/2026-05-20-agent-version-roadmaps.md) (2026-05-20) and the **sixteenth under [ADR-007](../../_meta/decisions/ADR-007-cloud-posture-as-reference-agent.md)** (F.3 / D.1 / D.2 / D.3 / F.6 / D.7 / D.4 / multi-cloud-posture / k8s-posture / A.1 / D.5 / D.8 / D.6 / D.13 / D.12 / **A.4**). **The first agent that reads other agents** — runs cross-agent batch eval, A/B-compares NLAH variants, tracks scorecard deltas, flags regressions. **Producer of operator-facing diagnostics; ruthlessly read-only in v0.1.**

**Scope (v0.1, locked per Path-B-breadth-first rule + the user-supplied hard scope fences for the architectural-foundation agent).** Five capabilities only:

1. **Cross-agent batch evaluation** — run the eval suites of all 16 prior shipped agents (including A.4's own meta-eval cases) in a single batch run. Output: structured scorecard with per-agent pass-rate + per-eval-case results + delta-vs-last-run column.
2. **A/B comparison runner** — two NLAH variants of the same agent, same eval cases, deterministic output diff. Stub-LLM byte-equal across reruns.
3. **Agent introspection primitives** — parse NLAH directories per ADR-007 v1.2 NLAH-loader shape; extract persona, tool surface, eval-case coverage. Read-only.
4. **Scorecard delta tracking** — persist scorecards in workspace + SemanticStore (`entity_type="agent_scorecard"`); compare each run to the previous run.
5. **Markdown report output** — operator-readable `meta_harness_report.md` summarizing batch eval results, regressions flagged (≥5% pass-rate drop), A/B comparison results, watch-list section.

**Nothing else in v0.1.** Six explicit deferrals (autonomous skill creation, NLAH auto-deploy, new fabric subject, autonomous Curator behavior, multi-tenant production, eval-framework substrate hoist) are listed in §Defers below — each is named with the version where it lands.

**Strategic role.** A.4 is **the architectural-foundation agent for the v0.2 second-pass conversation.** Every feature in `docs/_meta/hermes-pattern-absorption-2026-05-22.md` (skill creation, NLAH auto-deploy, curator) builds on A.4 v0.1's introspection + batch-eval primitives. v0.1's ruthlessly-narrow surface protects the v0.2 conversation from being pre-committed by v0.1 decisions.

**Substrate posture.** A.4 v0.1 makes **zero changes** to `packages/charter/` and `packages/shared/`. Every helper builds package-local first per ADR-007's 3rd-consumer hoist rule. If any task surfaces a need to touch substrate, STOP and surface it as a separate ADR question — don't bundle into A.4 v0.1.

---

## Q1 — Output shape: workspace markdown + KG entity (NO bus emission; NO NLAH writes)

**Resolution: 2 directions.** D.12 emits in 3 directions (KG + `claims.>` + workspace md); A.4 emits in **2** (KG + workspace md). NO bus emission in v0.1.

- **`SemanticStore` entities** — `entity_type="agent_scorecard"` (one per A.4 run per evaluated agent; external_id `<customer_id>:<run_id>:<evaluated_agent_id>`) + `entity_type="ab_comparison_result"` (one per A/B run when the subcommand is used; external_id `<customer_id>:<run_id>:<agent_id>:<variant_a>:<variant_b>`). Q5 opt-in default.
- **`meta_harness_report.md`** workspace markdown — operator-readable unified report covering batch eval results, A/B comparison results if any, regression flags, watch-list section.

**Explicitly NOT in v0.1.** No `claims.>` publish, no new bus subject (`meta.>` / `proposals.>` deferred per Q-ARCH-2). No writes to any `packages/agents/*/src/*/nlah/` directory (Q-ARCH-1 → v0.2). No OCSF emit (claims/proposals/findings are downstream concerns).

## Q2 — Agent-introspection mechanism: ADR-007 v1.2 NLAH-loader-shape read

**Resolution: build on `charter.nlah_loader` contract.** The NLAH parser (`tools/nlah_parser.py`) walks `packages/agents/*/src/*/nlah/` directories using the same conventions `charter.nlah_loader` enforces — README.md required, optional `tools.md`, optional `examples/`. Output: structured `AgentManifest` pydantic carrying `agent_id` + `persona` (excerpted from README.md) + `declared_tools` (parsed from `tools.md`) + `example_count` + `eval_case_count` (cross-referenced from `eval/cases/`).

**Read-only.** The parser opens files in `"r"` / `"rb"` / `"rt"` mode only. WI-4 ships an integration-test guard that intercepts file-open calls under the NLAH glob and asserts mode-in-{read-only-modes}.

**Eval-case discovery.** The parser peeks at each agent's `eval/cases/*.yaml` for case counts — this becomes input to Q3's batch runner. Pure read.

## Q3 — Eval-framework usage: direct consume; agent-local-first for any helper

**Resolution: direct consume of existing `eval_framework` API** (`cases.load_cases`, `runner.EvalRunner` Protocol, `suite.run_suite`, the `nexus_eval_runners` entry-point group). **No substrate hoist in v0.1.**

For batch-eval (running all 16 agents' suites in one batch), A.4 builds a thin agent-local `BatchEvalRunner` under `packages/agents/meta-harness/src/meta_harness/eval/batch.py` that iterates the registered `nexus_eval_runners` entry points + invokes each in sequence. **Per ADR-007's 3rd-consumer hoist rule (Q-ARCH-3):** keep this agent-local until a 3rd consumer arrives (likely Supervisor #0 or a future agent). Eval-framework substrate stays untouched.

Each per-agent run reuses that agent's bundled `eval/cases/` + `eval/stub_responses/` (where applicable). **A.4 doesn't author any per-agent stub responses;** it consumes what each agent already ships.

## Q4 — A/B comparison shape: two NLAH variants, deterministic byte-equal diff

**Resolution: `meta-harness ab-compare AGENT_ID --variant-a PATH --variant-b PATH`** — operator points at two versions of the same agent's `nlah/` directory (typically `nlah/` and `nlah/.proposed/`); A.4 monkey-patches the per-agent NLAH-loader for the agent's evaluator process, runs the agent's eval suite under each variant, captures `RunOutcome` arrays, diffs them.

**Output.** `ABComparison` pydantic (variant_a_pass_rate, variant_b_pass_rate, per-case-delta list, byte-equal flag). The **byte-equal flag is the WI-3 acceptance** — under stub-LLM mode + identical NLAH, both variants MUST produce byte-equal `RunOutcome` arrays. Any drift signals a hidden non-determinism source and is treated as a v0.1 bug.

**v0.1 ships single-agent A/B only.** Cross-agent A/B (variant of agent X tested against variant of agent Y) is deferred to A.4 v0.2.

## Q5 — Tenancy: single-tenant `semantic_store=None` opt-in default

**Resolution: identical to every prior agent.** `semantic_store=None` default; KG persistence is opt-in via the CLI. Multi-tenant production blocks on the future SET LOCAL `$1` tenant-RLS substrate-fix plan. Workspace markdown is the always-on output; KG is the opt-in.

## Q6 — Audit posture: F.6 audit-chain additive vocabulary

**Resolution: 4 additive audit-action vocabulary entries** (per ADR-010 condition 4 — additive-only; no existing audit-action strings touched):

- `meta_harness.batch_eval.started` (run start; carries customer_id + run_id + evaluated_agent_count)
- `meta_harness.batch_eval.completed` (run end; carries per-agent pass-rate summary)
- `meta_harness.regression_detected` (one entry per regression; carries agent_id + delta_pct + previous-run pointer)
- `meta_harness.ab_comparison.completed` (optional; only when A/B subcommand invoked)

F.6 hash-chain semantics inherited unchanged. No substrate write to `packages/charter/`.

---

## Q-ARCH acknowledgments — explicit deferrals to v0.2+

These are the three architectural questions the user flagged as needing explicit deferral acknowledgment:

### Q-ARCH-1: Should A.4 be added to `_FORBIDDEN_SUBSCRIPTIONS` per ADR-012's auto-acting agents clause?

**NOT in v0.1.** A.4 v0.1 reads, evaluates, reports. No write to NLAH directories. No bus publish. No remediation. The ADR-012 forbidden-subscriptions fence does not apply yet.

**When A.4 v0.2 adds auto-deploy of NLAH changes (per deferral #2), A.4 BECOMES an auto-acting agent and MUST be added to the forbidden-subscriptions registry.** Carried forward as **WI-5** in the v0.1 verification record: _"A.4 v0.2 plan MUST include subscriber-ACL review per ADR-012 since v0.2 introduces auto-acting behavior."_

### Q-ARCH-2: Does A.4 need a new fabric subject for meta-claims/proposals?

**NOT in v0.1.** Workspace markdown + SemanticStore entity is sufficient for the 5 in-scope capabilities. Operators read the report; no real-time consumer exists today.

**If A.4 v0.2 introduces real-time proposal emission** (e.g., for operator notification when regression detected), a `meta.>` or `proposals.>` ADR happens at that point — modeled on ADR-012's shape for `claims.>`. Do NOT pre-commit the subject namespace in v0.1.

### Q-ARCH-3: Eval-framework substrate extensions — package-local or charter-hoist?

**Package-local FIRST.** Per ADR-007's 3rd-consumer hoist rule. Build any batch-eval / A/B-comparison helpers under `packages/agents/meta-harness/src/meta_harness/` first. If Supervisor (#0) v0.1 plan or any future agent becomes the 3rd consumer, hoist to `packages/eval-framework/` at that point with a one-paragraph rationale in the hoist PR description.

This protects the eval-framework package from premature API commitment.

---

## Architecture

Six-stage pipeline (one fewer than D.12 — A.4 has no PUBLISH stage since v0.1 doesn't emit on fabric):

```
ExecutionContract (signed)
        │
        ▼
┌──────────────────────────────────────────────────────────────────┐
│ Meta-Harness Agent driver                                        │
│                                                                  │
│  Stage 1: INTROSPECT      — parse all agents' NLAH dirs         │
│  Stage 2: BATCH_EVAL      — run each agent's eval suite          │
│  Stage 3: AB_COMPARE      — optional; only when --ab subcommand │
│  Stage 4: DELTA           — diff scorecards vs previous run     │
│  Stage 5: REPORT          — assemble MetaHarnessReport          │
│  Stage 6: HANDOFF         — meta_harness_report.md + KG opt-in  │
└─────────┬────────────────────────────────────────────────────────┘
          │
          ▼
┌──────────────────────────────────────────────────────────────────┐
│ Tools (per-stage)                                                │
│  tools/nlah_parser.py     ─→ AgentManifest per agent (read-only) │
│  eval/batch.py            ─→ BatchEvalRunner (agent-local)       │
│  tools/ab_compare.py      ─→ ABComparison (single-agent A/B)     │
│  tools/scorecard_delta.py ─→ per-agent delta vs prev scorecard   │
│  tools/regression_flagger ─→ ≥5% drop flagged                    │
│  reporter.py              ─→ meta_harness_report.md              │
│  kg_writer.py             ─→ SemanticStore (entity_type=         │
│                              "agent_scorecard" + "ab_comparison_ │
│                              result"); opt-in default            │
└──────────────────────────────────────────────────────────────────┘
```

**Tech stack.** Python 3.12 · BSL 1.1 · `charter.llm_adapter` only if A.4's own meta-eval cases use LLM stubs (likely yes for the 10 meta-eval cases; ADR-006) · pydantic 2.9 · click 8 · `charter.nlah_loader` (ADR-007 v1.2). No external network dependencies. **No `claims.>` or any other fabric publish.**

**Depends on:** all 6 D-track agents shipped at v0.1 + D.13 Synthesis + every prior agent. **No** v0.1 dep on Supervisor (#0).

---

## Execution status

```
1 → 2 → 3 → 4 → 5 → 6 → 7 → 8 → 9 → 10 → 11 → 12 → 13 → 14 → 15 → 16
```

| Task | Status | Commit | Notes                                                                                                                                                                                                                                                                                                                                                                         |
| ---- | ------ | ------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1    | ⬜     |        | Bootstrap — pyproject (BSL 1.1; deps on charter / shared / eval-framework + nexus-synthesis-agent for Q6 reviewer reuse if A.4 self-eval needs Q6 guard). py.typed + `__init__`. Smoke tests including 3 Q-ARCH deferral guards (no claims.> import; no NLAH-write capability).                                                                                               |
| 2    | ⬜     |        | `schemas.py` — pydantic: `AgentManifest` (per-agent introspection result) + `Scorecard` (per-agent batch-eval result) + `ScorecardDelta` (vs prev run) + `ABComparison` + `MetaHarnessReport` (top-level run output). ~16 tests covering pydantic validation.                                                                                                                 |
| 3    | ⬜     |        | `tools/nlah_parser.py` — read-only NLAH directory walker per ADR-007 v1.2 conventions. Extracts persona / declared_tools / example_count / eval_case_count. ~12 tests including the WI-4 read-only guard (intercept file-open calls; assert read-mode only).                                                                                                                  |
| 4    | ⬜     |        | `eval/batch.py` — agent-local `BatchEvalRunner` wrapping registered `nexus_eval_runners` entry points. Sequential per-agent runs; structured `Scorecard` output. ~14 tests including 16-agent batch happy-path + per-agent failure tolerance (one agent's failure doesn't poison the batch).                                                                                  |
| 5    | ⬜     |        | `tools/ab_compare.py` — single-agent A/B engine. Monkey-patches per-agent NLAH dir; runs eval suite under each variant; produces `ABComparison`. Byte-equal flag (WI-3). ~13 tests using stub-LLM provider.                                                                                                                                                                   |
| 6    | ⬜     |        | `tools/scorecard_delta.py` — diffs current `Scorecard` vs previous-run scorecard loaded from SemanticStore (or empty if no prior run). Output: `ScorecardDelta` with per-agent pass-rate change. ~10 tests.                                                                                                                                                                   |
| 7    | ⬜     |        | `tools/regression_flagger.py` — emits warnings for ≥5% pass-rate drop. Outputs list of (agent_id, prev_pass_rate, current_pass_rate, delta_pct). Pure-function over `ScorecardDelta`. ~10 tests covering threshold edges + multi-agent regressions + zero regressions case.                                                                                                   |
| 8    | ⬜     |        | `entities.py` (`AgentScorecard` + `ABComparisonResult` pydantic) + `kg_writer.py` (SemanticStore upsert; single-tenant `semantic_store=None` opt-in). External_id contracts per Q1. ~14 tests including cross-tenant rejection.                                                                                                                                               |
| 9    | ⬜     |        | `reporter.py` — pure-function markdown renderer. Builds `meta_harness_report.md`: batch eval summary table, regression flags section, A/B section (conditional), watch-list section (agents whose pass-rate is trending down across ≥2 prior runs). ~12 tests.                                                                                                                |
| 10   | ⬜     |        | Agent driver `run()` — 6-stage pipeline (INTROSPECT → BATCH_EVAL → AB_COMPARE_OPT → DELTA → REPORT → HANDOFF). Signature: `run(contract, *, semantic_store=None, ab_variant_a=None, ab_variant_b=None, ab_target_agent=None) -> MetaHarnessReport`. ~15 driver tests.                                                                                                         |
| 11   | ⬜     |        | NLAH bundle + 21-LOC shim. ADR-007 v1.2 conformance — A.4 is the **12th** agent shipped natively against v1.2 (D.3 / F.6 / D.7 / D.4 / multi-cloud-posture / k8s-posture / D.5 / D.8 / D.6 / D.13 / D.12 / **A.4**). README ("Meta-Harness persona") + tools.md + 3 examples. ~16 tests.                                                                                      |
| 12   | ⬜     |        | 10 representative YAML meta-eval cases + `MetaHarnessEvalRunner` registered via `nexus_eval_runners`. Cases: clean-batch / one-agent-regression / multi-agent-regression / ab-comparison-clean / ab-comparison-divergent / single-agent-failed-eval-tolerated / never-prior-scorecard / watch-list-population / introspection-shape / kg-upsert-skipped-when-none. ~17 tests. |
| 13   | ⬜     |        | CLI (`meta-harness run` / `meta-harness eval` / `meta-harness ab-compare AGENT_ID --variant-a PATH --variant-b PATH`) — three subcommands. ~14 CLI tests using Click's CliRunner.                                                                                                                                                                                             |
| 14   | ⬜     |        | **Stub-LLM eval harness** — `eval/stub_responses/<case_id>/responses.json` per case. WI-3 byte-equal across reruns probe (×10 cases). ~28 tests.                                                                                                                                                                                                                              |
| 15   | ⬜     |        | README polish + smoke runbook. 3-step smoke runbook (unit tests / eval suite / batch-run against real-agent fleet). Architecture diagram + ADR-007 + Q-ARCH-1/2/3 deferral section.                                                                                                                                                                                           |
| 16   | ⬜     |        | Verification record (`docs/_meta/a-4-meta-harness-v0-1-verification-2026-05-21.md`) — 16-task table, gate results, 10/10 meta-eval acceptance, WI-1..WI-5 watch-item resolutions, **Q-ARCH-1 carry-forward to A.4 v0.2 inheritance** (WI-5 acceptance), Path-B sequence advance (**16/17 agents at v0.1**; next is **Supervisor #0**).                                        |

ADR references: [ADR-001](../../_meta/decisions/ADR-001-monorepo-bootstrap.md) · [ADR-005](../../_meta/decisions/ADR-005-async-tool-wrapper-convention.md) · [ADR-006](../../_meta/decisions/ADR-006-llm-adapter.md) · [ADR-007](../../_meta/decisions/ADR-007-cloud-posture-as-reference-agent.md) · [ADR-008](../../_meta/decisions/ADR-008-eval-framework.md) · [ADR-010](../../_meta/decisions/ADR-010-version-extension-template.md) · [ADR-011](../../_meta/decisions/ADR-011-pr-flow-and-branch-protection-discipline.md) · [ADR-012](../../_meta/decisions/ADR-012-claims-subject-namespace.md).

---

## Resolved questions

| #        | Question                            | Resolution                                                                                                                                                                    | Task           |
| -------- | ----------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------- |
| Q1       | Output shape?                       | 2 directions: SemanticStore entities (`agent_scorecard` + `ab_comparison_result`; opt-in) + `meta_harness_report.md` workspace markdown. **NO bus emission; NO NLAH writes.** | Tasks 8, 9, 10 |
| Q2       | Agent introspection?                | Build on ADR-007 v1.2 NLAH-loader contract. Read-only directory walker. `AgentManifest` pydantic output.                                                                      | Task 3         |
| Q3       | Eval-framework usage?               | Direct consume. Agent-local `BatchEvalRunner` per ADR-007 3rd-consumer hoist rule. No `packages/eval-framework/` substrate changes.                                           | Task 4         |
| Q4       | A/B comparison shape?               | Single-agent A/B via NLAH-dir monkey-patch. Byte-equal flag is the WI-3 acceptance. Cross-agent A/B deferred to v0.2.                                                         | Task 5         |
| Q5       | Tenancy?                            | Single-tenant (`semantic_store=None` opt-in default). Multi-tenant blocks on SET LOCAL `$1` fix.                                                                              | Tasks 8, 10    |
| Q6       | Audit posture?                      | 4 additive F.6 audit-action entries (started / completed / regression_detected / ab_comparison_completed). No existing audit-action strings touched.                          | Task 10        |
| Q-ARCH-1 | A.4 in `_FORBIDDEN_SUBSCRIPTIONS`?  | **NOT in v0.1.** v0.2 MUST review per ADR-012 since v0.2 introduces auto-acting. Captured as WI-5.                                                                            | (deferred)     |
| Q-ARCH-2 | New fabric subject?                 | **NOT in v0.1.** Workspace markdown + KG sufficient. v0.2 may add `meta.>` / `proposals.>` ADR.                                                                               | (deferred)     |
| Q-ARCH-3 | Eval-framework substrate extension? | **Package-local FIRST.** Hoist when 3rd consumer arrives.                                                                                                                     | Task 4         |

---

## Out of scope — explicit version-named deferrals

1. **NO autonomous skill creation.** Per Hermes-pattern N1 + N2 + N5. Deferred to **A.4 v0.2**.
2. **NO auto-deploy of NLAH changes.** A.4 v0.1 may propose in the report markdown (operator review only). Deferred to **A.4 v0.3** (after v0.2 ships skill-creation foundations).
3. **NO new fabric subject.** Workspace + KG only. Deferred to **A.4 v0.2 (conditional)**.
4. **NO autonomous Curator behavior.** Per Hermes-pattern N3. Deferred to **A.4 v0.3** after v0.2 skill-creation.
5. **NO multi-tenant production.** Blocks on future SET LOCAL `$1` tenant-RLS substrate-fix plan. Deferred to **A.4 v0.x post-SET-LOCAL-fix**.
6. **NO eval-framework substrate hoist UNLESS demonstrably required by 2+ consumers.** Agent-local first per ADR-007 3rd-consumer rule.

---

## File map (target)

```
packages/agents/meta-harness/
├── pyproject.toml                              # Task 1
├── README.md                                   # Tasks 1, 15
├── src/meta_harness/
│   ├── __init__.py                             # Task 1
│   ├── py.typed                                # Task 1
│   ├── schemas.py                              # Task 2
│   ├── nlah_loader.py                          # Task 11 (21-LOC shim)
│   ├── entities.py                             # Task 8
│   ├── kg_writer.py                            # Task 8
│   ├── reporter.py                             # Task 9
│   ├── tools/
│   │   ├── __init__.py
│   │   ├── nlah_parser.py                      # Task 3
│   │   ├── ab_compare.py                       # Task 5
│   │   ├── scorecard_delta.py                  # Task 6
│   │   └── regression_flagger.py               # Task 7
│   ├── eval/
│   │   ├── __init__.py
│   │   └── batch.py                            # Task 4 (agent-local; not eval-framework)
│   ├── agent.py                                # Task 10
│   ├── nlah/
│   │   ├── README.md                           # Task 11
│   │   ├── tools.md                            # Task 11
│   │   └── examples/                           # Task 11 (3 examples)
│   ├── eval_runner.py                          # Task 12
│   └── cli.py                                  # Task 13
├── eval/
│   ├── cases/                                  # Task 12 (10 meta-eval YAML cases)
│   └── stub_responses/                         # Task 14 (per-case canned LLM outputs)
└── tests/
    ├── test_smoke.py                           # Task 1 (incl. Q-ARCH deferral guards)
    ├── test_schemas.py                         # Task 2
    ├── test_tools_nlah_parser.py               # Task 3 (incl. WI-4 read-only guard)
    ├── test_eval_batch.py                      # Task 4
    ├── test_tools_ab_compare.py                # Task 5
    ├── test_tools_scorecard_delta.py           # Task 6
    ├── test_tools_regression_flagger.py        # Task 7
    ├── test_entities.py                        # Task 8
    ├── test_kg_writer.py                       # Task 8
    ├── test_reporter.py                        # Task 9
    ├── test_agent_unit.py                      # Task 10
    ├── test_nlah_loader.py                     # Task 11
    ├── test_eval_runner.py                     # Task 12
    ├── test_cli.py                             # Task 13
    └── test_stub_llm_harness.py                # Task 14 (WI-3 byte-equal probe)
```

---

## Risks

| Risk                                                                                               | Mitigation                                                                                                                                                                                                                                                               |
| -------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Per-agent eval suite drift breaks A.4 batch runs silently                                          | Task 4's BatchEvalRunner tolerates per-agent failure (one agent's exception doesn't poison the batch). Failures surface as `pass_rate=None` in the scorecard with `error` field populated; the report markdown flags them visibly.                                       |
| A.4 accidentally writes to an agent's NLAH directory (e.g., via a buggy A/B-compare monkey-patch)  | **WI-4 integration test** intercepts file-open calls under `packages/agents/*/src/*/nlah/` and asserts mode is read-only. Fails loudly on any mode containing `"w"`, `"a"`, `"x"`, or `"+"`. Runs in CI as part of the standard test suite.                              |
| Stub-LLM non-determinism in A/B-compare (different stub responses across variants under same NLAH) | A/B-compare runs the same case-set under both variants; stub responses come from each case's `responses.json` (same file across variants). The byte-equal flag is the regression probe — any divergence under identical NLAH signals a hidden source of non-determinism. |
| Scorecard delta tracking relies on prev-run SemanticStore entity that may not exist                | `scorecard_delta` handles "no prior run" gracefully (treats prev = empty scorecard; current run is baseline). First run never flags regressions. Documented in Task 6's tests + the report markdown's "first-run" banner.                                                |
| Hoisting batch_eval to `packages/eval-framework/` premature                                        | Q-ARCH-3 keeps it agent-local. Only hoist when 3rd consumer arrives. Documented in Task 4's module docstring + the verification record.                                                                                                                                  |
| Q-ARCH-1 carry-forward dropped (A.4 v0.2 author misses the subscriber-ACL review requirement)      | WI-5 is the explicit carry-forward mechanism. Verification record §"Watch-items" names "A.4 v0.2 plan MUST include subscriber-ACL review per ADR-012" verbatim. Plan-doc template for v0.2 inherits this watch-item.                                                     |
| Real-time fabric emission pressure ("but A.4 should publish to claims.> for live notification!")   | Q-ARCH-2 explicit deferral. v0.1 ships workspace markdown + KG entity ONLY. Operator-side notification can read the markdown / KG; if real-time emission is justified in v0.2, ADR-012-shape ADR amendment for `meta.>` / `proposals.>` lands at that point.             |

---

## Watch-items (carry-forward to verification record)

- **WI-1: Substrate sealed.** `git diff --stat packages/charter/ packages/shared/` empty across all 16 tasks. Verified at close.
- **WI-2: Single-tenant default.** `semantic_store=None` opt-in throughout; no cross-tenant reads.
- **WI-3: Stub-LLM determinism.** Per-case `responses.json`; byte-equal across reruns. A/B comparison also byte-equal under stub mode.
- **WI-4: No NLAH writes.** Read-only enforced by integration test that intercepts file-open calls under `packages/agents/*/src/*/nlah/` and asserts read-mode only.
- **WI-5: Q-ARCH-1 carry-forward.** Verification record explicitly names "A.4 v0.2 plan MUST include subscriber-ACL review per ADR-012" so the v0.2 plan author can't miss the constraint.

---

## Done definition

A.4 Meta-Harness v0.1 is **done** when:

- 16/16 tasks closed; every commit pinned in the execution-status table.
- ≥ 80% test coverage on `packages/agents/meta-harness`.
- `ruff check` + `ruff format --check` + `mypy --strict` clean.
- `meta-harness eval` returns 10/10 (deterministic via stub-LLM harness).
- `meta-harness run` against the live 15-agent fleet (+ A.4 self-eval = 16) produces a `meta_harness_report.md` with batch eval results across all 16.
- ADR-007 v1.1 + v1.2 + ADR-010 + ADR-011 conformance verified end-to-end.
- README + smoke runbook reviewed.
- A.4 v0.1 verification record committed at `docs/_meta/a-4-meta-harness-v0-1-verification-2026-05-21.md`.
- **Watch-items WI-1 through WI-5 verified at close**, with WI-5 explicitly named in the v0.2 plan-inheritance section so the next-cycle author can't miss the subscriber-ACL review requirement.

That closes the **sixth of 7 unbuilt agents** under the Path-B operating rule. **Supervisor (#0) v0.1** is the seventh and final agent (depends on all 16 prior agents + A.4 for routing decisions). After Supervisor closes: **17/17 platform-complete-narrow-depth**; the second-pass v0.2 conversation opens with `docs/_meta/hermes-pattern-absorption-2026-05-22.md` (forthcoming) as the reference.

---

## ADR-011 cadence (per-task discipline)

Every numbered task above lands as its **own PR** off branches like `feat/a-4-task-N-<scope>`. Per [ADR-011](../../_meta/decisions/ADR-011-pr-flow-and-branch-protection-discipline.md):

- **LOW-RISK label on every A.4 task** — all changes scoped to `packages/agents/meta-harness/` (new package, isolated). **Zero substrate touches** (WI-1). If any task surfaces a need to touch substrate, STOP and surface as a separate ADR question.
- **Report → review → merge → next task.** After each task PR opens, pause for review. Don't start the next task until the prior PR merges.
- **Verified-against-HEAD sentence** in every PR body.
- **Execution-status table is single source of truth** for task-commit pinning per ADR-010.

---

## Next plans queued (for context, per Path-B operating rule)

- **A.4 Meta-Harness v0.1** (this plan) — sixth of 7 unbuilt agents.
- **Supervisor (#0) v0.1** — seventh and last; depends on all 16 prior agents + A.4 for routing decisions.

After Supervisor closes: **17/17 platform-complete-narrow-depth.** Second-pass v0.2 conversation opens (Hermes-pattern absorption + A.4 v0.2 + v0.2 across the shipped agents).

---

## Reference template

Follows [ADR-007](../../_meta/decisions/ADR-007-cloud-posture-as-reference-agent.md) (reference NLAH) + [ADR-010](../../_meta/decisions/ADR-010-within-agent-version-extension.md). [D.12 Curiosity v0.1's verification record](../../_meta/d-12-curiosity-v0-1-verification-2026-05-21.md) is the closest reference for cadence + verification-record shape. The eval-framework primitives (`cases.load_cases`, `runner.EvalRunner` Protocol, `suite.run_suite`, `nexus_eval_runners` entry-point group) are the reference for batch-eval composition.
