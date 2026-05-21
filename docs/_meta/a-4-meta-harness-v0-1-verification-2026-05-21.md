# A.4 Meta-Harness Agent v0.1 — Verification Record

**Date closed:** 2026-05-21
**Plan:** [docs/superpowers/plans/2026-05-21-a-4-meta-harness-v0-1.md](../superpowers/plans/2026-05-21-a-4-meta-harness-v0-1.md)
**Status:** **CLOSED — 16/16 tasks merged.** A.4 is **the 16th of 17 v0.1 agents** under [ADR-007](decisions/ADR-007-cloud-posture-as-reference-agent.md), the **12th** shipped natively against ADR-007 v1.2's 21-LOC NLAH-loader shim, and the **sixth of 7 unbuilt agents** under the [Path-B-breadth-first operating rule](../superpowers/sketches/2026-05-20-agent-version-roadmaps.md). Supervisor (#0) is the seventh and final v0.1 agent.

## Execution status (16/16)

| Task | Status | Commit    | PR        | Notes                                                                                                                                                                            |
| ---- | ------ | --------- | --------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Plan | ✅     | 9431f1e   | #141      | Plan doc landed on main; 310 lines.                                                                                                                                              |
| 1    | ✅     | 83a1aa7   | #142      | Bootstrap package — pyproject + `__init__` + 12 smoke tests incl. 3 Q-ARCH deferral guards + WI-1 probe.                                                                         |
| 2    | ✅     | 99f30bc   | #143      | `schemas.py` — 6 pydantic types (AgentManifest / Scorecard / ScorecardDelta / ABComparison{,CaseDelta} / RegressionFlag / MetaHarnessReport). 21 schema tests.                   |
| 3    | ✅     | a3a3dd7   | #144      | `tools/nlah_parser.py` — read-only NLAH walker + **WI-4 runtime guard** (patches `Path.open` + `builtins.open` against real cloud_posture NLAH dir). 12 tests.                   |
| 4    | ✅     | e88e400   | #145      | `eval/batch.py` — `BatchEvalRunner` (agent-local per Q-ARCH-3). Per-agent failure tolerance. 15 tests.                                                                           |
| 5    | ✅     | aae7768   | #146      | `tools/ab_compare.py` — single-agent A/B engine. `nlah_override` context patches `charter.nlah_loader.default_nlah_dir`. WI-3 byte_equal flag at top level + per case. 13 tests. |
| 6    | ✅     | 160a39f   | #147      | `tools/scorecard_delta.py` — pure-function diffs. First-run rows never flag. 10 tests.                                                                                           |
| 7    | ✅     | aa0584d   | #148      | `tools/regression_flagger.py` — ≥5% drop threshold (conservative `<=` boundary). 10 tests.                                                                                       |
| 8    | ✅     | 3b3a6a5   | #149      | `entities.py` + `kg_writer.py` — AgentScorecard + ABComparisonResult entity types; cross-tenant rejection at writer boundary. 17 tests.                                          |
| 9    | ✅     | bd513eb   | #150      | `reporter.py` — pure-function markdown renderer for the 6 report sections. 12 tests.                                                                                             |
| 10   | ✅     | c5cc27a   | #151      | `agent.py` — 6-stage driver wiring INTROSPECT → BATCH_EVAL → AB_COMPARE → DELTA → REPORT → HANDOFF. 16 tests.                                                                    |
| 11   | ✅     | c0d597b   | #152      | NLAH bundle (`nlah_loader.py` 26-LOC shim + README + tools.md + 3 examples). 17 tests.                                                                                           |
| 12   | ✅     | 85cfe4f   | #153      | `eval_runner.py` + 10 YAML meta-eval cases registered via `nexus_eval_runners`. 17 tests; 10/10 cases PASS.                                                                      |
| 13   | ✅     | 079f9da   | #154      | CLI (`run` / `eval` / `ab-compare` subcommands). 14 Click CliRunner tests.                                                                                                       |
| 14   | ✅     | cbd6433   | #155      | Stub-LLM harness — 10 stub_responses dirs + **WI-3 byte-equal-across-reruns probe** per case (×10). 28 tests.                                                                    |
| 15   | ✅     | 2477765   | #156      | README polish — 3-step smoke runbook + Q-ARCH-1/2/3 deferral section + WI-1..WI-5 + 7 named v0.2+ deferrals.                                                                     |
| 16   | ✅     | _this PR_ | _this PR_ | This verification record + closure.                                                                                                                                              |

**Test surface at close:** 214 tests across 11 test modules. mypy --strict 0 errors across 16 source files. ruff check + ruff format --check clean.

## Eval suite acceptance

`meta-harness eval` → **10/10 PASS**, deterministic via the stub-LLM harness. All 10 cases also pass the WI-3 byte-equal-across-reruns probe (`tests/test_stub_llm_harness.py`).

| Case                                    | Verifies                                                                                      |
| --------------------------------------- | --------------------------------------------------------------------------------------------- |
| `01_clean_batch`                        | 3 agents, all pass, 0 regressions; placeholder text rendered.                                 |
| `02_one_agent_regression`               | Prior 100% / current 0% on one of two → 1 regression flagged.                                 |
| `03_multi_agent_regression`             | 2 of 3 cross threshold; 1 improves; multi-agent regression formatting.                        |
| `04_ab_comparison_clean`                | Variants identical → `byte_equal=True` (the WI-3 signal under stub-LLM mode).                 |
| `05_ab_comparison_divergent`            | Variants differ → `ab_present=True`; per-case delta surfaces.                                 |
| `06_single_agent_failed_eval_tolerated` | One agent's runner raises ImportError; batch continues; failed agent appears with error cell. |
| `07_never_prior_scorecard`              | No prior rows → all first-run; 0 regressions even on bad current rate.                        |
| `08_watch_list_population`              | v0.1 driver passes empty watch-list; placeholder rendered.                                    |
| `09_introspection_shape`                | Synthetic agents have no NLAH dir; `manifest_count=0` but eval still runs.                    |
| `10_kg_upsert_skipped_when_none`        | `semantic_store=None` → no upsert calls; markdown still emitted.                              |

## Acceptance criteria (plan §Q1-Q6 + Q-ARCH-1/2/3 + watch-items)

| Criterion                                                                   | Verification                                                                                                                                                                                                                                                                                                                                                    |
| --------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Q1.** Output: 2 directions (KG entities + workspace md); NO bus emission  | `kg_writer.upsert_scorecards` + `upsert_ab_result` ship the two entity types (`agent_scorecard` + `ab_comparison_result`). `reporter.render_report` + driver Stage 6 HANDOFF writes `meta_harness_report.md`. No `claims.>` or other fabric publish in agent.py (smoke test `test_qarch1_no_claims_publish_surface` is the regression probe).                   |
| **Q2.** Agent introspection: ADR-007 v1.2 NLAH-loader shape                 | `tools/nlah_parser.parse_nlah_dir` walks each agent's `nlah/` via `Path.read_text` only; required README → persona; optional tools.md → declared tool names (deduped); optional examples/ → count; optional eval_cases_dir → YAML count. WI-4 runtime guard asserts every observed open mode is read-only against the real cloud_posture NLAH dir.              |
| **Q3.** Eval-framework usage: direct consume; agent-local first             | `eval/batch.py` imports `eval_framework.cases.load_cases` + `eval_framework.suite.run_suite` directly. `BatchEvalRunner` is agent-local per Q-ARCH-3's 3rd-consumer hoist rule. No substrate edits to `packages/eval-framework/` (verified by `git diff --stat packages/eval-framework/` across all 16 tasks — empty).                                          |
| **Q4.** A/B compare: single-agent only; `byte_equal` is the WI-3 acceptance | `ab_compare` accepts `ABCompareRequest(target_agent, variant_a_path, variant_b_path)`. `nlah_override` context patches `charter.nlah_loader.default_nlah_dir`. `_canonical_bytes` strips duration_sec + trace timestamps before per-case compare; top-level `byte_equal` is the AND of per-case flags. Cross-agent A/B deferred to v0.2.                        |
| **Q5.** Tenancy: single-tenant `semantic_store=None` opt-in default         | `agent.run`'s `semantic_store` defaults to `None`. `kg_writer.upsert_scorecards` + `upsert_ab_result` no-op-with-log on `None`. Eval case 10 (`kg_upsert_skipped_when_none`) is the regression probe. Multi-tenant production blocks on the future SET LOCAL `$1` tenant-RLS substrate-fix plan.                                                                |
| **Q6.** Audit posture: 4 additive F.6 audit-action vocabulary entries       | The four entries (`meta_harness.batch_eval.started` / `.completed` / `.regression_detected` / `.ab_comparison.completed`) are documented in NLAH `tools.md` per the plan's Q6 resolution + ADR-010 condition 4 (additive-only; no existing strings touched). F.6 hash-chain semantics inherited unchanged.                                                      |
| **Q-ARCH-1.** A.4 NOT in `_FORBIDDEN_SUBSCRIPTIONS` (v0.1 is read-only)     | v0.1 ships no claims.> publish surface (smoke test `test_qarch1_no_claims_publish_surface` source-greps no `claims_subject` / `CLAIMS_STREAM` import). **WI-5 carry-forward**: when A.4 v0.2 adds auto-deploy of NLAH changes, A.4 becomes an auto-acting agent and MUST be added to the forbidden-subscriptions registry. Named verbatim below.                |
| **Q-ARCH-2.** No new fabric subject in v0.1                                 | Smoke test `test_qarch2_no_new_fabric_subject_literal` source-greps no `meta.>` / `proposals.>` / `meta.tenant.` / `proposals.tenant.` literal anywhere under src/. Workspace + KG only. v0.2 may introduce a meta/proposals fabric subject via a new ADR (modeled on ADR-012's shape) if real-time consumer pressure justifies.                                |
| **Q-ARCH-3.** Eval-framework helpers stay agent-local                       | `eval/batch.py` lives under `packages/agents/meta-harness/src/meta_harness/eval/`, NOT `packages/eval-framework/`. Per ADR-007's 3rd-consumer hoist rule. If Supervisor #0 (or any future agent) becomes the third consumer of `BatchEvalRunner`, hoist with a one-paragraph rationale in the hoist PR.                                                         |
| **WI-1** Substrate sealed                                                   | `git diff --stat packages/charter/ packages/shared/` empty across all 16 tasks. Bootstrap smoke probe (`test_wi1_substrate_sealed_substrate_imports_reachable`) is the positive-control reachability check; diff-empty at close is the substrate-sealed negative-control.                                                                                       |
| **WI-2** Single-tenant default                                              | `semantic_store=None` is the documented default on `agent.run` + every top-level helper. Eval case 10 + the no-op-with-log tests are the regression probes; the `_FORBIDDEN_SUBSCRIPTIONS` registry still names A.1 (not A.4 — A.4 isn't auto-acting in v0.1).                                                                                                  |
| **WI-3** Stub-LLM determinism                                               | Per-case `eval/stub_responses/<case_id>/responses.json` (10 files, all empty arrays in v0.1 since A.4 doesn't consume an LLM directly). `test_stub_llm_harness::test_wi3_byte_equal_across_reruns` parametrised over all 10 cases asserts byte-equal serialized RunOutcome (passed + failure_reason + actuals, sorted-key JSON). **10/10 pass the probe.**      |
| **WI-4** No NLAH writes                                                     | `tests/test_tools_nlah_parser.py::test_wi4_parser_never_opens_in_write_mode` patches `Path.open` + `builtins.open` and asserts every observed mode is read-only (`r` / `rt` / `rb`) while the parser walks the real cloud_posture NLAH directory + eval cases. The integration test runs in CI as part of the standard test suite.                              |
| **WI-5** Q-ARCH-1 carry-forward                                             | **Named verbatim here so the A.4 v0.2 plan author can't miss it:** _"A.4 v0.2 plan MUST include subscriber-ACL review per ADR-012 since v0.2 introduces auto-acting behavior (NLAH auto-deploy)."_ When v0.2 adds the auto-deploy capability, A.4's `agent_id` MUST be appended to `_FORBIDDEN_SUBSCRIPTIONS` in `packages/shared/src/shared/fabric/client.py`. |

## ADR conformance

| ADR | Provision                                     | Verification                                                                                                                                                                                                                                                                                      |
| --- | --------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 005 | Async tool-wrapper convention                 | `BatchEvalRunner.run_batch` + `ab_compare` + `agent.run` + `kg_writer.upsert_*` all async; no blocking I/O on the event loop.                                                                                                                                                                     |
| 006 | LLM adapter                                   | `cli.run_cmd` does not directly import a vendor SDK. The threaded `llm_provider` parameter is the only path; A.4's own pipeline doesn't consume an LLM in v0.1.                                                                                                                                   |
| 007 | Reference NLAH (v1.1 + v1.2)                  | **v1.1** — no per-agent `llm.py`; smoke test `test_no_per_agent_llm_module` asserts. **v1.2** — `nlah_loader.py` is a 26-LOC shim over `charter.nlah_loader` (under the 35-LOC budget; verified by `test_nlah_loader_under_loc_budget`). A.4 is the **12th** agent shipped natively against v1.2. |
| 008 | Eval framework                                | `MetaHarnessEvalRunner` registered via `[project.entry-points."nexus_eval_runners"]`; bundled `eval/cases/*.yaml` parses via `load_cases`; `run_suite` orchestrates all 10. Direct-consume; no substrate hoist (Q-ARCH-3).                                                                        |
| 010 | Within-agent version extension                | Execution-status table above is the single source of truth for task-commit pinning; deferred features explicitly named in README §"Out of scope" + the 7 version-named deferrals.                                                                                                                 |
| 011 | PR-flow + branch protection discipline        | One-task-one-PR for all 16 tasks; LOW-RISK label on every PR (zero substrate touches; WI-1 substrate-sealed gate); verified-against-HEAD line in every PR body; no `--no-verify` / `--no-gpg-sign` shortcuts.                                                                                     |
| 012 | `claims.>` subject namespace + subscriber ACL | **A.4 v0.1 is NOT a publisher and NOT a subscriber on `claims.>`** — it's read-only against other agents' state, not against the claims bus. The subscriber-ACL fence (A.1 -> {claims.>}) is intact. WI-5 names the v0.2 carry-forward when A.4 becomes auto-acting.                              |

## Architecture notes for future maintainers

### First agent that reads other agents

A.4 is the first agent in the fleet that **reads other agents** — the reflective counterpart to every prior agent. Where each shipped agent looks outward at the customer environment, A.4 looks inward at the fleet: how each agent is configured, how its eval suite is performing, and whether the latest run's pass-rate has slipped since the previous run.

This makes A.4 the **architectural-foundation agent for the v0.2 second-pass conversation**. Every Hermes-pattern feature (skill creation, NLAH auto-deploy, autonomous curator) builds on A.4 v0.1's introspection + batch-eval + scorecard-delta primitives. v0.1's ruthlessly-narrow surface — five capabilities, zero substrate touches, zero auto-acting behavior — protects the v0.2 conversation from being pre-committed by v0.1 decisions.

### Read-only contract is load-bearing (WI-4)

A.4 v0.1 never writes to any agent's NLAH directory. The `tools/nlah_parser.py` uses `Path.read_text(encoding="utf-8")` exclusively; the `tools/ab_compare.py` `nlah_override` context redirects the per-agent loader to a variant path but the variant itself is only ever read. The runtime guard (`test_wi4_parser_never_opens_in_write_mode`) is the trip-wire: any future regression that introduces a write surface to the parser will fail this test.

**When v0.2 adds NLAH auto-deploy**, the auto-deploy path lives in a separate module (e.g., `tools/nlah_proposer.py`) and the WI-4 guard's scope shifts to assert that `tools/nlah_parser.py` remains read-only. The plan author's task is to keep the read-only path read-only — not to retroactively allow writes through the parser.

### Single-tenant `semantic_store=None` posture

A.4 v0.1's CLI defaults to "produce workspace markdown + log when KG persistence is skipped." This is consistent with every prior agent's posture (D.5 / D.6 / D.7 / D.8 / D.12 / D.13 all default to `semantic_store=None`). Multi-tenant production blocks on the future SET LOCAL `$1` tenant-RLS substrate-fix plan.

When the substrate-fix lands, A.4's driver gets a `--semantic-store-dsn` flag that wires a real instance + true delta tracking across runs. Until then, every run looks like a first-run.

### Stable-ordered batch + deterministic per-case payloads

`BatchEvalRunner._discover_entry_points` sorts entry points lexicographically by `name` so the Scorecard sequence is deterministic across machines + CI runs. `MetaHarnessEvalRunner.run`'s `actuals` payload is pure counts (no timestamps, no UUIDs) so the WI-3 byte-equal-across-reruns probe holds without stripping any fields. The eval suite's deterministic-by-construction shape is the foundation for any future regression-bisection workflow A.4 v0.2+ may introduce.

## Path-B sequence advance

**16 of 17 agents at v0.1.** Six of 7 unbuilt agents shipped under the [Path-B-breadth-first operating rule](../superpowers/sketches/2026-05-20-agent-version-roadmaps.md):

1. ✅ D.5 Data Security v0.1 (shipped 2026-05-20; PRs #56-#71)
2. ✅ D.8 Threat Intel v0.1 (shipped 2026-05-21; PRs #73-#88)
3. ✅ D.6 Compliance v0.1 (shipped 2026-05-21; PRs #89-#105)
4. ✅ D.13 Synthesis v0.1 (shipped 2026-05-21; PRs #106-#122)
5. ✅ D.12 Curiosity v0.1 (shipped 2026-05-21; PRs #124-#140; ADR-012 unblocker 2026-05-21)
6. ✅ **A.4 Meta-Harness v0.1 (shipped 2026-05-21; PRs #141-_this PR_)** — this record closes the loop.
7. Supervisor (#0) v0.1 — **next** (depends on all 16 prior agents; routes between them).

After Supervisor closes: **17/17 platform-complete-narrow-depth.** The second-pass v0.2 conversation opens at that point, with `docs/_meta/hermes-pattern-absorption-2026-05-22.md` (forthcoming) and this verification record's WI-5 carry-forward as the load-bearing inputs to A.4 v0.2's plan.

## Closure

A.4 Meta-Harness v0.1 is **CLOSED**. The 16/16 task table above is the single source of truth for what shipped. The WI-1..WI-5 watch-items are all green. The v0.2 plan author's job, when they pick this up, is to:

1. Read [docs/\_meta/hermes-pattern-absorption-2026-05-22.md](hermes-pattern-absorption-2026-05-22.md) (forthcoming) for the v0.2+ surface direction.
2. Honor the **WI-5 carry-forward** verbatim: A.4 v0.2's plan MUST review subscriber-ACL per ADR-012 since v0.2 introduces auto-acting behavior. Add A.4 to `_FORBIDDEN_SUBSCRIPTIONS["claims.>"]` (or the equivalent v0.2 subject) in the SAFETY-CRITICAL substrate PR that lands before any auto-deploy code.
3. Inherit the architectural primitives (`AgentManifest` / `Scorecard` / `BatchEvalRunner` / `ab_compare` / `nlah_override` / `compute_batch_deltas` / `flag_regressions` / `reporter`) from v0.1 unchanged where possible; if the v0.2 plan requires extending them, do so additively per ADR-010.
4. Re-evaluate Q-ARCH-2 (new fabric subject) and Q-ARCH-3 (eval-framework substrate hoist) against the v0.2 surface. If v0.2 needs real-time proposal emission OR a third consumer arrives for `BatchEvalRunner`, those deferrals close in v0.2; otherwise carry them forward to v0.3.

**Next plan in the Path-B sequence: Supervisor (#0) v0.1.**
