# D.13 Synthesis v0.1 — Verification Record

**Date:** 2026-05-21
**Plan:** [`docs/superpowers/plans/2026-05-21-d-13-synthesis-v0-1.md`](../superpowers/plans/2026-05-21-d-13-synthesis-v0-1.md)
**Operating rule:** [Path-B-breadth-first (2026-05-20)](../../packages/agents/synthesis/README.md#scope-v01) — every unbuilt agent ships to v0.1 in sketch §8 sequence before any v0.2+ work on a shipped agent.
**Outcome:** **D.13 v0.1 shipped.** 16 tasks, 17 PRs (plan + 16 task PRs), all merged to main. 214 tests passing (+ 1 live-LLM smoke skipped by default). 10/10 eval cases pass. WI-1 (first-LLM-call budget consumption) + WI-2 (Q6 no-classifier-substring posture) + WI-3 (stub-LLM byte-equal determinism) all verified at unit, eval, and CLI layers. Path-B sequence advances to **D.12 Curiosity** (blocks on F.7 `claims.>` substrate ADR; may skip to **A.4 Meta-Harness** if ADR still pending).

## Execution-status table

| Task | Status | PR   | Commit    | Summary                                                                                                                                                                                                                                                       |
| ---- | ------ | ---- | --------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| -    | ✅     | #106 | `c82eec4` | Plan doc — `2026-05-21-d-13-synthesis-v0-1.md` (16-task table, Q1-Q6, WI-1..WI-3, six-stage pipeline diagram).                                                                                                                                                |
| 1    | ✅     | #107 | `40d915f` | Package bootstrap — pyproject (BSL 1.1; nexus-investigation + nexus-compliance-agent + nexus-cloud-posture deps); py.typed + `__init__`; smoke tests covering ADR-007 v1.1 + v1.2 + LLM-adapter import + entry-point. 9 tests.                                |
| 2    | ✅     | #108 | `c19c9b9` | `schemas.py` — 7 pydantic types (`ContextBundle`, `OutlineSection`, `SynthesisOutline`, `NarrativeSection`, `ExecutiveSummary`, `SynthesisReport`, `ReviewVerdict`). Internal pydantic models; no OCSF emit in v0.1 per Q1. 20 tests.                         |
| 3    | ✅     | #109 | `3b7b946` | `tools/sibling_workspace_reader.py` — async loader for `findings.json` across 3 sibling agents. ADR-005 `asyncio.to_thread`. Forgiving on every failure mode. 12 tests.                                                                                       |
| 4    | ✅     | #110 | `df5d106` | `context_bundle.py` — Stage 2 ENRICH; **Q6 first-line scrub**. Strips `evidence.matched_text` / bucket-object key fragments / `finding_info.desc` from cloud-posture path. Surfaces classifier labels (not values). 16 tests including 4 Q6 invariant probes. |
| 5    | ✅     | #111 | `bfc138b` | `prompts/` — 3 markdown templates (`outline.md`, `narration.md`, `executive_summary.md`) loaded via `importlib.resources`. Q6 reminder block in narration + executive_summary templates. 11 tests.                                                            |
| 6    | ✅     | #112 | `d491fd1` | `narrator.py` — async 3-call LLM orchestration. `OutlineCallError` / `NarrationCallError` / `ExecutiveSummaryCallError`. Per-section failure is forgiving (placeholder body). Q6 retry banner injection. 20 tests using `FakeLLMProvider`.                    |
| 7    | ✅     | #113 | `920080b` | `reviewer.py` — deterministic narrative validator. Two layers (shape + Q6 substring guard). Regex patterns lifted verbatim from D.5's classifier patterns. `retry_hint=q6_violation` for narrator retry. 18 tests.                                            |
| 8    | ✅     | #114 | `c72d565` | `entities.py` (`SynthesisReportEntity`; entity_type=`synthesis_report`; external_id=`<customer_id>:<run_id>`) + `kg_writer.py` (SemanticStore upsert adapter; single-tenant `semantic_store=None` opt-in). 18 tests.                                          |
| 9    | ✅     | #115 | `d80261f` | `agent.py` — **6-stage driver** wiring INGEST → ENRICH → NARRATE → REVIEW → SUMMARIZE → HANDOFF. Q6 retry loop (budget=1). Fallback narrative on narrator typed errors. 15 driver tests.                                                                      |
| 10   | ✅     | #116 | `b99aa46` | NLAH bundle (Narrator persona README + tools.md + 3 examples: executive-summary / mixed-severity-narrative / q6-substring-rejection) + 26-LOC `nlah_loader.py` (under 35-LOC budget). 16 tests.                                                               |
| 11   | ✅     | #117 | `0bc7851` | `eval_runner.py` + 10 YAML cases (`eval/cases/01…10`). Stub LLMProvider via `FakeLLMProvider` with fixed 100/50 token counts. 18 tests (10 parametrised case-pass + 8 framework).                                                                             |
| 12   | ✅     | #118 | `d29be21` | `cli.py` — `synthesis run` + `synthesis eval` click commands. Live LLMProvider built from `charter.llm_adapter.config_from_env()`. One-line digest output. 14 CLI tests.                                                                                      |
| 13   | ✅     | #119 | `5272caf` | Stub-LLM eval harness refactor — canned LLM responses lifted from inline YAML into `eval/stub_responses/<case_id>/responses.json`. WI-3 byte-equal across reruns probe (×10 cases). 28 tests.                                                                 |
| 14   | ✅     | #120 | `f576e47` | Live-LLM smoke test (`tests/integration/test_live_llm_smoke.py`) gated by `NEXUS_LIVE_LLM=1`. Skipped in CI; operator-side WI-1 acceptance gate.                                                                                                              |
| 15   | ✅     | #121 | `315d12c` | README polish + smoke runbook. 4-step runbook (unit tests / eval / live agent / live-LLM smoke), 6-stage architecture diagram, prompt-template authoring guide.                                                                                               |
| 16   | ✅     | this | this PR   | This verification record + plan-doc execution-status table update + auto-memory advance.                                                                                                                                                                      |

## Gate results

| Gate                                            | Result                                                                   |
| ----------------------------------------------- | ------------------------------------------------------------------------ |
| `ruff check`                                    | clean (`All checks passed!`)                                             |
| `ruff format --check`                           | clean                                                                    |
| `mypy --strict`                                 | clean — 14 source files in `src/synthesis/`                              |
| `pytest packages/agents/synthesis`              | **214 passed, 1 skipped** in <1s (live-LLM smoke skipped by default)     |
| `synthesis eval` (bundled `eval/cases/`)        | **10/10 passed**                                                         |
| Operator-side `synthesis run --contract <path>` | exits 0; emits `narrative.md` + `executive_summary.md` + one-line digest |

## 10/10 eval acceptance

All 10 bundled cases pass via `SynthesisEvalRunner` (registered via the `nexus_eval_runners` entry point):

| Case ID                                    | Coverage                                                                                                                                    |
| ------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------- |
| `clean_no_findings`                        | Zero findings across all 3 sources; benign narrative.                                                                                       |
| `single_finding_narrative`                 | Single F.3 finding → 1-section narrative; cited-id thread-through.                                                                          |
| `multi_source_synthesis`                   | F.3 + D.6 spread; 2 sections; 3 cited findings after dedup.                                                                                 |
| `executive_summary_shape`                  | Exec summary H1 + Key Metrics + Run ID rendered.                                                                                            |
| `no_source_workspaces`                     | All 3 omitted; degraded but legal output; `review_retries=0`.                                                                               |
| `partial_workspace`                        | Single workspace (F.3 only); narrative scoped correctly.                                                                                    |
| `classifier_substring_rejection_and_retry` | **WI-2 retry probe**: pass 1 leaks SSN; pass 2 clean; `review_retries=1`; narrative.md excludes leaked substring.                           |
| `level_1_pinning_narrative`                | Level-1 vs Level-2 control-section ordering.                                                                                                |
| `stub_llm_determinism`                     | WI-3 substring contract.                                                                                                                    |
| `context_bundle_q6_invariant`              | **WI-2 invariant probe**: F.3 finding carries `evidence.matched_text`; bundle strips it; narrative.md excludes `SECRET_LEAK_DO_NOT_RENDER`. |

## Acceptance criteria (plan §Q1-Q6 + watch-items)

| Criterion                                                                      | Verification                                                                                                                                                                                                                                                                                               |
| ------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Q1.** Markdown reports (no OCSF emit in v0.1)                                | `agent.py` emits `narrative.md` + `executive_summary.md`. No `class_uid` discriminator wired. OCSF deferred to v0.2 per plan §Q1; tracked in [README §Deferred](../../packages/agents/synthesis/README.md#deferred-to-d13-v02--v03).                                                                       |
| **Q2.** 3 sibling sources via 3 flags (D.7 / D.6 / F.3)                        | `agent.run(...)` signature carries `investigation_workspace` / `compliance_workspace` / `cloud_posture_workspace`; `tools/sibling_workspace_reader.py` is the forgiving 3-source loader; `test_partial_workspace.yaml` exercises operator omission.                                                        |
| **Q3.** Reuse `charter.llm_adapter` (ADR-006); stub provider via local helper  | `narrator.py` imports `charter.llm.LLMProvider`; `cli.py` builds providers via `charter.llm_adapter.config_from_env()`; `eval_runner._build_stub_provider` wraps `charter.llm.FakeLLMProvider` with deterministic 100/50 token counts.                                                                     |
| **Q4.** Two-call → three-call structure (outline + per-section + exec summary) | `narrator.narrate()` issues 1 outline + N narration + 1 exec-summary calls; all 3 pin `temperature=0.0`; prompt templates loaded via `synthesis.prompts.load_prompt`.                                                                                                                                      |
| **Q5.** Single-tenant `semantic_store=None` opt-in default                     | `agent.run` defaults `semantic_store=None`; `kg_writer.upsert_synthesis_report` is a no-op-with-log when `None`; multi-tenant remains gated on the SET LOCAL `$1` tenant-RLS substrate-fix plan.                                                                                                           |
| **Q6.** Two-layer defence against classifier-substring leakage                 | **Layer 1** (Stage 2 ENRICH) verified by `test_context_bundle.py` 4 invariant probes (SSN / AWS access key / JWT / object-key fragments). **Layer 2** (Stage 4 REVIEW) verified by `test_reviewer.py` 18 tests including violation-name-only invariant. Both probed end-to-end via eval cases 07 + 10.     |
| **WI-1** Budget consumption wired via `charter.llm_adapter`                    | `narrator.SynthesisDraft` tracks `llm_call_count` + `total_tokens_used`. `test_narrator.py::test_narrate_tracks_llm_call_count` + `test_narrate_tracks_total_tokens` assert 1 + N + 1 calls; CLI exposes the count via the one-line digest. Live-LLM smoke (Task 14) is the operator-side acceptance gate. |
| **WI-2** Q6 narrative-substring posture                                        | Reviewer rejects classifier-shaped substrings; eval case 07 `classifier_substring_rejection_and_retry` exercises the full retry loop; eval case 10 `context_bundle_q6_invariant` exercises the bundle scrub. Both are bundled regression probes that must pass on every release.                           |
| **WI-3** Stub-LLM determinism (byte-equal across reruns)                       | Per-case canned responses in `eval/stub_responses/<case_id>/responses.json`. `test_stub_llm_harness::test_eval_output_byte_equal_across_two_runs` parametrised over all 10 cases verifies byte equality (timestamps stripped — datetime.now drifts between calls; prose body is identical).                |

## ADR conformance

| ADR | Provision                              | Verification                                                                                                                                                                                                                                           |
| --- | -------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 005 | Async tool-wrapper convention          | `sibling_workspace_reader.read_sibling_workspaces` uses `asyncio.gather` over `asyncio.to_thread`-wrapped per-source readers; no blocking filesystem I/O on the event loop.                                                                            |
| 006 | LLM adapter                            | Narrator imports `charter.llm.LLMProvider` Protocol; agent driver does not import `anthropic` / `openai` directly. CLI builds providers via `charter.llm_adapter.config_from_env()` + `make_provider()`.                                               |
| 007 | Reference NLAH (v1.1 + v1.2)           | **v1.1** — no per-agent `llm.py`; `narrator.py` calls `charter.llm.LLMProvider` directly. **v1.2** — `nlah_loader.py` is a 26-LOC shim over `charter.nlah_loader` (under the 35-LOC budget). D.13 is the **10th agent** shipped natively against v1.2. |
| 010 | Within-agent version extension         | Execution-status table is the single source of truth for task-commit pinning; deferred features documented in README §Deferred + plan §Next plans queued.                                                                                              |
| 011 | PR-flow + branch protection discipline | One-task-one-PR for all 16 tasks; LOW-RISK label on every PR (scoped to `packages/agents/synthesis/`); verified-against-HEAD line in every PR body; no `--no-verify` / `--no-gpg-sign` shortcuts.                                                      |

## Architecture notes for future maintainers

### First LLM-call agent in the fleet

D.13 is the first Nexus agent that calls the LLM in its hot path. The 13 agents before it (F.3, D.1-D.4, D.5, D.6, D.7, D.8, multi-cloud-posture, k8s-posture, F.6, A.1) plumb `llm_provider` through their drivers but never invoke it. D.13's `narrator.narrate()` makes 1 outline + N per-section + 1 exec-summary `LLMProvider.complete()` calls per run (doubled on Q6 retry).

This sets the pattern future LLM-driven agents (D.12 Curiosity, A.4 Meta-Harness, Supervisor #0) will follow:

- Inline prompts as markdown files loaded via `importlib.resources` (not Python string literals).
- Pydantic-validated structured JSON outputs (`SynthesisOutline`, `ExecutiveSummary`).
- Typed narrator errors (`OutlineCallError`, etc.) so the driver can branch on the error class.
- Per-section forgiving-fallback (placeholder body, not whole-run failure).
- Deterministic reviewer + retry-hint contract (Stage 4 REVIEW).

### Two-layer Q6 defence is non-negotiable

When you add a new finding source (D.12 Curiosity will be the next), the ENRICH layer must strip every freeform-substring field before the LLM ever sees it. The reviewer is the second line, not the first. Eval case 10 `context_bundle_q6_invariant` is the regression probe — any new source must add a case mirroring this shape.

### Stub vs live LLM

The eval suite is **always stub-mode** for reproducibility (WI-3 byte-equal acceptance). The CLI `synthesis run` is **always live-mode** (real LLM provider via `charter.llm_adapter.config_from_env()`). The live smoke test (`tests/integration/test_live_llm_smoke.py`) is the only other path that exercises a real LLM; it's gated by `NEXUS_LIVE_LLM=1` so CI runs cleanly.

### Single-tenant gate

D.13's `kg_writer` writes a `SynthesisReportEntity` to the SemanticStore only when an explicit `semantic_store` is passed. v0.1 default is `None`. Multi-tenant production remains blocked on the future SET LOCAL `$1` tenant-RLS substrate-fix plan (per the `feedback_path_b_breadth_first.md` auto-memory).

## Path-B sequence advances

D.13 was **#4 of the 7 unbuilt agents** in the Path-B-breadth-first ordering. After this closure:

- **14 of 17 agents at v0.1** (was 13 after D.6 closure on 2026-05-21).
- **Next agent:** D.12 Curiosity (5th in the sketch §8 sequence). **Blocked on:** F.7 `claims.>` substrate ADR. If ADR hasn't shipped, sequence skips to A.4 Meta-Harness.
- **Remaining v0.1 work:** D.12 Curiosity (or A.4) → A.4 Meta-Harness → Supervisor (#0).

## Cross-references

- Plan: [`docs/superpowers/plans/2026-05-21-d-13-synthesis-v0-1.md`](../superpowers/plans/2026-05-21-d-13-synthesis-v0-1.md)
- README + smoke runbook: [`packages/agents/synthesis/README.md`](../../packages/agents/synthesis/README.md)
- Sketch §5 (D.13 scope + LLM-call structure): [`docs/superpowers/sketches/2026-05-20-remaining-agents-sketch.md`](../superpowers/sketches/2026-05-20-remaining-agents-sketch.md)
- Sister agents in Path-B sequence: [D.5 v0.1](d-5-data-security-v0-1-verification-2026-05-21.md) · [D.8 v0.1](d-8-threat-intel-v0-1-verification-2026-05-21.md) · [D.6 v0.1](d-6-compliance-v0-1-verification-2026-05-21.md)
