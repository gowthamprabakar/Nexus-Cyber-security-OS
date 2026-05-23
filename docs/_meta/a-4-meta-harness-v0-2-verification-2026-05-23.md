# A.4 Meta-Harness Agent v0.2 — Verification Record

**Date closed:** 2026-05-23
**Plan:** [docs/superpowers/plans/2026-05-22-a-4-meta-harness-v0-2.md](../superpowers/plans/2026-05-22-a-4-meta-harness-v0-2.md)
**Status:** **CLOSED — 16/16 tasks merged.** A.4 v0.2 is **Wave 0 of Phase 1 (Maturity-First)** complete. The platform's first auto-acting Meta-Harness — composing SKILL.md candidates from successful agent runs, eval-gating them, and auto-deploying to target agents' NLAH directories. Becomes the **third forbidden subscriber** under ADR-012, closing the Q-ARCH-1 trajectory predicted in Supervisor v0.1's verification record.

**Strategic significance.** A.4 v0.2 installs the foundation layer for all subsequent Phase 1 waves. Wave 1 (F.3 v0.2 → multi-cloud-posture v0.2 → k8s-posture v0.2) and every wave after inherits the compounding learning loop. From this point forward, agents accumulate institutional memory per-customer.

## Execution status (16/16)

| Task | Status | Commit   | PR       | Notes                                                                                                                                                                                                                                             |
| ---- | ------ | -------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Plan | ✅     | 6a9f385  | #176     | Plan doc (394 lines); landed on main 2026-05-22.                                                                                                                                                                                                  |
| 1    | ✅     | 9e00822  | #177     | Bootstrap v0.2 — version bump (`0.1.0` → `0.2.0`); 4 Q-ARCH guard extensions; `charter.llm_adapter` now-permitted; backwards-compat regression probe (byte-equal against empty skills dir). 14 smoke tests.                                       |
| 2    | ✅     | c213f26  | #178     | `schemas.py` extension — 5 skill-lifecycle types (`Skill`, `SkillCandidate`, `SkillClassKey`, `DeploymentDecision`, `EvalGateResult`). 14 schema tests.                                                                                           |
| 3    | ✅     | b43b88d  | #179     | `skill_format.py` — agentskills.io YAML frontmatter parser + writer; Nexus-specific fields validated; `write_skill_md` + `parse_skill_md`. 12 tests.                                                                                              |
| 4    | ✅     | d8356f9  | #180     | **SAFETY-CRITICAL.** `charter.nlah_loader` v1.4 progressive-disclosure extension (`default_skills_dir`, `load_skill_metadata_index`, `load_skill`, `load_skill_reference`). Paired with ADR-007 v1.4 amendment. 14 tests.                         |
| 5    | ✅     | d485ba9  | #182     | `skill_discovery.py` — per-agent + cross-agent registry walk; `discover_agent_skill_index` / `discover_cross_agent_skill_registry`. 12 tests.                                                                                                     |
| 6    | ✅     | 6380a36  | #183     | `skill_triggers.py` — 3-condition gate (≥5 tool calls + successful + hash-novel). `compute_tool_sequence_hash` + `should_trigger_skill_creation`. 13 tests.                                                                                       |
| 7    | ✅     | 72170c8  | #184     | `skill_writer.py` — LLM-compose `SKILL.md` via `charter.llm_adapter`; shadow-path write; provenance populated from audit-chain refs. 13 tests including stub-LLM WI-3 byte-equal probe.                                                           |
| 8    | ✅     | bbac42b  | #185     | `skill_eval_gate.py` — mandatory Option-B eval-gate (two runs per candidate: baseline + with-candidate); `with_candidate_skill_overlay` context; per-case regression ≥5% threshold. 14 tests.                                                     |
| 9    | ✅     | 824a567  | #186     | `skill_registry.py` — skill-class registry at `<workspace>/.nexus/skill-class-registry.json`; first-of-class `(agent_id, category)` operator gate; auto-deploy decision rule. 10 tests.                                                           |
| 10   | ✅     | 6cb7a7e  | #187     | `skill_approval.py` — file-based approval workflow; candidate-notification markdown writer; shadow → canonical promotion. 10 tests.                                                                                                               |
| 11   | ✅     | ae3d622  | #188     | **SAFETY-CRITICAL.** `_FORBIDDEN_SUBSCRIPTIONS["meta_harness"] = frozenset({"claims.>"})` in `packages/shared/src/shared/fabric/client.py` + ADR-012 v1.1 amendment (third entry; closes future-auto-acting paragraph). 7 tests.                  |
| 12   | ✅     | df05a47  | #189     | `audit_emit.py` extension — 4 additive `meta_harness.skill.*` actions (`candidate_emitted` / `eval_gate_completed` / `deployed` / `rejected`). Total 8 `meta_harness.*` actions. 10 tests.                                                        |
| 13   | ✅     | d79afdb  | #190     | Driver extension — Stage 6 SKILL_TRIGGER + Stage 7 SKILL_CREATE; `skill_lifecycle.py` orchestration; v0.1 Stage 6 HANDOFF → Stage 8. 16 tests.                                                                                                    |
| 14   | ✅     | 2e01258  | #191     | NLAH bundle v0.2 — persona reflects auto-acting capability; `04-skill-curation.md` example; `tools.md` updated with skill-lifecycle helpers. 17 tests.                                                                                            |
| 15   | ✅     | efd0c75  | #193     | CLI extension (`approve-skill` / `reject-skill` / `list-skills`) + `skill_candidate_store.py` sidecar layer + eval-runner skill-lifecycle extension + 5 new eval cases (11-15). 20 CLI tests + 10 sidecar tests + 5 new cases = 35 net-new tests. |
| 16   | ✅     | _see PR_ | _see PR_ | This verification record + closure.                                                                                                                                                                                                               |

**Test surface at close:** 392 tests across 27 test modules. ruff check + ruff format --check + mypy --strict clean.

## Eval suite acceptance

`meta-harness eval` → **15/15 PASS**, deterministic via the stub-LLM harness. All 15 cases also pass the WI-3 byte-equal-across-reruns probe (`tests/test_stub_llm_harness.py`).

| Case                                    | Verifies                                                                                                        |
| --------------------------------------- | --------------------------------------------------------------------------------------------------------------- |
| `01_clean_batch`                        | 3 agents, all pass, 0 regressions; placeholder text rendered.                                                   |
| `02_one_agent_regression`               | Prior 100% / current 0% on one of two → 1 regression flagged.                                                   |
| `03_multi_agent_regression`             | 2 of 3 cross threshold; 1 improves; multi-agent regression formatting.                                          |
| `04_ab_comparison_clean`                | Variants identical → `byte_equal=True`.                                                                         |
| `05_ab_comparison_divergent`            | Variants differ → `ab_present=True`; per-case delta surfaces.                                                   |
| `06_single_agent_failed_eval_tolerated` | One agent's runner raises ImportError; batch continues.                                                         |
| `07_never_prior_scorecard`              | No prior rows → all first-run; 0 regressions.                                                                   |
| `08_watch_list_population`              | Empty watch-list placeholder rendered.                                                                          |
| `09_introspection_shape`                | Synthetic agents have no NLAH dir; `manifest_count=0`.                                                          |
| `10_kg_upsert_skipped_when_none`        | `semantic_store=None` → no upsert calls.                                                                        |
| `11_skill_lifecycle_skipped`            | **v0.2** — lifecycle disabled → empty summary; backwards-compat probe (drift #5).                               |
| `12_skill_eval_gate_fail_reject`        | **v0.2** — trigger fires, eval-gate fails (`fail_when_overlay: true`) → candidate rejected; sidecar cleaned up. |
| `13_skill_auto_deploy`                  | **v0.2** — class pre-registered → auto-deploy on eval-gate pass; sidecar cleaned up.                            |
| `14_skill_first_of_class_pending`       | **v0.2** — new class → notification markdown written; candidate pending operator review.                        |
| `15_skill_no_trigger`                   | **v0.2** — <5 tool calls → Q3 condition 1 fails → no trigger; lifecycle summary stays empty.                    |

## Acceptance criteria (plan §Q1-Q6 + Q-ARCH-1/2/3/4 + watch-items)

| Criterion                                                                             | Verification                                                                                                                                                                                                                                                             |
| ------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Q1.** Skill storage: per-agent in-repo `nlah/skills/<category>/<skill>/SKILL.md`    | Shadow path at `<workspace>/.nexus/candidate-skills/<agent>/<skill_id>/SKILL.md`; canonical path at `packages/agents/<agent>/src/<agent>/nlah/skills/<skill_id>/SKILL.md`. `skill_approval._promote_to_canonical` moves shadow → canonical. CLI tests assert both paths. |
| **Q2.** Skill format: agentskills.io + Nexus frontmatter extensions                   | `skill_format.py` validates 10 frontmatter fields (`name`, `description`, `version`, `platforms`, `target_agent`, `category`, `created_by`, `provenance`, `eval_gate_status`, `deployment_status`). Parse + write round-trip tests.                                      |
| **Q3.** Trigger criteria: ≥5 tool calls + successful + hash-novel                     | `skill_triggers.py` 3-condition gate. Eval case 15 (<5 calls → no trigger) and case 12 (trigger fires) are the acceptance probes.                                                                                                                                        |
| **Q4.** Eval-gate: A.4-local using `BatchEvalRunner` + `with_candidate_skill_overlay` | `skill_eval_gate.py` Option-B (two eval runs per candidate). `with_candidate_skill_overlay` wraps `nlah_override`. CLI has no `--force`. Eval case 12 is the fail-reject probe; case 13 is the pass-deploy probe.                                                        |
| **Q5.** Approval: file-based + CLI; first-of-class operator gate                      | `skill_registry.py` tracks `(agent_id, category)` pairs. Auto-deploy when class registered (case 13); notification + CLI approval needed otherwise (case 14). `approve-skill` / `reject-skill` / `list-skills` wired in Task 15 CLI.                                     |
| **Q6.** Audit posture: 4 additive `meta_harness.skill.*` entries                      | `audit_emit.py` extended with `skill.candidate_emitted` / `.eval_gate_completed` / `.deployed` / `.rejected`. Total 8 `meta_harness.*` actions. F.6 hash-chain semantics inherited.                                                                                      |
| **Q-ARCH-1.** `_FORBIDDEN_SUBSCRIPTIONS["meta_harness"]`                              | **Task 11 — DONE.** Third forbidden subscriber. Trajectory predicted in Supervisor v0.1's WI-5 closes here.                                                                                                                                                              |
| **Q-ARCH-2.** Eval-gate mandatory; no `--force`                                       | CLI has no `--force` flag. Eval-gate cannot be bypassed.                                                                                                                                                                                                                 |
| **Q-ARCH-3.** First-of-class operator approval                                        | `skill_registry.py` first-of-class gate. `approve-skill` CLI is the operator path.                                                                                                                                                                                       |
| **Q-ARCH-4.** Progressive-disclosure NLAH loader                                      | **Task 4 — DONE.** `charter.nlah_loader` v1.4 additive extension. Paired with ADR-007 v1.4.                                                                                                                                                                              |

## ADR conformance

| ADR | Provision                              | Verification                                                                                                                                                                                                                                                                                                        |
| --- | -------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 005 | Async tool-wrapper convention          | `agent.run` + `skill_lifecycle.run_pipeline` + `skill_eval_gate.run_eval_gate` all async.                                                                                                                                                                                                                           |
| 006 | LLM adapter                            | Stage 7 consumes LLM via `charter.llm_adapter` (same pattern as D.13/D.12). Task 7's stub-LLM harness enables deterministic byte-equal probes.                                                                                                                                                                      |
| 007 | Reference NLAH (v1.1 + v1.2 + v1.4)    | v1.1 — no per-agent `llm.py`. v1.2 — 26-LOC `nlah_loader.py` shim. v1.4 — progressive-disclosure `skills/` loader (Task 4; SAFETY-CRITICAL).                                                                                                                                                                        |
| 008 | Eval framework                         | `MetaHarnessEvalRunner` registered via `nexus_eval_runners`. 15 bundled YAML cases. Direct-consume; no substrate hoist.                                                                                                                                                                                             |
| 010 | Within-agent version extension         | Execution-status table is single source of truth. 7 version-named deferrals explicit in plan §"Out of scope".                                                                                                                                                                                                       |
| 011 | PR-flow + branch protection discipline | One-task-one-PR for all 16 tasks. LOW-RISK on 14 tasks; SAFETY-CRITICAL on Tasks 4 + 11. No `--no-verify` / `--no-gpg-sign` shortcuts. Task 15 + 16 initially bundled in #192; split into #193 + this PR per ADR-011 discipline (verification record requires independent prior-task merge for honest attestation). |
| 012 | `claims.>` subscriber ACL              | **Third forbidden subscriber: `meta_harness`** (Task 11). A.4 v0.2 is auto-acting; blocked from claims bus. Q-ARCH-1 trajectory closes at 3 entries (`remediation` + `supervisor` + `meta_harness`).                                                                                                                |

## Watch-items (WI-1 through WI-5)

| WI                                                             | Status   | Verification                                                                                                                                                                                                                                                   |
| -------------------------------------------------------------- | -------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **WI-1** Substrate sealed except Tasks 4 + 11                  | ✅ GREEN | `git diff --stat packages/charter/ packages/shared/` empty across Tasks 1-3, 5-10, 12-16. Task 4 bounded to `charter/nlah_loader.py` additive + ADR-007 v1.4. Task 11 bounded to `_FORBIDDEN_SUBSCRIPTIONS["meta_harness"]` + ADR-012 v1.1.                    |
| **WI-2** Single-tenant default                                 | ✅ GREEN | `semantic_store=None` inherited from v0.1. Per-customer skill isolation deferred to v0.x post-SET-LOCAL-fix.                                                                                                                                                   |
| **WI-3** Stub-LLM determinism extended to skill content        | ✅ GREEN | Task 7 `stub_responses/` per-case `responses.json` enables byte-equal probe across reruns. `test_stub_llm_harness.py::test_wi3_byte_equal_across_reruns` parametrised over all 15 cases — all pass.                                                            |
| **WI-4** Auto-deploy safety rails                              | ✅ GREEN | No skill deploys without eval-gate pass + first-of-class operator approval. Two eval runs per candidate (Option B baseline). CLI has no `--force`. Eval cases 12-14 exercise all three routing paths.                                                          |
| **WI-5** Q-ARCH-1 trajectory CLOSED at 3 forbidden subscribers | ✅ GREEN | `_FORBIDDEN_SUBSCRIPTIONS` now contains `remediation` + `supervisor` + `meta_harness`. The trajectory predicted in Supervisor v0.1's WI-5 completes here. Q-ARCH-1 trajectory CLOSED at three forbidden subscribers; no further pending additions for Phase 1. |

## Substrate touch summary

Two SAFETY-CRITICAL substrate touches (per plan):

1. **Task 4 — `charter.nlah_loader` v1.4.** `default_skills_dir()`, `load_skill_metadata_index()`, `load_skill()`, `load_skill_reference()` — additive; existing functions (`default_nlah_dir`, `load_system_prompt`) unchanged. Paired with ADR-007 v1.4 amendment.
2. **Task 11 — `_FORBIDDEN_SUBSCRIPTIONS["meta_harness"]`.** ~5 lines in `packages/shared/src/shared/fabric/client.py`. Paired with ADR-012 v1.1 amendment (third subscriber-ACL entry).

Zero other substrate changes across all 16 tasks. WI-1 diff-empty gate confirmed.

## Carry-forwards to v0.2.5+ (9 items)

These are **consciously accepted debt** that the v0.2 plan explicitly deferred or discovered during execution. Named here so the v0.2.5 plan author and future maintainers can find them.

1. **DSPy+GEPA v0.2.5 follow-up cycle.** The [prompt-optimization strategic analysis](dspy-gepa-prompt-optimization-2026-05-22.md) (f1a05a7, #181) lays out DSPy teleprompter integration with GEPA evaluation. v0.2's stub-LLM eval harness + skill-content byte-equal probe are the prerequisite building blocks. v0.2.5 must cite that analysis in its plan and wire the first DSPy optimizer against the Q3 trigger prompt + Stage 7 skill-composition prompt.

2. **Forensic-visibility gap — silent swallow in mid-pipeline helpers.** v0.2's `skill_lifecycle.py` uses `_safely` wrappers around Stage 6 (trigger) and Stage 7 (compose). When a mid-pipeline exception occurs (LLM call fails, compositor raises, registry write fails), the `_safely` helper catches the exception, emits `_LOG.warning`, and returns gracefully — but does NOT emit to the F.6 audit chain. This means a skill-lifecycle failure is visible in workspace logs but invisible to downstream agents that consume the audit log (D.6 Compliance Agent, Supervisor). Fix shape: new `meta_harness.skill.lifecycle_error` audit action emitted from the `_safely` helpers on exception. Related: the audit payloads also don't carry the raw LLM prompt/response for successful compositions — the `provenance` frontmatter points to the audit-log path + entry hash, but the LLM transcript itself lives only in workspace logs. v0.2.5 should address both: error-emission for failures, LLM-transcript recording for successes.

3. **`--force` bypass absent (by design — Q4 + Task 8 + Task 14; triple-gate discipline).** No `--force` flag exists anywhere in the skill-lifecycle pipeline. The prohibition originates from Q4 of the v0.2 plan (operator directive: eval-gate is mandatory), was implemented in Task 8 (eval-gate built without `--force` flag), and reinforced in Task 14 (NLAH persona §"What you do NOT do"). Task 15's CLI inherited this constraint; adding `--force` here would have been a discipline violation against all three prior gates. v0.2.5 may add `--force` for emergency unblock workflows, but it MUST be paired with a forcible audit entry and an ADR amendment.

4. **ContextVar for active skill overlay (over monkeypatch).** `with_candidate_skill_overlay` uses `ContextVar` (`get_active_skill_overlay` / `set_active_skill_overlay`) rather than monkeypatching module-level state. This choice was deliberate — ContextVars are async-safe, thread-safe, and don't leak between concurrent eval-gate runs. The `nlah_override` monkeypatch from v0.1 is preserved for v0.1 callers but v0.2's new code uses ContextVars exclusively. v0.2.5 should migrate `nlah_override` to ContextVar as well, then deprecate the monkeypatch path.

5. **Skill-class registry single-tenant.** `<workspace>/.nexus/skill-class-registry.json` is per-workspace, not per-customer. Multi-tenant production (per-customer registry isolation) blocks on the SET LOCAL `$1` tenant-RLS substrate-fix. Until then, the registry file is a single-tenant artifact.

6. **Audit-payload compactness — decision in chain, detail in cached JSON.** Task 12's `audit_emit.py` `meta_harness.skill.eval_gate_completed` action carries the regression COUNT in the audit payload for downstream decision-making (Supervisor can act on "3 regressions" without loading detail). The full per-case regression LIST — which cases failed, by what margin, against which baseline — is written to `eval_gate_result.json` beside the shadow `SKILL.md`. D.6 Compliance Agent's v0.2 evidence-package generation will need to cross-reference BOTH layers: the audit chain for the decision timestamp + count, the cached JSON for per-case evidentiary detail. v0.2.5's eval cases should be updated to assert both layers if F.6's schema or D.6's evidence requirements evolve.

7. **`skill_lifecycle.py` as DSPy substitution seam.** The `skill_lifecycle.py` orchestrator is deliberately structured as a DSPy-compatible pipeline: deterministic trigger → LLM compose → deterministic eval-gate. Each stage has a clean input/output boundary. When v0.2.5 wires DSPy, the `_build_lifecycle_kwargs` helper in `eval_runner.py` is the injection point for the optimized prompts. The evaluation harness already produces the metric (15/15 pass) that DSPy's teleprompter optimizes against.

8. **Trust-boundary design carries forward.** A.4 v0.2 writes to other agents' NLAH directories — the first agent in the fleet to do so. The trust model is: A.4 is trusted because (a) it's blocklisted from `claims.>` (Q-ARCH-1), (b) eval-gate is mandatory (Q-ARCH-2), and (c) first-of-class requires operator approval (Q-ARCH-3). v0.2.5+ must carry this trust model forward when adding new auto-acting capabilities (curation, NLAH refactoring, cross-agent skill porting).

9. **Sidecar store (`skill_candidate_store.py`) — legitimate plan gap discovered during Task 15 execution.** The original v0.2 plan assumed in-process skill-lifecycle — candidate metadata (`tool_sequence_hash`, `emitted_at`) was available in-memory from the driver run. Task 15's out-of-process CLI flow (`approve-skill` / `reject-skill` / `list-skills`) surfaced the gap: the operator runs the CLI hours or days after candidate emission, and the in-memory `SkillCandidate` is gone. The sidecar (`<workspace>/.nexus/candidate-skills/<agent>/<skill_id>/candidate_meta.json`) fills this gap as an additive, file-adjacent JSON store. It is NOT scope creep: the three alternatives were (a) lose the hash → incomplete registry, (b) hijack SKILL.md frontmatter with non-standard fields → break agentskills.io interop, or (c) sidecar JSON file (chosen). Lifecycle parity is mechanically enforced (created in Task 7 by `skill_writer.py`, deleted in Task 10 by `_promote_to_canonical` + `reject_candidate`). Fails loud on absence (`CandidateNotFoundError`). Forward-compatible with v0.2.5 DSPy+GEPA: the sidecar write happens after the compositor produces a `SkillCandidate`; the compositor implementation (single-LLM → DSPy-compiled program) does not affect the post-compositor sidecar contract. Eval cases 12-14 explicitly assert `candidate_meta_exists` after each routing path.

## Architecture notes for future maintainers

### First auto-acting agent in the fleet

A.4 v0.2 is the platform's **first agent that writes to other agents' directories.** v0.1 was read-only diagnostics — it looked at agents but never touched them. v0.2 crosses that line with surgical precision: only the `skill_approval._promote_to_canonical` path writes to another agent's NLAH directory, and only after eval-gate pass + operator approval (for first-of-class) or auto-deploy (for registered classes).

This is the architectural precedent for every future auto-acting agent. The three-rail safety model — bus isolation (`_FORBIDDEN_SUBSCRIPTIONS`), mandatory eval-gate, and operator gate for novel capabilities — is the template for Phase 1's remaining auto-acting agents.

### Skill sidecar store is the out-of-band metadata layer

Task 15 discovered a plan gap and introduced `skill_candidate_store.py` — a sidecar JSON file (`candidate_meta.json`) that sits beside each shadow `SKILL.md`. The SKILL.md YAML frontmatter carries the agentskills.io fields; the sidecar carries the out-of-band fields (`tool_sequence_hash`, `emitted_at`) that the CLI needs to reconstruct a full `SkillCandidate` pydantic object from disk.

This pattern — in-band format (YAML/markdown) + out-of-band sidecar (JSON) — is load-bearing for the approval workflow. The CLI's `approve-skill` / `reject-skill` / `list-skills` commands all read from the sidecar, not from the SKILL.md. See carry-forward #9 above for the full plan-gap analysis. v0.2.5's curator (N3) will extend the sidecar with per-skill telemetry fields.

### Three eval-gate routing paths (tested)

The eval-runner extension (Task 15) exercises all three skill-lifecycle routing paths:

1. **Eval-gate fail → reject.** Case 12: `fail_when_overlay: true` makes the synthetic agent fail under the candidate overlay → `skill_rejected_count: 1`, sidecar cleaned up.
2. **Class registered → auto-deploy.** Case 13: registry pre-populated with `(investigation, iam-privesc)` class → `skill_auto_deploy_count: 1`, sidecar cleaned up.
3. **First-of-class → notification pending.** Case 14: new class not in registry → `skill_pending_review_count: 1`, notification file written, sidecar preserved.

Case 11 (lifecycle skipped — backwards compat) and case 15 (<5 tool calls — no trigger) are the negative-control probes.

### Deterministic-by-construction eval suite

The 15-case eval suite is deterministic end-to-end. All 15 cases pass the WI-3 byte-equal-across-reruns probe because:

- `llm_responses` in the fixture provide canned LLM output (no real provider calls).
- `_SyntheticAgent` run outcomes are pure counts + fixed payloads (no timestamps, no UUIDs).
- `_canonical_bytes` strips only legitimately-variable fields (`duration_sec`, trace timestamps).

This deterministic-by-construction shape is the prerequisite for DSPy integration in v0.2.5 — the DSPy teleprompter optimizes against a metric, and 15/15 pass is that metric.

### ADR-011 note: Tasks 15 + 16 unbundled

PR #192 initially bundled Tasks 15 and 16 together. Per ADR-011's per-task PR cadence and the requirement that the verification record honestly attest to a prior-merged task, the bundle was split: PR #193 (Task 15 standalone, merged at `efd0c75`) and this PR (Task 16, rebased onto post-Task-15 main at `6284a35`). The verification record now references Task 15's **actual merged commit hash** (`efd0c75`) and **actual PR number** (#193) — no circular attestation.

## Path-B sequence: all 17 agents at v0.1; A.4 v0.2 is Wave 0

**All 17 agents shipped v0.1** (16 agent family + Supervisor #0 closed 2026-05-21). Path-B breadth-first operating rule satisfied.

**Wave 0 of Phase 1 closes here.** The compounding learning loop is installed. Next in sequence:

- **Wave 1:** F.3 v0.2 → multi-cloud-posture v0.2 → k8s-posture v0.2 (CSPM family, live mode).
- **Wave 2:** D.5 v0.2 → D.6 v0.2 (Data + Compliance).
- **Wave 3:** D.4 v0.2 → D.3 v0.2 → D.8 v0.2 (Threat layer).
- **Wave 4:** D.2 v0.2 → D.1 v0.2 (Identity + Vulnerability).
- **Wave 5:** D.7 v0.2 → D.12 v0.2 → D.13 v0.2 (Smart layer).
- **Wave 6:** A.4 v0.3 (Curator — N3) + F.6 v0.2 (Compliance reporting).

## Closure

A.4 Meta-Harness v0.2 is **CLOSED**. The 16/16 task table above is the single source of truth for what shipped. WI-1 through WI-5 are all green. The **Q-ARCH-1 trajectory closes** — `_FORBIDDEN_SUBSCRIPTIONS` now contains the final v0.2 set: `remediation` + `supervisor` + `meta_harness`. No further pending additions in Phase 1.

**Wave 0 → Wave 1 handoff**: the compounding learning loop is in place. Every agent from Wave 1 forward inherits a platform that learns from successful runs. The v0.2.5 plan author's job is to wire DSPy+GEPA against the deterministic eval suite documented here, then extend the skill-lifecycle pipeline with the N3 Curator's similarity-based dedup + per-skill telemetry.

**Critical — v0.2.5 plan prerequisite.** v0.2.5 requires its own plan doc (same shape as PR #176) before any v0.2.5 task PRs open. The strategic brief at `docs/_meta/dspy-gepa-prompt-optimization-2026-05-22.md` alone is INSUFFICIENT to begin v0.2.5 task PR work. The plan doc must decompose the DSPy+GEPA cycle into concrete tasks, name the carry-forwards from this record that each task addresses, and link the 15-case deterministic eval suite as the acceptance metric. This is not optional — ADR-011 per-task cadence requires a plan to branch from, and the 9 carry-forwards above are the plan's starting checklist.

The 9 carry-forwards above are the v0.2.5 plan's starting checklist.
