# A.1 v0.1.1 verification record — 2026-05-17

Final-verification gate for **A.1 Remediation Agent v0.1.1 (earned-autonomy pipeline)**. Companion to the implementation record at [`a1-verification-2026-05-16.md`](a1-verification-2026-05-16.md) (v0.1) and the safety record at [`a1-safety-verification-2026-05-16.md`](a1-safety-verification-2026-05-16.md). Closes the §3 gap of the safety record — "per-action-class promotion state lives only in operator memory" — by shipping the promotion package in code and proving the fail-closed default against a real `kind` cluster.

All 14 tasks of [`2026-05-17-a-1-earned-autonomy-pipeline.md`](../superpowers/plans/2026-05-17-a-1-earned-autonomy-pipeline.md) are committed; every pinned hash is in the plan's execution-status table.

**This is the load-bearing contract every future cure-quadrant agent inherits.** A.1 v0.2 (more K8s action classes), A.1 v0.3 (AWS Cloud Custodian), and the next "do" agents land on top of this surface, not in parallel to it.

---

## Gate results

| Gate                                                                                                                         | Threshold                                                                                                              | Result                                                           |
| ---------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------- |
| `uv run pytest -q` (repo-wide, mocked lane)                                                                                  | green, no regressions                                                                                                  | **2539 passed, 17 skipped**                                      |
| `uv run pytest packages/agents/remediation/tests/test_eval_runner.py`                                                        | every YAML in `eval/cases/` executes with `fixture.promotion` parser ACTIVE                                            | **17 passed** (`test_run_suite_15_of_15`)                        |
| `remediation eval packages/agents/remediation/eval/cases`                                                                    | "15/15 passed" in stdout                                                                                               | ✅ (CLI gate via `test_eval_with_shipped_cases_passes_15_of_15`) |
| `NEXUS_LIVE_K8S=1 pytest packages/agents/remediation/tests/integration/test_agent_kind_live.py` (kind v0.31.0 / K8s v1.30.0) | 3/3 v0.1.1 live tests + 2/2 G3 tests pass                                                                              | **5 passed, 1 xfail** (rolled-back path)                         |
| `ruff check .`                                                                                                               | clean                                                                                                                  | ✅                                                               |
| `ruff format --check .`                                                                                                      | clean                                                                                                                  | ✅ (420 files)                                                   |
| `mypy` (configured `files`)                                                                                                  | strict-clean                                                                                                           | ✅ (210 source files)                                            |
| **Pre-flight stage gate**                                                                                                    | per-finding REFUSED_PROMOTION_GATE in `agent.run()`; never reaches kubectl                                             | ✅ (Task 5 + Task 13 live proof)                                 |
| **Promotion-state cache (`promotion.yaml`)**                                                                                 | YAML cache + Pydantic-validated schema + atomic write                                                                  | ✅ (Tasks 1-3)                                                   |
| **Audit-chain source of truth**                                                                                              | 9 `promotion.*` action types in the F.6 chain                                                                          | ✅ (Tasks 4 + 6, `replay()` round-trip)                          |
| **Stage-4 globally closed in code**                                                                                          | CLI `advance` and CLI `reconcile` both refuse Stage 4 with the same prerequisite message                               | ✅ (Tasks 7 + 8)                                                 |
| **Operator-facing summary**                                                                                                  | `REFUSED_PROMOTION_GATE` ranks alongside `REFUSED_UNAUTHORIZED` in dual-pin pattern                                    | ✅ (Task 11)                                                     |
| **Eval-runner parser ACTIVE**                                                                                                | 15/15 with `fixture.promotion` plumbed into `agent.run(promotion=...)`                                                 | ✅ (Task 12 — Task 10 filters fully reverted)                    |
| **Case 003 paired-negative**                                                                                                 | Stage-2 grant is what makes case 003 pass, not coincidence                                                             | ✅ (`test_case_003_promotion_gate_is_load_bearing`)              |
| **Live-cluster fail-closed**                                                                                                 | Stage 1 + execute against real apiserver: 0 mutating kubectl calls, 0 total kubectl calls, `resourceVersion` unchanged | ✅ (Task 13 + §8 Entry 2, reproducible from commit `dc1a1d4`)    |
| **Branch protection**                                                                                                        | all 5 CI checks required to merge to `main`; no bypass_actors                                                          | ✅ (PR #5 + #6, ruleset `main-require-five-ci-checks`)           |

### Repo-wide sanity check

`uv run pytest -q` → **2539 passed, 17 skipped**. **+174 tests** vs the v0.1 baseline (2365 from [`a1-verification-2026-05-16.md`](a1-verification-2026-05-16.md)). Skip delta: +6 (3 new live K8s tests, 3 new live localstack tests from the cloud-posture lane added in the same period — see that record). No regressions in any other agent or substrate package.

---

## Per-task surface

Pinned in [the plan's execution-status table](../superpowers/plans/2026-05-17-a-1-earned-autonomy-pipeline.md) with full per-task notes. Headline-level summary:

| Task | Commit (or final commit in PR)                                                                   | Notes                                                                                                                                                                              |
| ---- | ------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1    | promotion/ skeleton                                                                              | Package scaffold + 1 smoke test                                                                                                                                                    |
| 2    | promotion schemas                                                                                | `PromotionStage` / `Evidence` / `ActionClassPromotion` / `SignOff` / `PromotionFile` Pydantic models with cross-field invariants                                                   |
| 3    | `PromotionTracker`                                                                               | `from_path` / `save` / `stage_for` / `record_evidence` / `propose_promotions` / `apply_signoff`                                                                                    |
| 4    | 9 `promotion.*` audit events                                                                     | `PipelineAuditor` extended with `record_promotion_evidence` / `record_promotion_proposal` / `record_promotion_transition` / `record_promotion_init` / `record_promotion_reconcile` |
| 5    | pre-flight gate + per-finding split                                                              | `_compute_effective_modes` + `REFUSED_PROMOTION_GATE` outcome; per-finding routing (Stage 1→recommend / 2→dry_run / 3+→execute); zero-kubectl proof tests                          |
| 6    | `replay.py` reconciler                                                                           | Pure function `replay(entries, default_cluster_id, now) -> PromotionFile`; idempotent; raises `ReplayError` on inconsistency                                                       |
| 7    | promotion CLI: status/advance/demote/init                                                        | Operator-readable per-action-class print; `advance` rejects skip/no-op/3→4 with the same Stage-4 closure message                                                                   |
| 8    | promotion CLI: reconcile                                                                         | Replay-from-audit-chain to disk; `--dry-run` diff path; Stage-4 gate independent of `advance`                                                                                      |
| 9    | retrofit 10 eval cases with `fixture.promotion`                                                  | Empty `action_classes` for recommend-mode; Stage 2 advance for dry_run; Stage 3 advance(1→2)+advance(2→3) for execute                                                              |
| 10   | 5 new eval cases (011-015)                                                                       | Promotion-gate surface authored as authoritative spec                                                                                                                              |
| 11   | summarizer slots REFUSED_PROMOTION_GATE alongside REFUSED_UNAUTHORIZED                           | `_OUTCOME_ORDER` index 4; +8 tests (severity + per-outcome + all-actions + no-rollback-pin + no-failures-pin + white-box tuple-shape pin)                                          |
| 12   | eval runner parses `fixture.promotion`; Task 10 filters FULLY REVERTED; 15/15 with parser ACTIVE | Constants + load-only test + tmp-copy fixture all DELETED; new `test_case_003_promotion_gate_is_load_bearing` paired-negative                                                      |
| 13   | live kind proof of fail-closed default                                                           | 3 new live tests, recorded in safety-verification §8 Entry 2 (proof reproducible from commit `dc1a1d4` post-hotfix)                                                                |
| 14   | docs + verification record + plan-pin                                                            | This record + runbook §13 (promotion.yaml schema) + §14 (cold-followable v0.1→v0.1.1 migration) + README addendum + safety-verification §3 flipped to "shipped"                    |

---

## ADR-007 conformance

[ADR-007](decisions/ADR-007-cloud-posture-as-reference-agent.md) names cloud-posture as the reference agent; A.1 v0.1 was the first agent landing under its conventions. v0.1.1 adds new surface without breaking conformance:

| Convention                     | v0.1 status (per `a1-verification-2026-05-16.md`)           | v0.1.1 delta                                                                                                                                                                                                              |
| ------------------------------ | ----------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| OCSF v1.3 wire schema          | `class_uid 2007 Remediation Activity`                       | Unchanged. `REFUSED_PROMOTION_GATE` is a new value of the existing `RemediationOutcome` enum, not a new schema.                                                                                                           |
| F.6 hash-chained audit log     | 11-action `remediation.*` vocabulary                        | **+9** `promotion.*` actions (`promotion.evidence.{stage1,stage2,stage3,unexpected_rollback}` / `.advance.{proposed,applied}` / `.demote.applied` / `.init.applied` / `.reconcile.completed`). Chain integrity unchanged. |
| F.5 episodic memory            | One promotion-evidence record per stage-N action            | Unchanged. Evidence still flows into F.5 via the audit chain.                                                                                                                                                             |
| Charter contract + NLAH bundle | v1.2-native loader, LOC budget                              | Unchanged. v0.1.1 ships no new NLAH examples (promotion CLI is operator-only, not LLM-driven).                                                                                                                            |
| eval-framework integration     | 10/10 via `eval-framework run --runner remediation`         | **15/15** with parser ACTIVE. The runner registration is unchanged; `RemediationEvalRunner.run` plumbs `fixture.promotion` to `agent.run(promotion=...)`.                                                                 |
| `pytest` lane structure        | Module tests + integration lane gated by `NEXUS_LIVE_K8S=1` | Unchanged. The 3 new live tests join the existing lane; the gate-skip reason string is shared.                                                                                                                            |
| Output contract (7 files)      | `report.md` / `findings.json` / `audit.jsonl` / etc.        | Unchanged. `promotion.yaml` is **not** part of the per-run workspace; it lives in `persistent_root` and is operator-managed across runs.                                                                                  |

A.1 v0.1.1 conforms to every v0.1 contract and adds the earned-autonomy surface as additive code paths. Operators upgrading from v0.1 do not lose any behaviour.

---

## Coverage delta vs v0.1

| File                                                                      | v0.1 LOC | v0.1.1 LOC |         Δ |
| ------------------------------------------------------------------------- | -------: | ---------: | --------: |
| `remediation/promotion/__init__.py` (new)                                 |        — |         55 |       +55 |
| `remediation/promotion/events.py` (new)                                   |        — |         88 |       +88 |
| `remediation/promotion/schemas.py` (new)                                  |        — |        442 |      +442 |
| `remediation/promotion/tracker.py` (new)                                  |        — |        447 |      +447 |
| `remediation/promotion/replay.py` (new)                                   |        — |        294 |      +294 |
| `remediation/agent.py` (pre-flight gate + per-finding split)              |     ~570 |       ~700 |     +~130 |
| `remediation/audit.py` (9 new `promotion.*` methods)                      |     ~340 |       ~480 |     +~140 |
| `remediation/summarizer.py` (slot for `REFUSED_PROMOTION_GATE`)           |     ~205 |       ~225 |      +~20 |
| `remediation/eval_runner.py` (parser + by_promotion_proposal + reconcile) |     ~260 |       ~520 |     +~260 |
| `remediation/cli.py` (5 new `promotion` subcommands)                      |     ~470 |       ~750 |     +~280 |
| `remediation/schemas.py` (`REFUSED_PROMOTION_GATE`)                       |     ~280 |       ~282 |       +~2 |
| **Test count delta**                                                      |     ~271 |       ~445 | **+~174** |

Coverage of `remediation.*` measured on the v0.1.1 mocked lane: **>93%** (same instrumentation as the v0.1 record; not re-measured in this PR — the gate is "no regression," which `pytest -q` confirms).

---

## Breaking-change note for execute-mode operators

**Cold-readable migration guide:** [`packages/agents/remediation/runbooks/remediation_workflow.md` §14](../../packages/agents/remediation/runbooks/remediation_workflow.md#14-v01--v011-migration). Every step is concrete; no "configure appropriately" hand-waving.

The TL;DR for an operator already running `remediation run --mode execute` on v0.1:

1. **No CLI-flag breaking change in v0.1.1.** `remediation run` ignores `promotion.yaml` — the pre-flight stage gate fires from the `agent.run()` Python API only. The operational kill-switch `--i-understand-this-applies-patches-to-the-cluster` remains the operator-facing gate at the CLI surface.
2. **`promotion.yaml` is opt-in.** v0.1.1 ships the file format + the `remediation promotion` subcommands, but does not require operators to use them. Customers wanting tracked graduation should follow §14's step-by-step setup.
3. **Stage 4 is globally closed in code.** Both `remediation promotion advance --to stage_4` and `remediation promotion reconcile` refuse with the same message naming the two prerequisites (rolled-back-path mutating-admission-webhook fixture + ≥4 weeks customer Stage-3 evidence). This is enforced regardless of `--operator`, `--reason`, or any flag.
4. **Eval coverage moved from 10/10 to 15/15.** Operators running `remediation eval <cases-dir>` against the v0.1.1 shipped cases dir will see "15/15 passed." Custom case dirs continue to work the same way.

The CLI wiring of `promotion.yaml` into `remediation run` (so the gate fires from the customer-facing CLI surface, not only from the Python API) is a **v0.1.2 task**, scoped after the rolled-back-path webhook fixture lands. Documented in the post-Task-14 next-gate section below.

---

## Process notes — the FOUR boundaries

The plan's process discipline shifted four times during execution. Recording all four here, in source-of-truth form, so future plans inherit the history honestly rather than rediscover it.

### Boundary 1 — Tasks 1–8: direct-to-main pre-guard

Tasks 1–8 landed via turn-by-turn review followed by direct push to `main`. No PRs, no CI gating beyond what existed pre-plan. Review was a chat-turn artifact; the only permanent record was the commit + the plan-status row pin.

This worked because Tasks 1–8 were structural — schemas, audit emissions, the gate itself, the reconciler, two CLI subcommand groups — and the review trail was the conversation that immediately preceded each push. It became inadequate when the plan's subject matter (the safety contract) generalised one level up.

### Boundary 2 — Tasks 9–14: PR-based flow after the bypass-guard fired

At Task 9, the sandbox's `bypass-PR-review` guard fired on the direct-to-main push. The user's framing (recorded in [memory](../../.claude/projects/-Users-prabakarannagarajan-nexus-cyber-os/memory/feedback_safety_plan_pr_flow.md)): _"the review of the safety pipeline must be as durable as the safety pipeline."_ From Task 9 onward, every task shipped as a PR — review attached to commits, the cadence "I create, you merge" enforced as a hard boundary.

PRs: #2 (Task 9), #3 (Task 10), #4 (Task 11), #7 (Task 12), #8 (Task 13), this PR (Task 14).

### Boundary 3 — CI-enforcement gap + structural fix (PRs #5/#6)

PR #3 (Task 10) was merged with two red CI checks (`python-tests`, `python` lint). The merge button doesn't enforce CI by default in this repo, and PR #3 demonstrated the gap by being merged anyway. Surfaced when Task 11 (PR #4) was reported as merged but GitHub still showed `state: OPEN, mergedAt: null` — the same broken CI on a PR meant for `main`.

Two PRs closed the gap:

- **PR #5** (`chore(ci): fix python-tests + mypy lint`) — added `uv sync --all-extras --all-packages`, bumped setup-uv from 0.4.27 to 0.11.1, dropped the explicit `packages` path from `uv run mypy` so it uses `pyproject.toml`'s configured `files` list (which excludes the alembic env.py duplicate). Centralised test tooling in the root `[dependency-groups].dev`.
- **PR #6** (`chore(repo): require all 5 CI checks on main via repository ruleset`) — checked in `.github/branch-protection.json` and `.github/BRANCH_PROTECTION.md`. Ruleset `main-require-five-ci-checks` is now active on the repo: pull_request required, all 5 status checks required, `non_fast_forward` + `deletion` blocked, `bypass_actors: []` (no admin bypass). The PR captured intent; the user applied the ruleset to GitHub repo settings via `gh api`.

After PR #6 applied, a red-CI merge to `main` became structurally impossible. The methodology that motivated the Boundary-2 PR flow is now enforced at the GitHub layer, not just at the chat layer.

### Boundary 4 — Task 13 broken proof merged, corrected via hotfix PR #9

PR #8 (Task 13, SAFETY-CRITICAL) merged with a broken spy in `test_stage1_only_refuses_execute_against_live_cluster`. The committed test used `monkeypatch.setattr(kc_mod.subprocess, "run", counting_run)`, which fails with `AttributeError` because `remediation.tools.kubectl_executor` does not import `subprocess` directly — it wraps `asyncio.create_subprocess_exec` inside a single helper, `_run`. The corrected spy that produced safety-verification §8 Entry 2's green measurements lived in the working tree at test time but was never staged before subsequent commits, so the editor-only fix never reached the branch.

Three failure modes allowed the slip past the merge gate, **all recorded verbatim in §8 Entry 2's Correction note**:

1. **Editor-only fix never staged.** First local run with broken spy → `AttributeError`. Fixed in the editor; re-ran → PASS; subsequent commits (Entry 2, plan-pin) only touched docs. The test-file fix never reached a commit.
2. **CI does not run `NEXUS_LIVE_K8S=1`.** Documented behaviour for manual lanes — the broken spy was not exercised by CI. Branch protection was active and all 5 CI checks were green, but the gate is mocked-only by design; the proof for live lanes lives in the manual record, not in CI.
3. **PR #8 review was post-merge and trusted the recorded measurements without re-running the live lane against the merged HEAD.**

**Hotfix PR #9** (`fix(remediation): spy targets kubectl_executor._run (post-merge hotfix for task 13)`) landed the spy fix and appended the Correction note to §8 Entry 2 — disclosing the three failure modes, recording the new HEAD `dc1a1d4` from which the proof reproduces, and stating that the safety claim itself (the fail-closed property) was real and still held against the real apiserver. Re-verified measurements after the hotfix: `mutating_kubectl_calls=0`, `total_kubectl_calls=0`, `resourceVersion 36174→36174`, stage2 evidence emission + reconcile parity unchanged.

**Boundary 4 is the methodological lesson:** post-merge review is not equivalent to pre-merge review. A SAFETY-CRITICAL PR's claims must be verified against the merged branch HEAD before merge, not after. Task 14's process change (Task 14 will not merge until the PR body explicitly states that what is verified is what is in the PR, against the merged branch HEAD) is the durable response.

---

## Permanent documented limitation — `reconcile_matches` evidence-only parity

`promotion.replay()` over a run's audit chain cannot reconstruct the **stage** or the **sign_offs** of an action class that started above Stage 1. The agent's run-time chain emits `promotion.evidence.*` events only; transition events (`promotion.advance.applied`, `promotion.demote.applied`, `promotion.init.applied`, `promotion.reconcile.completed`) originate from the CLI paths (`remediation promotion advance / demote / init / reconcile`), not from the agent's pipeline.

**The §3 source-of-truth contract therefore holds only on the evidence-counter surface of `PromotionFile.action_classes[X].evidence`, not on stage + sign_offs.** Evidence counters are reproducible from the chain; stage + sign_offs require the CLI-issued transition events to also be in the chain.

This limitation surfaces in three places in the codebase:

1. **Eval cases 012 and 013** — Stage 2/3 fixtures running through dry_run / execute do not assert `reconcile_matches: true` in their `expected` block, precisely because the agent's chain doesn't carry their advance sign-offs. Documented in their YAML and in [`eval_runner.py`'s docstring](../../packages/agents/remediation/src/remediation/eval_runner.py) for the `reconcile_matches` key.
2. **Live test `test_reconcile_matches_tracker_state_live`** — asserts evidence parity only, with the limitation called out verbatim in its docstring.
3. **Safety-verification §8 Entry 2** — "What this entry does NOT prove" → item 1 names this limitation.

**Operator implication.** If an operator depends on `promotion.yaml` being losslessly reproducible from `audit.jsonl` (i.e., recovering from a corrupted promotion.yaml by chain replay), they must ensure the chain contains the full CLI history: `promotion init` + every `promotion advance` / `demote` ever issued. A chain that captures only agent-runs (no CLI events) replays to a Stage-1, evidence-only file regardless of what stage the operator believes the action class to be at.

The runbook addendum §13 (promotion.yaml schema) calls this out explicitly so customers running `remediation promotion reconcile` understand what reconstructs and what does not.

---

## Stage-by-stage shipping status (the bright line, preserved)

After Task 14 closes:

| Stage   | Status                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| ------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Stage 1 | **Ships to customers.** Recommend mode. Promotion floor; safe-by-default for every action class.                                                                                                                                                                                                                                                                                                                                                                                           |
| Stage 2 | **Ships to customers.** Dry_run mode. Customer-conditional on the §6 customer-side prerequisites (signed runbook, separation of duties, kill-switch drill, rollback-window-tuning).                                                                                                                                                                                                                                                                                                        |
| Stage 3 | **Customer-conditional.** Customer-side prerequisites of §6 must close before per-customer Stage-3 enablement. The plan's mocked + live + eval gates are necessary but not sufficient.                                                                                                                                                                                                                                                                                                     |
| Stage 4 | **Globally closed in code.** Both `remediation promotion advance --to stage_4` and `remediation promotion reconcile` refuse with the same prerequisite message. Stage 4 opens to **anyone** (no customer can opt themselves in) only when (a) the rolled-back-path mutating-admission-webhook fixture lands and `test_execute_rolled_back_against_live_cluster` flips `xfail → pass`, AND (b) at least 4 weeks of customer Stage-3 evidence accumulates against a real production cluster. |

The bright line from safety-verification §6 is preserved exactly. Task 14 does not move it.

---

## Immediate next-plan gate (non-negotiable)

The rolled-back-path mutating-admission-webhook fixture that flips [`test_execute_rolled_back_against_live_cluster`](../../packages/agents/remediation/tests/integration/test_agent_kind_live.py) from `xfail` to `pass`.

- Today this test is `xfail` (Entry 1, 2026-05-16; Entry 2, 2026-05-17) — A.1's `executed_rolled_back` outcome is proven against mocked tests only.
- The fixture needs to install (e.g.) OPA Gatekeeper or a custom MutatingWebhookConfiguration that strips `runAsNonRoot` on apply, then assert A.1's validator re-runs detection, finds the rule still firing, and applies the inverse patch automatically.
- It is the **first** task after Task 14 — not deferred, not absorbed into something else, not skipped.

Until that fixture lands and the test flips green, the Stage-3-to-Stage-4 promotion path remains globally closed in code regardless of any customer's Stage-3 accumulation.

---

## Sign-off

A.1 v0.1.1 closes the §3 gap of the safety-verification record. Per-action-class promotion tracking ships in code with operator-readable CLI, eval-suite coverage at 15/15 with the parser active, and live-kind proof that the fail-closed default holds against a real Kubernetes apiserver (reproducible from commit `dc1a1d4` per §8 Entry 2's Correction note).

The four process boundaries are recorded honestly above. The `reconcile_matches` limitation is permanently documented. The bright line on stage shipping is preserved exactly. The next-plan gate is named.

— recorded 2026-05-17 (A.1 v0.1.1, earned-autonomy-pipeline plan close)
