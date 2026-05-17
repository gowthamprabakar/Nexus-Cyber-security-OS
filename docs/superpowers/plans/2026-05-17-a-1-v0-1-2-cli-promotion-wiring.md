# A.1 v0.1.2 — CLI promotion wiring

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Pause for review after each numbered task.

**Goal.** Wire `--promotion <path>` into the `remediation run` CLI so the pre-flight stage gate fires from the customer-facing CLI surface, not only from the `agent.run()` Python API. v0.1.1 shipped the promotion package + the `remediation promotion` subcommand group + the eval-runner parser; the `remediation run` subcommand alone was named in `a1-v0-1-1-verification-2026-05-17.md` as the remaining wiring — explicitly "gated on the rolled-back-path webhook fixture landing first" (PR #11 closed that gate). This plan closes the wiring.

**Strategic context.** Also the first worked example of [ADR-010](../../_meta/decisions/ADR-010-version-extension-template.md)'s small-follow-up-commit pattern — a single-task version extension that fully conforms to the template (eligibility test executed and recorded; plan + companion verification record; plan-status table as single source of truth for the task-commit binding). Demonstrates that ADR-010 scales to small changes, not just multi-task plans like A.1 v0.1.1 or D.6 v0.2.

## ADR-010 eligibility test — executed result

Running the six-condition eligibility test from [ADR-010 § "What 'within-agent version extension' means concretely"](../../_meta/decisions/ADR-010-version-extension-template.md#what-within-agent-version-extension-means-concretely):

| #   | Condition                                         | Result                                                                                                                                                                                                                             |
| --- | ------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | Same package directory as the prior version       | ✅ Everything ships under `packages/agents/remediation/` (the `cli.py` change is in the existing module; no new packages).                                                                                                         |
| 2   | Additive surface — no rename / remove / repurpose | ✅ Adds `--promotion` option to `run`. No existing option removed, renamed, or repurposed. `auth.yaml` + `--i-understand-this-applies-patches-to-the-cluster` remain unchanged.                                                    |
| 3   | OCSF `class_uid` unchanged                        | ✅ Wire shape is `class_uid 2007` (Remediation Activity). No new outcomes, no schema changes — this PR adds zero `RemediationOutcome` enum values.                                                                                 |
| 4   | F.6 audit-chain action vocabulary additive only   | ✅ Zero new audit-event types. The pre-flight stage gate emits the same `promotion.evidence.*` actions v0.1.1 already established.                                                                                                 |
| 5   | CLI subcommand surface unchanged                  | ✅ No subcommand added; no subcommand removed. The new `--promotion` is an option on the existing `run` subcommand and is **optional** with a `None`-equivalent safe default (when omitted, the run behaves exactly as in v0.1.1). |
| 6   | Python public API params unchanged                | ✅ `agent.run()` already accepts `promotion: PromotionTracker \| None` (added in v0.1.1 Task 5). This plan plumbs the CLI to that existing param. Zero changes to the function signature.                                          |

**Result: all six conditions hold.** v0.1.2 is eligible as a within-agent version extension under ADR-010. Reviewer rechecks this at PR-review time against the actual diff.

## Scope

**In v0.1.2:**

- `--promotion <path>` option on `remediation run`. When supplied, the CLI loads a `PromotionTracker` from the path (via `PromotionTracker.from_path()`) and passes it to `agent.run(promotion=tracker)`. When omitted, the CLI behaves exactly as v0.1.1 (passes `promotion=None`, gate is skipped — the safe-by-default for legacy invocations).
- 2–3 CLI tests covering: (a) `--promotion` plumbs the tracker through to a Stage-1-refusal outcome against `--mode execute`; (b) `--promotion` is optional — its absence preserves v0.1.1 behaviour; (c) an invalid path errors cleanly.
- Runbook §14 Step 8 ("Continue running `remediation run` exactly as before") updated to drop the "no `--promotion` flag in v0.1.1" caveat and document the v0.1.2 surface.
- Runbook §14 Step 10 ("Plan for the rolled-back-path fixture landing") updated — that fixture is now closed (PR #11), so the post-Task-14 ordering reads "v0.1.2 wired the CLI gate" rather than "v0.1.2 will wire it next."
- README earned-autonomy paragraph updated to drop the "v0.1.2 task" caveat on CLI wiring.

**Deferred to future versions:**

- None. v0.1.2 is the last named wiring item from the A.1 v0.1.1 verification record's "what's still pending v0.1.2" section.

## Strategic role

After A.1 v0.1.1 closed (`promotion` package + CLI subcommand group + eval-runner parser + live-cluster proofs of fail-closed default + rolled-back path proven via Kyverno fixture in PR #11), the only operator-facing surface where the gate did **not** fire was the `remediation run` CLI. v0.1.2 closes that by routing the same `PromotionTracker` instance the eval runner uses (via `--promotion <path>`) through the existing `agent.run(promotion=...)` parameter that's already plumbed end-to-end. This is the smallest valid version extension under ADR-010 — single task, ~30 LOC of `cli.py` change, 2–3 tests, runbook + README sentence-level edits — and serves as the first worked example that ADR-010's full plan-doc + companion-verification-record shape scales to a tiny change without bureaucratic overhead.

## Resolved questions

| #   | Question                                                                                              | Resolution                                                                                                                                                                                                                                                                                                                                       | Task   |
| --- | ----------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------ |
| Q1  | What's the type of the `--promotion` Click option?                                                    | `click.Path(exists=True, dir_okay=False, path_type=Path)` — matches the `--promotion` option already on the `remediation promotion status` subcommand. Required to exist (vs. "create if absent") because the CLI's `run` subcommand should not create a tracker on first invocation; the operator initialises via `remediation promotion init`. | Task 1 |
| Q2  | What happens when `--promotion` is absent?                                                            | The agent runs with `promotion=None` — the gate is skipped (legacy v0.1 behaviour). This is the safe-by-default for operators who haven't initialised a `promotion.yaml` yet; the `auth.yaml` + `--i-understand-this-applies-patches-to-the-cluster` operational gates remain the kill switches.                                                 | Task 1 |
| Q3  | Does the CLI need its own promotion error reporting separate from `agent.run`'s `PromotionGateError`? | No. `agent.run` already emits per-finding `REFUSED_PROMOTION_GATE` outcomes for the all-downgraded case (v0.1.1 Task 5); the CLI's existing per-outcome echo (`for outcome_name, count in counts.items(): ...`) already surfaces those counts. Zero new CLI output paths.                                                                        | Task 1 |
| Q4  | Should the CLI run subcommand also accept `--operator` like the `promotion` subcommand group does?    | No. Operator identity is irrelevant for the `run` path because `run` only reads the promotion state for gating decisions; it doesn't issue any `promotion.advance.applied` / `promotion.demote.applied` events (those originate from the CLI's `promotion` subcommand group, where operator identity matters for the audit chain).               | Task 1 |

## Architecture

**Delta vs A.1 v0.1.1.** Single change in `packages/agents/remediation/src/remediation/cli.py`:

1. New `@click.option("--promotion", "promotion_path", type=click.Path(...), default=None)` on `run_cmd`.
2. New `tracker = PromotionTracker.from_path(promotion_path) if promotion_path else None` after auth loading.
3. New `promotion=tracker` kwarg on the existing `asyncio.run(agent_run(...))` call.

Everything else is sentence-level documentation updates in the runbook and README + 2–3 new CLI tests asserting the wiring.

Cross-references the shared architecture:

- `agent.run(promotion=...)` signature (unchanged): [`agent.py:131-143`](../../../packages/agents/remediation/src/remediation/agent.py).
- `PromotionTracker.from_path()` (unchanged): [`promotion/tracker.py:140-160`](../../../packages/agents/remediation/src/remediation/promotion/tracker.py).
- Existing `--promotion` option pattern on `remediation promotion status` (the reference for Q1's flag type): [`cli.py:286-294`](../../../packages/agents/remediation/src/remediation/cli.py).

## Execution status

| #   | Status  | Commit    | Notes                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| --- | ------- | --------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | ✅ done | `47e79fa` | Wired `--promotion <path>` into `run_cmd`. Implementation matches the resolved questions: `click.Path(exists=True, dir_okay=False)` (Q1); `tracker = PromotionTracker.from_path(...) if promotion_path else None` then `agent_run(promotion=tracker, ...)` (Q2); zero new CLI output paths — the existing per-outcome echo surfaces `refused_promotion_gate` automatically (Q3); no `--operator` flag (Q4). 3 new CLI tests landed verbatim per the plan: `test_run_promotion_flag_loads_tracker_and_fires_gate` (Stage 1 + execute + run-as-root finding → `refused_promotion_gate: 1` in stdout); `test_run_promotion_flag_absent_preserves_v0_1_behaviour` (absent flag + recommend mode → succeeds, zero promotion-gate output); `test_run_promotion_flag_invalid_path_errors_via_click` (non-existent path → Click's `exists=True` rejects before agent runs). Runbook §13 + §14 updated (Step 8 + Step 10 + surface-change table + "what if I get stuck" table + opt-in note + flag-day-rejection paragraph) to drop "v0.1.2 task" caveats and document the live flag with a working invocation example. README earned-autonomy paragraph updated to drop the caveat and cross-reference [`a1-v0-1-2-verification-2026-05-17.md`](../../_meta/a1-v0-1-2-verification-2026-05-17.md). Repo-wide gates: ruff/format/mypy clean; pytest 2542 passed / 17 skipped (+3 from v0.1.1's 2539 — exactly the three new CLI tests, no changes to any existing test). |

This single-row table is the **single source of truth** per ADR-010 invariant #4 — the companion verification record cites this row; it does not duplicate the task-commit binding.

## Compatibility contract

Re-statement of the eligibility-test results in standing-rule form, against ADR-010's six invariants:

| Invariant                                | How v0.1.2 honours it                                                                    |
| ---------------------------------------- | ---------------------------------------------------------------------------------------- | ------------------- |
| Same package directory                   | All changes under `packages/agents/remediation/`.                                        |
| Additive surface                         | `--promotion` is a new optional CLI flag; nothing else changes on the CLI surface.       |
| OCSF `class_uid` unchanged               | Still `class_uid 2007`; no new outcomes.                                                 |
| F.6 audit-chain vocabulary additive only | Zero new audit-event types.                                                              |
| CLI subcommand surface unchanged         | `run` subcommand keeps every existing flag verbatim; `--promotion` is added as optional. |
| Python public API params unchanged       | `agent.run`'s signature unchanged (already accepts `promotion: PromotionTracker          | None` from v0.1.1). |

**v0.1.1's full test surface stays green.** The companion verification record's gate table will explicitly assert the no-regression line — `uv run pytest -q` returns at least 2539 passed (the v0.1.1 baseline; v0.1.2 may add 3 new CLI tests for the new flag, bringing the count to 2542).

## Defers

None. v0.1.2 is the final wiring item named in [`a1-v0-1-1-verification-2026-05-17.md` "what's still pending v0.1.2"](../../_meta/a1-v0-1-1-verification-2026-05-17.md#whats-still-pending-v012-named-so-the-next-plan-inherits-it). Next plans after v0.1.2 are platform-line (F.7 fabric runtime), not A.1 cure-quadrant expansion.

## Reference template

Follows [ADR-007](../../_meta/decisions/ADR-007-cloud-posture-as-reference-agent.md) (reference NLAH) + [ADR-010](../../_meta/decisions/ADR-010-version-extension-template.md) (version-extension template). Zero deltas from either — v0.1.2 is the first worked example of ADR-010's small-PR scaling claim.
