# A.1 v0.1.2 verification record — 2026-05-17

**Companion** to the [v0.1 implementation record](a1-verification-2026-05-16.md) and the [v0.1.1 companion record](a1-v0-1-1-verification-2026-05-17.md); **not a replacement** for either. v0.1's record remains source of truth for v0.1's claims; v0.1.1's companion records the earned-autonomy pipeline; v0.1.2's companion (this record) records only the delta: CLI wiring of `--promotion <path>` into `remediation run`.

This is also the **first worked example of [ADR-010](decisions/ADR-010-version-extension-template.md)'s small-PR scaling claim** — a single-task version extension that fully conforms to the template (eligibility test executed and recorded; plan + companion verification record; plan-status table as single source of truth for the task-commit binding; no breaking changes to prior contracts; additive code paths only).

---

## Gate results

| Gate                                                                       | Threshold                                                                                          | Result                                                                                                                                                                           |
| -------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `uv run pytest -q` (repo-wide, mocked lane)                                | green, no regressions; v0.1.1 baseline = 2539 passed / 17 skipped                                  | **2542 passed, 17 skipped** (+3 new CLI tests for the `--promotion` flag)                                                                                                        |
| **No behavioural regression vs v0.1.1**                                    | every v0.1.1 test still passes unchanged                                                           | ✅ — the +3 delta is purely new tests; zero existing tests modified                                                                                                              |
| `uv run pytest packages/agents/remediation/tests/test_cli.py -k promotion` | 3 new CLI tests pass                                                                               | **3 passed, 19 deselected**                                                                                                                                                      |
| `ruff check .`                                                             | clean                                                                                              | ✅                                                                                                                                                                               |
| `ruff format --check .`                                                    | clean                                                                                              | ✅ (420 files)                                                                                                                                                                   |
| `mypy` (configured `files`)                                                | strict-clean                                                                                       | ✅ (210 source files)                                                                                                                                                            |
| **ADR-010 eligibility test (6 conditions)**                                | all 6 hold                                                                                         | ✅ — recorded in the plan doc's [ADR-010 eligibility test section](../superpowers/plans/2026-05-17-a-1-v0-1-2-cli-promotion-wiring.md#adr-010-eligibility-test--executed-result) |
| **CLI surface backwards-compatible**                                       | omitting `--promotion` preserves v0.1.1 behaviour exactly                                          | ✅ (`test_run_promotion_flag_absent_preserves_v0_1_behaviour`)                                                                                                                   |
| **CLI flag plumbs gate end-to-end**                                        | `--promotion <stage-1>` + `--mode execute` produces `refused_promotion_gate` outcome in CLI output | ✅ (`test_run_promotion_flag_loads_tracker_and_fires_gate`)                                                                                                                      |
| **CLI rejects non-existent promotion path**                                | `click.Path(exists=True)` surfaces a usage error before the agent runs                             | ✅ (`test_run_promotion_flag_invalid_path_errors_via_click`)                                                                                                                     |

### Repo-wide sanity check

`uv run pytest -q` → **2542 passed, 17 skipped**. **+3 tests** vs the v0.1.1 baseline (2539 from [`a1-v0-1-1-verification-2026-05-17.md`](a1-v0-1-1-verification-2026-05-17.md)) — exactly the three new CLI tests added in this plan; zero changes to the existing test count. The "no behavioural regression vs v0.1.1" gate above is asserted by this delta being a pure-additive 3 rather than a non-zero net delta.

---

## Per-task surface

Pinned in [the v0.1.2 plan's execution-status table](../superpowers/plans/2026-05-17-a-1-v0-1-2-cli-promotion-wiring.md#execution-status) — single task, hash-pinned per the plan's execution-status row. This record **cites** that row; it does not duplicate the task-commit binding, per [ADR-010 invariant #4](decisions/ADR-010-version-extension-template.md#the-invariants-this-template-enforces) ("plan-status table is single source of truth for task-commit hashes").

---

## ADR-007 conformance

[ADR-007](decisions/ADR-007-cloud-posture-as-reference-agent.md) names the reference NLAH; A.1 has passed the 10-pattern conformance gate since v0.1. v0.1.2 deltas:

| Convention                     | v0.1.1 status                                                                                           | v0.1.2 delta                                                                                                                                                                      |
| ------------------------------ | ------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| OCSF v1.3 wire schema          | `class_uid 2007`                                                                                        | Unchanged.                                                                                                                                                                        |
| F.6 hash-chained audit log     | 11 `remediation.*` + 9 `promotion.*` actions                                                            | Unchanged. No new audit-event types.                                                                                                                                              |
| F.5 episodic memory            | Evidence via the audit chain                                                                            | Unchanged.                                                                                                                                                                        |
| Charter contract + NLAH bundle | v1.2-native loader                                                                                      | Unchanged.                                                                                                                                                                        |
| eval-framework integration     | 15/15 with parser ACTIVE                                                                                | Unchanged. The eval runner already plumbed `fixture.promotion → agent.run(promotion=...)`; v0.1.2 plumbs the same param from the CLI surface, mirroring the eval-runner's wiring. |
| `pytest` lane structure        | Module tests + integration lane gated by `NEXUS_LIVE_K8S=1`                                             | Unchanged. The 3 new CLI tests join the existing `test_cli.py`.                                                                                                                   |
| Output contract (7 files)      | `report.md` / `findings.json` / `audit.jsonl` / etc.                                                    | Unchanged. `promotion.yaml` is operator-managed across runs in `persistent_root`, not part of the per-run workspace.                                                              |
| CLI surface                    | `remediation run` + `remediation eval` + `remediation promotion {status,init,advance,demote,reconcile}` | **One new optional flag** (`--promotion`) added to `remediation run`; nothing removed or renamed.                                                                                 |
| Python public API              | `agent.run(promotion=PromotionTracker \| None = None, ...)`                                             | Unchanged. v0.1.2 plumbs the existing param from a new CLI option.                                                                                                                |

A.1 v0.1.2 conforms to every v0.1 and v0.1.1 contract.

---

## Coverage delta vs v0.1.1

| File                                           | v0.1.1 LOC | v0.1.2 LOC |                                                  Δ |
| ---------------------------------------------- | ---------: | ---------: | -------------------------------------------------: |
| `remediation/cli.py`                           |       ~750 |       ~775 |                                               +~25 |
| `remediation/tests/test_cli.py`                |       ~480 |       ~640 |                      +~160 (3 new tests + helpers) |
| `remediation/runbooks/remediation_workflow.md` |       ~610 |       ~615 | +~5 (Step 8 + Step 10 + four sentence-level edits) |
| `remediation/README.md`                        |       ~175 |       ~177 |             +~2 (earned-autonomy paragraph update) |
| **Test count delta**                           |       2539 |       2542 |               **+3** (`test_run_promotion_flag_*`) |

All file-level deltas are additive. No deletions; no renames; no API breaks. The +~25 LOC in `cli.py` is exactly the new `--click.option("--promotion", ...)` decorator + the 4-line `tracker = ...` block + the new `promotion=tracker` kwarg on `agent_run(...)`.

---

## What this version extension proves about ADR-010

ADR-010's stated success criterion was: _"F.7 v0.1's plan, when written, follows this template without special-case carve-outs."_ v0.1.2 is the **first** plan after ADR-010 was accepted (PR #12 merged immediately before), and it is the **smallest possible** within-agent version extension that could be eligible — a single task, ~25 LOC of source change, 3 tests. If ADR-010 worked, v0.1.2's plan + record would fit the template without acrobatics.

Empirical result: it does. The plan doc has all 11 required sections; the verification record (this document) has all 8 required sections; the eligibility test is executed and recorded in the plan; the plan-status table is the single source of truth for the task-commit hash; no breaking changes to v0.1 or v0.1.1 contracts; all four invariants hold. The plan doc came in at ~150 lines (vs. A.1 v0.1.1's 14-task plan at ~120 lines pre-status-pins); the verification record at ~95 lines (vs. v0.1.1's at ~200 lines). The template scales down to small changes without bureaucratic overhead.

The next test of ADR-010 is **F.7 v0.1's plan**, which will exercise a larger-scope version extension on a new infrastructure surface. v0.1.2 establishes that the small-PR end of the template works; F.7 v0.1 will establish the multi-task end.

---

## Sign-off

A.1 v0.1.2 wires the v0.1.1-shipped pre-flight stage gate into the customer-facing `remediation run` CLI via an optional `--promotion <path>` flag. Backwards-compatibility is preserved exactly: omitting the flag reverts to v0.1 behaviour. The 3 new CLI tests pin the wiring end-to-end (flag plumbs gate; absent flag preserves prior behaviour; invalid path errors cleanly via Click).

This closes the final wiring item named in the [A.1 v0.1.1 verification record's "what's still pending v0.1.2" section](a1-v0-1-1-verification-2026-05-17.md#whats-still-pending-v012-named-so-the-next-plan-inherits-it). The next plans after v0.1.2 are platform-line (F.7 fabric runtime + ADR-011 PR-flow discipline), not A.1 cure-quadrant expansion.

The Stage-shipping bright line is unchanged. Stage 1 (recommend) and Stage 2 (dry_run) continue to ship to customers; Stage 3 remains customer-conditional on the §6 customer-side prerequisites; Stage 4 remains globally closed in code pending prerequisite (b) — the ≥4 weeks of customer Stage-3 evidence that cannot close empirically until customers run Stage 3 in production. v0.1.2 does not move the bright line; it makes the gate more reachable from the operator-facing CLI surface.

— recorded 2026-05-17 (A.1 v0.1.2, first worked example of ADR-010's small-PR scaling)
