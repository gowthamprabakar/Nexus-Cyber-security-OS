# Phase C — Production-Loop Wiring Sprint — Completion Record — 2026-06-14

**Subject:** main HEAD `1d7e181`. **Type:** verification record (SS7 finale), NOT a cycle and NOT a
new audit. **Method:** ground-truth verification against main. Full repo at completion:
**7109 passed, 72 skipped, 0 failed**; ruff + mypy clean; substrate seal empty across every
self-merge sub-sprint.

Phase C turned the v0.2 fleet from **INFRASTRUCTURE** (capabilities defined, tested, but not on the
`run()` path) into **OPERATING** (those capabilities load-bearing in the production flow). It was
scoped directly against the v0.2 Quality Audit (`v0-2-quality-audit-2026-06-13.md`, #622), whose
headline finding was: **"0 of ~36 `assert_*` invariants are wired into any agent `run()` flow"**
plus a registered-tool bypass on the only cloud-mutating agent. Phase C closes both.

---

## Executive summary

- **Every agent's dormant safety invariants are now load-bearing in `run()`.** The audit's
  "tested-but-unwired shelf" is gone: the 3 detect agents (SS2), the 2 deviators (SS3), the 3
  LLM agents (SS5, 15 invariants), and the safety-critical remediation agent (SS6, 10 invariants)
  all invoke their `assert_*` guards on the production path.
- **The remediation tool-proxy bypass is fixed** (P1 #623) and the **static tool-import guard is
  fleet-wide** (P1 #624); **`PENDING_MIGRATION` is now empty** — the vulnerability registry-scan
  bypass was migrated to the charter proxy (SS4 #635).
- **Continuous-loop foundation shipped** (SS1): a non-substrate `nexus_runtime` package with the
  `ContinuousDriver`, supervisor trigger sources, and 5 manual-dispatch live-lane workflows.
- **Dormant live readers registered** (SS4) so the live lanes can dispatch them through the charter.
- **Honest deferrals recorded** (below) — meta-harness DSPy cadence and the two substrate P3 items
  are explicitly out of Phase C scope, not silently skipped.

---

## Sub-sprint → PR map

| Phase                                            | What landed                                                                                                                                                                  | PRs                    |
| ------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------- |
| Pre-flight P1                                    | remediation rollback routed through `ctx.call_tool`; static tool-import guard widened fleet-wide                                                                             | #623, #624             |
| Pre-flight P3                                    | non-substrate hygiene batch (versions, OCSF-extension note, ruff `--no-fix` pre-commit hook)                                                                                 | #625                   |
| SS1 Foundation                                   | `packages/runtime` (`nexus_runtime.ContinuousDriver`); supervisor `ContinuousTriggerSource` + `FabricEventsSource`; 5 `live-*.yml` (workflow_dispatch-only)                  | #626, #627, #628, #629 |
| SS2 detect agents                                | D.3 snapshot (`assert_authorized`), D.4 temp-IP-block (`assert_block_authorized`), k8s-posture cluster isolation (`assert_single_cluster_context`)                           | #630, #631, #632       |
| SS3 deviators                                    | F.6 audit (`assert_audit_readonly` + `assert_admin_for_cross_tenant`); supervisor (`assert_no_peer_to_peer` + `assert_signed_contract`)                                      | #633, #634             |
| SS4 live modules                                 | vulnerability Trivy via charter proxy (**PENDING_MIGRATION emptied**); multi-cloud-posture discovery registered; data-security live-S3 route; network-threat live-VPC poller | #635, #636, #637, #638 |
| SS5 LLM trio                                     | synthesis (3 invariants), investigation (6), curiosity (6) — **15 invariants load-bearing**                                                                                  | #639, #640, #641       |
| SS6 remediation (SAFETY-CRITICAL, per-PR review) | 7 universal invariants (PR1); 2 action-specific A16/A17 (PR2); H6 idempotent via Option a (PR3); H6 re-land onto main                                                        | #642, #643, #644, #645 |

~25 PRs, #623–#645.

---

## Verification (ground-truthed against main `1d7e181`)

- **A.1 remediation — all 10 safety invariants wired into `run()`.** Verified present in
  `packages/agents/remediation/src/remediation/agent.py`: `assert_tenant_scoped`,
  `assert_default_recommend`, `assert_blast_radius_capped`, `assert_action_allowlisted`,
  `assert_dry_run_before_execute`, `assert_tool_proxy_for_execute`,
  `assert_rollback_on_failed_validation`, `assert_privileged_action_extra_authz`,
  `assert_auto_mount_validation`, `assert_idempotent_workspace_scoped`. The H1 kill-switch
  (`enable_execute`) is now enforced inside `run()`, not only at the CLI.
- **Static tool-import guard:** `PENDING_MIGRATION: set[str] = set()` in
  `packages/charter/tests/test_tool_import_guard.py` — no known registered-tool bypass remains.
- **SS1 foundation present:** `packages/runtime/src/nexus_runtime/continuous.py` and 5
  `.github/workflows/live-*.yml`.
- **Behaviour-change note (SS5):** in synthesis (D.13) and curiosity (D.12), a degraded LLM draft
  that still leaks plaintext PII after the retry budget now **hard-fails** before write/publish
  (load-bearing `assert_categorical_only`) instead of being accepted — a deliberate safety
  improvement; the corresponding tests were updated to assert the no-leak hard-fail.

---

## Process lesson — the stranded H6 stacked PR

SS6 PR3 (#644, the H6 idempotent reconciliation) was opened **stacked** on the PR2 branch. PR2
(#643) was **squash-merged** into main at its PR2-only head, and #644 had merged _into_ the PR2
branch — so #644 showed `MERGED` but its content **never reached main**. The gap was caught at SS7
start by verifying main's actual content (not the PR's merge status): main was 9/10 invariants. It
was re-landed as a clean cherry-pick onto main (#645). **Lesson:** for stacked PRs under
squash-merge, verify the child's _content_ reached main, never trust the child's `MERGED` flag
alone.

---

## Honest deferrals (out of Phase C scope, not silently skipped)

- **meta-harness wire-up — intentionally none.** meta-harness (F.4) has no `assert_*` invariants and
  no `continuous/` dir to wire. Its only dormant infra is `compilation_cadence.py`, which is the
  **DSPy compilation pipeline — deliberately default-OFF behind v0.3 flag-flip gates** (per the
  v0.2.5 close). Wiring it is a v0.3 effort, not Phase C. SS7 therefore carries no meta-harness code
  change.
- **P3-2 / P3-4 (substrate) held for operator.** P3-2 (hoist `categorical_only` / `bounded_retry`
  into a shared charter module) and P3-4 (add curiosity to `shared/fabric._FORBIDDEN_SUBSCRIPTIONS`)
  touch the substrate seal and were never self-merged; they await an operator decision.
- **Live lanes are operator-run.** The `live-*.yml` workflows and per-agent `NEXUS_LIVE_*` gates are
  manual `workflow_dispatch` only — live cloud/LLM/cluster green is the operator's to produce; CI
  proves the wiring, not the live calls.
- **Continuous orchestration is wired but not auto-driven.** The `ContinuousDriver` + per-agent
  continuous infrastructure are load-bearing infra; turning the fleet's run loop fully autonomous is
  the next operating step beyond this wiring sprint.

---

## Status

**Phase C is complete.** v0.2 is now OPERATING: the safety invariants and tool-proxy boundaries that
the v0.2 audit found shelved are load-bearing on every agent's production path, and the
foundation for the continuous operating loop is in place. Next: the operator's call on P3-2/P3-4 and
the v0.3 effort (incl. the meta-harness DSPy cadence and full continuous-loop autonomy).
