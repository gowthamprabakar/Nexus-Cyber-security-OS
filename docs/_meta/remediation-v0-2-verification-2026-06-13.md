# remediation (A.1) v0.2 — Verification Record & Cycle Closure

**Date:** 2026-06-13 · **Cycle 16 of 17** · **Maturity: Level 1 → Level 2 (infrastructure).**
Remediation — the **only agent that mutates customer infrastructure**, and therefore the
**SAFETY-CRITICAL** cycle by design. The **FINAL v0.2 infrastructure cycle**: its closure brings
**all 17 agents to v0.2** and launches the Phase C production-loop wiring sprint. Single
comprehensive directive, self-merge cascade with EXTRA safety discipline. Per the Cycle-10
amendment, Tasks 1–21 auto-merge on green CI; the cycle closes when this record merges.

---

## §1. Cycle summary

Took remediation from package **`__version__` 0.1.0 → 0.2.0** (ADR-010, both pyproject.toml AND
`__init__.py`): 7 action classes, 10 code-level safety invariants, K8s-relevant source
consumption, batched mode, and continuous infrastructure — all keeping the OCSF 2007 wire shape
byte-identical (WI-A5) and A.1 the sole 2007 producer (Q7).

- **22 tasks, 22 PRs** (#600–#621). 9 milestones.
- **Tests:** remediation **562 passed** + 7 skipped (incl. the gated live e2e). Full repo **7045
  passed, 72 skipped, 0 failed**.
- **Substrate seal EMPTY all 22** — no charter/shared edit. **No charter hoist** (no third
  consumer at A.1).
- **OCSF 2007 sole producer preserved (Q7/WI-A5).** Tool-proxy hard boundary (apply_patch via
  ctx.call_tool, incl. execute) + the dual audit chain preserved throughout.

## §2. Task execution table

| #   | Task                                                | PR          |
| --- | --------------------------------------------------- | ----------- |
| 1   | Bootstrap (version + SAFETY-CRITICAL banner)        | #600        |
| 2   | assert_default_recommend (H1, WI-A8)                | #601        |
| 3   | assert_action_allowlisted (H2, WI-A9)               | #602        |
| 4   | assert_dry_run_before_execute (H3, WI-A10)          | #603        |
| 5   | assert_rollback_on_failed_validation (H4, WI-A11)   | #604        |
| 6   | assert_blast_radius_capped (H5, WI-A12)             | #605        |
| 7   | assert_idempotent_workspace_scoped (H6, WI-A13)     | #606        |
| 8   | K8S_PATCH_DISABLE_PRIVILEGED_CONTAINER action class | #607        |
| 9   | K8S_PATCH_DISABLE_AUTO_MOUNT_SA_TOKEN action class  | #608        |
| 10  | Action class registry expansion 5 -> 7              | #609        |
| 11  | k8s-posture source mapping                          | #610        |
| 12  | F.3 + D.5 cloud-K8s source mapping                  | #611        |
| 13  | Batched-mode contract field + dispatcher            | #612        |
| 14  | Batch-level safety primitives                       | #613        |
| 15  | assert_privileged_action_extra_authz (WI-A16, NEW)  | #614        |
| 16  | assert_auto_mount_validation (WI-A17, NEW)          | #615        |
| 17  | assert_tool_proxy_for_execute (WI-A14)              | #616        |
| 18  | assert_tenant_scoped (WI-A18)                       | #617        |
| 19  | Continuous scheduler + mode coexistence             | #618        |
| 20  | v0.2 e2e composition + live-kind gate (WI-A4)       | #619        |
| 21  | 2007 sweep + coverage + runbooks + README v0.2      | #620        |
| 22  | Verification record + cycle closure                 | #621 (this) |

## §3. Q-lock mapping (all 7 honored)

| Q   | Lock                                              | Where honored                                    |
| --- | ------------------------------------------------- | ------------------------------------------------ |
| Q1  | (A) +2 action classes (privileged + auto-mount)   | `action_classes/` (Tasks 8-10); host-\* deferred |
| Q2  | (C) K8s remediation only                          | unchanged; cloud-native S3/IAM deferred v0.3     |
| Q3  | (C) k8s-posture + F.3 + D.5 sources               | `tools/source_mapping.py` (Tasks 11-12)          |
| Q4  | (A) 3 tiers preserved (recommend/dry-run/execute) | unchanged; canary + scheduled deferred v0.3      |
| Q5  | (C) single-finding default + opt-in batched       | `batch.py` + `batch_safety.py` (Tasks 13-14)     |
| Q6  | (B) continuous + heartbeat coexistence            | `continuous/` (Task 19); INFRASTRUCTURE          |
| Q7  | OCSF 2007 preserved; A.1 sole producer            | `schemas.py` unchanged; sweep (Task 21)          |

## §4. Gates passed

- **All 5 CI checks green** on every self-merged PR.
- **Substrate seal EMPTY** all 22; no charter/shared edit; no charter hoist.
- **OCSF 2007 byte-identical (WI-A5):** the 2 new action types are additive enum members; existing
  emission is unchanged, so the 15 eval cases pass identically (full remediation suite green each
  task).
- **The 10 code-level safety invariants (the cycle's institutional contribution):** the 6
  decision heuristics formalized — `assert_default_recommend` (H1) · `assert_action_allowlisted`
  (H2) · `assert_dry_run_before_execute` (H3) · `assert_rollback_on_failed_validation` (H4) ·
  `assert_blast_radius_capped` (H5) · `assert_idempotent_workspace_scoped` (H6); **2 NEW
  action-specific** — `assert_privileged_action_extra_authz` (WI-A16) ·
  `assert_auto_mount_validation` (WI-A17); plus `assert_tool_proxy_for_execute` (WI-A14, audit #316
  C-1 codified) + `assert_tenant_scoped` (WI-A18). All exercised end-to-end (Task 20).
- **Dual-layer execute auth preserved (WI-A15):** execute requires both `--enable-execute` AND
  `auth.yaml mode_execute_authorized`; privileged-container needs the extra
  `privileged_actions_authorized` (WI-A16).
- **Tool-proxy hard boundary** (apply_patch via ctx.call_tool incl. execute; ADR-016
  DirectInvocationBlocked) + **dual audit chain** (charter + PipelineAuditor) preserved.
- **WI-A4 e2e:** ungated composition (7 action classes + all 10 invariants + batched safety) runs
  in CI; the full 7-stage execute+rollback is gated behind NEXUS_LIVE_REMEDIATION.
- **Cross-agent sweep (Task 21, WI-A6):** A.1 is the sole OCSF 2007 producer; fleet inventory = 14
  emitter roles across 5 classes.
- **ruff + ruff format + mypy strict** clean per task.

## §5. Honest findings (WI-A3)

- **v0.2 is BREADTH, not new autonomy.** 7 action classes + the safety-invariant set + batched
  mode are complete, but the action surface is still K8s strategic-merge patches only.
- **The cloud-K8s source overlap is THIN.** k8s-posture (D.6) is the real source; F.3/D.5 only
  surface A.1-actionable findings when they scan a managed cluster's _workloads_ — most cloud
  findings are cluster/control-plane (IAM, networking, encryption) and correctly match no action
  class.
- **Continuous remediation is INFRASTRUCTURE; the production loop is NOT wired (Phase C, not
  v0.3).** The scheduler decides _when_; it does not drive `agent.run()`. Continuous mode never
  auto-escalates the tier — a continuous run is still `recommend` unless the operator opted in
  (H1 preserved). Wiring is the **Phase C consolidated retrofit** after this cycle.
- **Target was ~60%; realistic realized ~50-60% `[estimate]`.** Action classes + invariants +
  batched mode done; host-\* actions + cloud-native remediation + canary/scheduled tiers + the
  production loop are deferred.
- **Per-action-class coverage (WI-A1, no aggregate):** the 7 classes at ~55-65% `[estimate]` each.
- **Deferred (v0.3):** host-network/host-pid/host-ipc actions · cloud-native remediation (S3
  bucket policies, IAM) · canary tier · scheduled-execute tier · D.7→A.1 auto-handoff.
- **Process:** the `reset --hard`-after-failed-commit trap recurred (Tasks 3, 9, 16, 17) — RUF043
  (`.` metacharacter in `pytest.raises(match=...)`) and S105 ("TOKEN"/"PATH" names read as
  secrets) are NOT reliably auto-fixed by husky's `ruff --fix`, so a failing commit + chained
  reset wiped the new files each time (all recreated). **Reinforced rule: when an explicit
  `ruff check` returns non-zero, FIX before committing — never let the commit+reset chain proceed.
  Use metacharacter-free `match=` substrings and inline `# noqa: S105` on enum/path constants.**

## §6. Watch-items carry-forward

- The **Phase C wiring list** grows by one agent (remediation continuous → run()) — now **12**
  agents with the production-loop gap; this is the **complete** v0.2 list (all 17 represented; A.4
  already at v0.2.5).
- host-\* actions + cloud-native remediation + canary/scheduled tiers (v0.3).
- **The 10 code-level safety invariants are the institutional safety-critical-agent pattern** for
  future v0.3 host-\* actions, cloud-native remediation, and any future mutating agent.

## §7. Phase C deferred handoff (NOT v0.3)

Wire the continuous remediation loop (scheduler-driven re-run, default-recommend preserved) into
`agent.run()` — the consolidated production-loop retrofit shared with the 11 prior cycles. This is
the FIRST item of the Phase C sprint that launches now that all 17 agents are at v0.2.

## §8. 🎉 v0.2 INFRASTRUCTURE BREADTH COMPLETE

With A.1 closed, **all 17 agents are at v0.2** (A.4 Meta-Harness already at v0.2.5). The
institutional patterns accumulated across the 16 cycles:

- **Code-level invariant catalog — 26 across the fleet:** D.3 `assert_authorized` · D.4
  `assert_block_authorized` · data-security `assert_privacy_contract` · F.6 `assert_audit_readonly`
  - `assert_admin_for_cross_tenant` · supervisor `assert_no_peer_to_peer` + `assert_signed_contract`
    · the LLM-agent template (D.13→D.7→D.12: categorical_only + bounded_retry + findings_cited/
    evidence_chain/coverage_gap_cited, + D.7 worker_bounded/evidence_chain/no_speculation, + D.12
    tenant_scoped/no_claims_subscription/llm_only_with_gaps) · **A.1's 10 safety invariants (H1-H6 +
    privileged-authz + auto-mount + tool-proxy + tenant)**.
- Self-merge cascade proven across **8 cycles** (Cycles 9-16); Path 1 (continuous=infra,
  run()-wiring=Phase C) held across **12** cycles.
- Cross-references: every prior closure record (`*-v0-2-verification-*.md`) — F.3 #267, D.5 #288,
  D.1 #312, D.2 #365, k8s-posture #454, compliance #477, audit #517, supervisor #535, synthesis
  #555, investigation #579, curiosity #599, **remediation #621 (this)**.

**Next:** the operator **batched audit** (Cycles 13/14/15/16), then the **Phase C production-loop
wiring sprint** (~5-7 weeks), then **Phase D v0.3 L3 capabilities**.

---

**remediation (A.1) v0.2 — CYCLE CLOSED ✅** (auto-merges on green CI per the Cycle-10 protocol).
22/22 tasks, 9/9 milestones, substrate seal empty throughout, OCSF 2007 + dual-audit + tool-proxy
boundary preserved, 0 failures. The SAFETY-CRITICAL final cycle: 7 action classes + the **10
code-level safety invariants** (6 H1-H6 formalized + 2 action-specific + tool-proxy + tenant) +
batched mode, with H1 (default-to-recommend) and the dual-layer execute authorization held
throughout. **🎉 v0.2 INFRASTRUCTURE BREADTH COMPLETE — all 17 agents at v0.2.**
