# F.3 Cloud Posture v0.2 — cross-agent OCSF 2003 consumer regression sweep (2026-06-08)

> **F.3 v0.2 Milestone 4, Task 9.** A **guard, not a fix**: run every OCSF-2003 consumer's suite + the KG/audit verification paths at current `main` HEAD and confirm F.3 v0.2's offline→live change left the shared `class_uid 2003` wire contract invariant. **No production/consumer code was changed.** Pairs with the F.3 v0.2 plan ([`2026-06-07-f-3-cloud-posture-v0-2.md`](../superpowers/plans/2026-06-07-f-3-cloud-posture-v0-2.md), Task 9).

- **Date:** 2026-06-08 · **Baseline:** `origin/main` after Tasks 1–8 merged (#250, #254, #255, #256, #257, #259, #260, #261).
- **Method:** `uv run pytest` per consumer package + the charter memory/audit paths; OCSF constants imported per consumer; flakiness re-checked in isolation.
- **Headline:** **F.3 v0.2 changed the data _source_ (offline → live AWS), not the finding _shape_.** `cloud_posture/schemas.py` (the canonical OCSF 2003 definition the other four re-export) was **not touched** by any v0.2 task — its last change is the pre-v0.2 ADR-004 typing refactor (`6131300`). So the shared 2003 contract is invariant by construction; this sweep is the empirical confirmation.

---

## §1. The five OCSF-2003 consumers — suites green

| Consumer                                  | Package               | Result                       | OCSF `class_uid` |
| ----------------------------------------- | --------------------- | ---------------------------- | ---------------- |
| **F.3 Cloud Posture** (the changed agent) | `cloud-posture`       | **148 passed, 9 skipped** ✅ | 2003             |
| **D.5 Multi-Cloud Posture**               | `multi-cloud-posture` | **214 passed** ✅            | 2003             |
| **D.6 K8s Posture**                       | `k8s-posture`         | **309 passed** ✅            | 2003             |
| **DSPM Data Security**                    | `data-security`       | **292 passed** ✅            | 2003             |
| **Compliance**                            | `compliance`          | **225 passed** ✅            | 2003             |

The 9 skips in `cloud-posture` are the gated live lanes (`NEXUS_LIVE_LOCALSTACK` ×3, `NEXUS_LIVE_AWS` ×6) — they skip cleanly when env is unset, as designed (Tasks 6–8). No fails, no errors, no new warnings/deprecations in any of the five.

**Pre/post note:** the sweep changes no consumer code, so per-consumer counts equal current `main` HEAD. F.3 v0.2 added tests only to `cloud-posture` (108 → 148 + 9 skipped across Tasks 1–8); the other four consumers' counts are unchanged from their pre-v0.2 baselines (214 / 309 / 292 / 225), confirming **no collateral impact**.

## §2. OCSF 2003 schema invariance — confirmed

Each consumer's `schemas` module re-exports the canonical constants from `cloud_posture.schemas`. Imported live:

| Consumer            | `OCSF_CLASS_UID` | `OCSF_CLASS_NAME`    | `OCSF_VERSION` |
| ------------------- | ---------------- | -------------------- | -------------- |
| cloud_posture       | **2003**         | `Compliance Finding` | 1.3.0          |
| multi_cloud_posture | **2003**         | `Compliance Finding` | 1.3.0          |
| k8s_posture         | **2003**         | `Compliance Finding` | 1.3.0          |
| data_security       | **2003**         | `Compliance Finding` | 1.3.0          |
| compliance          | **2003**         | `Compliance Finding` | 1.3.0          |

**All five identical.** The wire shape (`class_uid 2003`, category 2, OCSF v1.3.0) is invariant across the family. F.3 v0.2's live-AWS work flows live findings through the _same_ `build_finding` / `FindingsReport` path, so downstream consumers see no change.

## §3. KG write paths (SemanticStore)

- **charter memory + SemanticStore (offline / aiosqlite):** green within the combined `packages/charter/tests/` + `packages/agents/audit/` run (**405 passed, 8 skipped**). The entity/relationship write paths and the per-agent `kg_writer` paths (exercised inside each consumer's own suite, all green in §1) carry no drift.
- **Multi-tenant RLS (live Postgres):** **NOT verifiable in this sweep.** The real-Postgres lane (`charter-f5-live.yml`, #252) cannot reach green on current `main`: the `SET LOCAL` fix (#251) is merged but is **necessary-not-sufficient** — the three remaining substrate bugs (`postgresql.LTREE` attr-error, pgvector `cosine_distance`, RLS `FORCE` + non-superuser role) are still **open in the parked multi-bug substrate cycle (PR #253 brainstorm)**. Docker/Postgres was also unavailable in this run. **RLS isolation was therefore verified offline only** (app-side tenant filtering paths green via aiosqlite); true DB-level RLS isolation remains gated on #253. → Watch-Item.

## §4. Audit chain integrity

- **F.6 hash-chain + verifier:** the audit package is **green in isolation (129 passed, 2/2 runs)**; the verifier (`charter.verify_audit_log`) and chain tests pass. **No drift in the audit event vocabulary.**
- **🟡 One flaky test surfaced (cross-package only):** `packages/agents/audit/tests/test_agent.py::test_run_logs_warning_when_non_wall_clock_budget_overrun` **failed once** in the _combined_ charter+audit run but **passes 3/3 in isolation and 2/2 in the audit package alone**, and **passes in CI** (`python-tests` green on every F.3 v0.2 PR). It is a **`caplog` cross-test logging-state flake** (another package's logging config intermittently swallows the captured WARNING record), **not** a product bug, **not** OCSF-2003-related, and **not** caused by F.3 v0.2 (which touched only `cloud-posture`). Per Task 9's discipline it was **NOT fixed here**. → Watch-Item.

---

## §5. Findings + Watch-Items (carry-forward to Task 13)

1. ✅ **OCSF 2003 invariant holds** across all 5 consumers; F.3 v0.2 is source-not-shape.
2. ✅ **All 5 consumer suites green**; no collateral impact on the four unchanged consumers.
3. 🟡 **WI — flaky audit test** `test_run_logs_warning_when_non_wall_clock_budget_overrun`: cross-package `caplog` flake, pre-existing, CI-green, unrelated to F.3 v0.2. Candidate fix (its own PR, not this cycle): make the test robust to cross-test logging state (e.g. `caplog.set_level` on the specific logger / `propagate=True`). **Not a release blocker.**
4. 🟡 **WI — live-Postgres RLS unverifiable**: blocked by the parked multi-bug substrate cycle (#253). RLS isolation re-verification belongs to that cycle's closure, not F.3 v0.2.

## §6. Verdict

**The F.3 v0.2 offline→live change is regression-clean for the OCSF-2003 family.** All five consumer suites pass, the `class_uid 2003` wire shape is invariant, KG (offline) + audit-chain paths are green. The two 🟡 items are pre-existing and out of F.3 v0.2's scope (one flaky test; one substrate-cycle dependency), carried as Watch-Items to the Task 13 verification record. **No consumer code was modified; no blocker for F.3 v0.2 closure.**

---

— recorded 2026-06-08 (F.3 v0.2 Task 9, cross-agent OCSF 2003 regression sweep; guard-only, no code changes).
