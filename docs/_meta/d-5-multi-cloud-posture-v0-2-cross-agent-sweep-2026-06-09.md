# D.5 Multi-Cloud Posture v0.2 — cross-agent OCSF 2003 consumer regression sweep (2026-06-09)

> **D.5 v0.2 Milestone 6, Task 16.** A **guard, not a fix** (analog to [F.3 v0.2 Task 9](f-3-cloud-posture-v0-2-cross-agent-sweep-2026-06-08.md), #262): run every OCSF-2003 consumer's suite + the KG/audit paths at current `main` HEAD and confirm D.5 v0.2's changes (new native-rule finding types + provenance) left the shared `class_uid 2003` wire contract invariant. **No production/consumer code was changed.**

- **Date:** 2026-06-09 · **Baseline:** `origin/main` after D.5 Tasks 1–15 merged (#270–#284).
- **Headline:** **D.5 v0.2 added new finding _discriminators_ (`AZURE_NATIVE`, `GCP_NATIVE`) + a `provenance` evidence field — all inside `multi_cloud_posture.schemas`, which is D.5-internal.** The other four consumers re-export from `cloud_posture.schemas` (untouched), so the shared `class_uid 2003` shape is invariant by construction; this sweep is the empirical confirmation.

---

## §1. The five OCSF-2003 consumers — suites green

| Consumer                                          | Package               | Result                                                                        | `class_uid` |
| ------------------------------------------------- | --------------------- | ----------------------------------------------------------------------------- | ----------- |
| Cloud Posture (F.3)                               | `cloud-posture`       | **148 passed / 9 skipped** ✅                                                 | 2003        |
| **Multi-Cloud Posture (D.5 — the changed agent)** | `multi-cloud-posture` | **344 passed / 12 skipped** ✅                                                | 2003        |
| K8s Posture (D.6)                                 | `k8s-posture`         | **309 passed** ✅                                                             | 2003        |
| DSPM Data Security                                | `data-security`       | **292 passed** ✅                                                             | 2003        |
| Compliance                                        | `compliance`          | **225 passed** ✅                                                             | 2003        |
|                                                   |                       | **1,318 tests across 5 consumers, all green** (+21 skipped: gated live lanes) |             |

**No collateral impact:** the four non-D.5 consumers' counts (148/309/292/225) are **identical** to the [F.3 v0.2 sweep](f-3-cloud-posture-v0-2-cross-agent-sweep-2026-06-08.md) — D.5's additions touched nothing outside its own package. D.5 itself grew **214 → 344 passed** across the v0.2 cycle (+130).

## §2. OCSF 2003 schema invariance — confirmed

All five `schemas` modules report **`class_uid 2003`** / **`v1.3.0`** (imported live). D.5's new `CSPMFindingType.AZURE_NATIVE` / `GCP_NATIVE` are **additive discriminators on `finding_info.types[0]`** inside the same 2003 envelope; the `provenance` field is **additive evidence**. No existing finding's shape changed — the offline eval cases stayed **10/10 byte-identical** through all 15 tasks.

## §3. KG write paths + audit chain

- **charter memory + SemanticStore (offline / aiosqlite):** green (**405 passed / 8 skipped** in the combined `charter` + `audit` run). KG entity/relationship + per-agent `kg_writer` paths carry no drift.
- **Multi-tenant RLS (live Postgres):** **NOT verifiable** — still blocked by the parked multi-bug substrate cycle (PR #253: LTREE / pgvector / RLS-FORCE). Same standing item as F.3; offline-only verification. → Watch-Item (unchanged).
- **Audit chain (F.6 verifier):** green in isolation; one **known flaky test recurred** — see §4.

## §4. Findings + Watch-Items

1. ✅ **OCSF 2003 invariant holds** across all 5 consumers; D.5 v0.2 is additive-discriminator, not shape-changing.
2. ✅ **All 5 consumer suites green**; zero collateral on the four non-D.5 consumers.
3. 🟡 **WI-A (recurrence) — flaky audit caplog test:** `packages/agents/audit/tests/test_agent.py::test_run_logs_warning_when_non_wall_clock_budget_overrun` failed once in the _combined_ charter+audit run — the **same pre-existing cross-package `caplog` flake** captured in backlog [`#264`](backlog/2026-06-08-flaky-audit-caplog-test.md). Passes in isolation / in-package / in CI; **not** caused by D.5 (which touched only `multi-cloud-posture`). Not fixed here (guard-only). Still opportunistic.
4. 🟡 **WI-B (unchanged) — live-Postgres RLS unverifiable:** blocked by the parked #253 substrate cycle.

## §5. Verdict

**D.5 v0.2's offline + native-rule + provenance changes are regression-clean for the OCSF-2003 family.** All five consumer suites pass, the `class_uid 2003` wire shape is invariant, KG (offline) + audit-chain paths are green. The two 🟡 items are pre-existing and out of D.5's scope. **No consumer code was modified; no blocker for D.5 v0.2 closure.**

---

— recorded 2026-06-09 (D.5 v0.2 Task 16, cross-agent OCSF 2003 regression sweep; guard-only, no code changes).
