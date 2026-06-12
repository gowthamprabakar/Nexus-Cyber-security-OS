# supervisor v0.2 — Per-Agent Dispatch Coverage (WI-O1)

**Date:** 2026-06-12 · Measured **per-agent**, no aggregate (WI-O1). All `[estimate]`.

## Full dispatch (the 11 v0.2 agents, Q1)

Each of these gets registry-validated full dispatch (`plan_live_delegations` -> `execute_live`),
per-agent concurrency (default cap 4), failure classification + bounded transient retry, and
F.6 audit emission. Dispatch-path coverage is **infrastructure-complete**; the residual is the
production-loop wiring (Phase C).

| Agent                     | Dispatch  | Notes                                                   |
| ------------------------- | --------- | ------------------------------------------------------- |
| cloud_posture (F.3)       | full ~70% | dependency source for compliance                        |
| multi_cloud_posture (D.5) | full ~70% | dependency source for compliance                        |
| vulnerability (D.1)       | full ~65% |                                                         |
| identity (D.2)            | full ~65% |                                                         |
| threat_intel (D.8)        | full ~65% |                                                         |
| runtime_threat (D.3)      | full ~65% | real-time class                                         |
| network_threat (D.4)      | full ~65% | real-time class                                         |
| k8s_posture               | full ~70% | dependency source for compliance                        |
| compliance (D.6)          | full ~70% | depends on the 3 posture agents (order_by_dependencies) |
| data_security             | full ~65% |                                                         |
| audit (F.6)               | full ~70% | also the audit sink for supervisor's own vocabulary     |

## Basic dispatch (remaining built agents, until their v0.2)

synthesis · investigation · curiosity · remediation · meta_harness — **~30% `[estimate]`**:
routed + dispatched, but they reach full dispatch only when their own v0.2 cycle lands (Q1).

## NOT covered (v0.3)

Per-tenant concurrency (Q2) · full circuit-breaker (Q3) · F.6 chain read-integration (Q4) ·
Postgres-backed queue via F.5 (Q5). Production-loop wiring is **Phase C**, not v0.3 (WI-O2).
