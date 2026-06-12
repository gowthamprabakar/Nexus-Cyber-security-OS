# synthesis v0.2 — Per-Source Coverage (WI-Y1)

**Date:** 2026-06-12 · Measured **per source agent**, no aggregate (WI-Y1). All `[estimate]`.

## Covered at v0.2

D.13 now narrates the **12 closed-cycle source agents** (Q3; supervisor excluded — it emits F.6
audit only). Each source's findings are read (`fleet_workspace_reader`), enumerated by
class_uid + severity (`fleet_enumeration`), and risk-ranked into the cross-source narrative
(`cross_source`). The narrative is emitted as **OCSF 2004** (markdown preserved alongside, Q1).

| Source                    | Coverage | Notes                         |
| ------------------------- | -------- | ----------------------------- |
| investigation (D.7)       | ~60%     | original 3-source set         |
| compliance (D.6)          | ~60%     | original; dependency-weighted |
| cloud_posture (F.3)       | ~60%     | original                      |
| multi_cloud_posture (D.5) | ~55%     | net-new at v0.2               |
| vulnerability (D.1)       | ~55%     | net-new                       |
| identity (D.2)            | ~55%     | net-new                       |
| threat_intel (D.8)        | ~55%     | net-new                       |
| runtime_threat (D.3)      | ~55%     | net-new                       |
| network_threat (D.4)      | ~55%     | net-new                       |
| k8s_posture               | ~55%     | net-new                       |
| data_security             | ~55%     | net-new                       |
| audit (F.6)               | ~55%     | net-new                       |

## NOT covered (v0.3)

4th LLM call for risk-prioritization (Q2) · follow-up question generation (Q2) · multi-provider
scoreboard beyond DeepSeek+Anthropic (Q5) · per-tenant LLM cost optimization. Production-loop
wiring is **Phase C** (WI-Y2), not v0.3.

## Honest estimate (WI-Y3)

**~50-60% `[estimate]`** of the narrative-synthesis signal — 12-source coverage + OCSF emission

- provider fallback are solid; the 4th LLM call + production loop are deferred. Estimate, not a
  benchmark.
