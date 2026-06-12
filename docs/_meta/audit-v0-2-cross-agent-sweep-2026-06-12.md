# audit v0.2 — Cross-Agent OCSF Sweep (WI-F6) — the FIRST 10-emitter sweep

**Date:** 2026-06-12 · **Task:** audit v0.2 Task 17 · **Scope:** prove audit (F.6) v0.2 changes
don't perturb any OCSF v1.3 emitter or consumer. audit is the **first OCSF 6003 (API Activity)
emitter** — the fleet now has **10 OCSF emitters across 3 classes**, the largest sweep yet.

## Why this is safe by construction

Every audit v0.2 change was kept **additive** and **off** the offline OCSF-6003 emission path:
the cross-agent aggregation, Merkle index, tamper detection + alerts, typed query engine,
compliance-evidence integration, the code-level read-only + cross-tenant invariants, and the
live lane are **new modules**. The normal audit-record `to_ocsf` path is untouched, so the
6003 wire shape — chain hashes in the unmapped slot — and the 10 offline eval cases are
byte-identical (WI-F5). **F.6's single `BY_DESIGN_EXEMPT` tool-proxy deviation is preserved;
no new exemption was added (WI-F10).**

## The 10 OCSF emitters across the fleet

### class_uid 2003 — Compliance Finding (5)

| Agent                   | Suite                 | Result                     |
| ----------------------- | --------------------- | -------------------------- |
| F.3 Cloud Posture       | `cloud-posture`       | **148 passed, 9 skipped**  |
| D.5 Multi-Cloud Posture | `multi-cloud-posture` | **344 passed, 12 skipped** |
| k8s-posture             | `k8s-posture`         | **431 passed, 1 skipped**  |
| compliance              | `compliance`          | **351 passed, 1 skipped**  |
| data-security           | `data-security`       | **459 passed, 1 skipped**  |

### class_uid 2004 — Detection Finding (4)

| Agent              | Suite            | Result                    |
| ------------------ | ---------------- | ------------------------- |
| D.2 Identity       | `identity`       | **211 passed, 1 skipped** |
| D.3 Runtime Threat | `runtime-threat` | **317 passed, 2 skipped** |
| D.4 Network Threat | `network-threat` | **387 passed, 3 skipped** |
| D.8 Threat Intel   | `threat-intel`   | **400 passed, 2 skipped** |

### class_uid 6003 — API Activity (1, NEW)

| Agent                  | Suite   | Result                    |
| ---------------------- | ------- | ------------------------- |
| F.6 audit (this cycle) | `audit` | **270 passed, 1 skipped** |

## Downstream consumers (spot check)

| Agent           | Suite         | Result                    |
| --------------- | ------------- | ------------------------- |
| Synthesis       | `synthesis`   | **214 passed, 1 skipped** |
| A.1 Remediation | `remediation` | **455 passed, 6 skipped** |
| Supervisor      | `supervisor`  | **234 passed**            |

## Result

**All 10 emitters + 3 consumers green — 0 failures.** Total (13 agents): **4221 passed, 40
skipped, 0 failed**; the full-repo run at Task 16 was **6383 passed, 68 skipped, 0 failed**. No
OCSF wire-shape drift across 2003 / 2004 / 6003; substrate seal empty the entire cycle; F.6
deviation preserved. audit v0.2 introduces no cross-agent regression.
