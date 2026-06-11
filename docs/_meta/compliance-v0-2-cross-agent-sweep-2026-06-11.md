# compliance v0.2 — Cross-Agent OCSF 2003 Consumer Sweep (WI-C7)

**Date:** 2026-06-11 · **Task:** compliance v0.2 Task 21 · **Scope:** prove compliance v0.2
changes don't break any OCSF v1.3 Compliance Finding (`class_uid 2003`) emitter or
downstream consumer. **Now 4 emitters** (F.3, D.5, k8s-posture, compliance) — the largest
OCSF 2003 sweep yet.

## Why this is safe by construction

Every compliance v0.2 change was kept **additive** and **off** the offline OCSF emission
path:

- The CIS-family control libraries (Azure/GCP/K8s) + their readers, PASS attestation,
  multi-emitter consumption, continuous infrastructure (scheduler + delta + mode), and
  evidence packaging are **new modules**; the FAIL `build_finding` path is unchanged.
- `build_pass_finding` + the `ComplianceFramework` Azure/GCP/K8s enum members + the PASSED
  status are **additive** and emitted only on the live/consumption path — so the offline
  `run()` + the 10 eval cases + the FAIL wire shape are byte-identical (WI-C5).

## OCSF 2003 emitters (4 — share the `class_uid 2003` wire shape)

| Agent                   | Suite                                 | Result                     |
| ----------------------- | ------------------------------------- | -------------------------- |
| F.3 Cloud Posture       | `packages/agents/cloud-posture`       | **148 passed, 9 skipped**  |
| D.5 Multi-Cloud Posture | `packages/agents/multi-cloud-posture` | **344 passed, 12 skipped** |
| k8s-posture             | `packages/agents/k8s-posture`         | **431 passed, 1 skipped**  |
| compliance (this cycle) | `packages/agents/compliance`          | **351 passed, 1 skipped**  |

## Downstream consumers (read / route / synthesize 2003 findings)

| Agent             | Suite                           | Result                    |
| ----------------- | ------------------------------- | ------------------------- |
| Audit             | `packages/agents/audit`         | **129 passed**            |
| Synthesis         | `packages/agents/synthesis`     | **214 passed, 1 skipped** |
| A.1 Remediation   | `packages/agents/remediation`   | **455 passed, 6 skipped** |
| D.7 Investigation | `packages/agents/investigation` | **254 passed, 2 skipped** |

## Result

**All 4 emitters + 4 consumers green — 0 failures.** Total (8 agents): **2326 passed, 32
skipped, 0 failed**; the full-repo run at Task 20 was **6075 passed, 66 skipped, 0 failed**.
No OCSF 2003 wire-shape drift; substrate seal empty the entire cycle. compliance is itself
both a **consumer** (of F.3/D.5/k8s-posture) and now the **4th emitter**, and introduces no
cross-agent regression.
