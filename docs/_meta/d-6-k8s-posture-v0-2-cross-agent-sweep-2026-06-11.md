# D.6 K8s Posture v0.2 — Cross-Agent OCSF 2003 Consumer Sweep (WI-K6)

**Date:** 2026-06-11 · **Task:** D.6 v0.2 Task 20 · **Scope:** prove D.6 v0.2 changes
don't break any OCSF v1.3 Compliance Finding (`class_uid 2003`) emitter or downstream
consumer. **3 emitters** (F.3, D.5, D.6) share the 2003 wire shape.

## Why this is safe by construction

Every D.6 v0.2 change was kept **off** the offline OCSF emission path:

- The live kube-bench / Polaris / kubelet readers, CIS v1.8 catalog, runtime + RBAC
  detectors, isolation guard, kubeconfig safety, and cluster-auth are **new modules** not
  wired into the deterministic `run()` path.
- Live findings normalize via the **shared** kube-bench/Polaris normalizers (byte-identical,
  proven by `to_dict()` equality tests); the new RBAC/RUNTIME finding types are **additive**
  enum members emitted only on the live path — so the offline `run()` + the 10 eval cases +
  the OCSF 2003 wire shape are byte-identical (WI-K5).

## OCSF 2003 emitters (3 — share the `class_uid 2003` wire shape)

| Agent                        | Suite                                 | Result                     |
| ---------------------------- | ------------------------------------- | -------------------------- |
| F.3 Cloud Posture            | `packages/agents/cloud-posture`       | **148 passed, 9 skipped**  |
| D.5 Multi-Cloud Posture      | `packages/agents/multi-cloud-posture` | **344 passed, 12 skipped** |
| D.6 K8s Posture (this cycle) | `packages/agents/k8s-posture`         | **431 passed, 1 skipped**  |

## Downstream consumers (read / route / synthesize 2003 findings)

| Agent             | Suite                           | Result                    |
| ----------------- | ------------------------------- | ------------------------- |
| Compliance        | `packages/agents/compliance`    | **225 passed**            |
| Audit             | `packages/agents/audit`         | **129 passed**            |
| Synthesis         | `packages/agents/synthesis`     | **214 passed, 1 skipped** |
| A.1 Remediation   | `packages/agents/remediation`   | **455 passed, 6 skipped** |
| D.7 Investigation | `packages/agents/investigation` | **254 passed, 2 skipped** |

## Result

**All 3 emitters + 5 consumers green — 0 failures.** Total (8 agents): **2200 passed, 31
skipped, 0 failed**; the full-repo run at Task 19 was **5949 passed, 65 skipped, 0
failed**. No OCSF 2003 wire-shape drift; substrate seal empty the entire cycle (schemas.py
additions are k8s-local + additive). D.6 v0.2 introduces no cross-agent regression.
