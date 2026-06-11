# compliance v0.2 — CIS-K8s Coverage (WI-C1)

**Date:** 2026-06-11 · Measured **per-framework**, no aggregate (WI-C1).

## Covered at v0.2

- CIS Kubernetes Benchmark v1.8 library: **15 controls**, **all 15 wired** — the strongest
  framework, because k8s-posture's kube-bench findings carry `rule_id == the CIS control id`,
  so each control maps to its own id (1:1).
- **Multi-source**: 3 controls also cross-map to k8s-posture's fixed runtime/RBAC rules
  (5.2.2 -> privileged-container, 5.2.6 -> run-as-root, 5.1.1 -> cluster-admin-binding).
- Source agent `k8s_posture`; exact matching.

## NOT covered (Phase D / v0.3)

- The full CIS-K8s v1.8 control set (~120 controls) — v0.2 ships k8s-posture's CIS_K8S_V18
  catalog (15). Broader coverage tracks k8s-posture's catalog expanding.

## Honest estimate

**~12% `[estimate]`** of the full CIS-K8s v1.8 set (15 of ~120), but **100% of k8s-posture's
emitted catalog** is wired — the tightest emitter-to-compliance coupling of the four
frameworks. Estimate, not a measured benchmark.
