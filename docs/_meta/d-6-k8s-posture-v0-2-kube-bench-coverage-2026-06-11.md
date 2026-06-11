# k8s-posture v0.2 — kube-bench Coverage (WI-K1)

**Date:** 2026-06-11 · Measured **per-tool**, no aggregate (WI-K1).

## Covered at v0.2

- Live kube-bench scan execution against a **running cluster** (kubeconfig-based, injectable
  runner) via `tools/kube_bench_live.py`, alongside the offline `read_kube_bench` (Q1 coexist).
- Byte-identical parse with the offline reader (shared `_extract_controls` + `_walk_control`;
  `model_dump` equality test) → OCSF 2003 via the shared normalizer.
- **CIS Kubernetes Benchmark v1.8** control catalog (`cis/benchmark.py`) spanning sections
  1-5 (control plane / etcd / config / worker / policies) — broader than v0.1's ~v1.5 subset.

## NOT covered (v0.3+)

- Running kube-bench **as an in-cluster Job** end-to-end (the prod runner is defined; CI uses
  an injected fake — WI-K3 honest scope).
- Full CIS v1.8 control set (the catalog is a representative subset, not all ~120 controls).
- Remediation automation (read-only posture only).

## Honest estimate

**~55-65% `[estimate]`** of the kube-bench signal a CIS-posture consumer wants — strong on
live scan execution + byte-identical normalization + the v1.8 catalog breadth, absent on the
full control set + the in-cluster Job execution loop. Estimate, not a measured benchmark.
