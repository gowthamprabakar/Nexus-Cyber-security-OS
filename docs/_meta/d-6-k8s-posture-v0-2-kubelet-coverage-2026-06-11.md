# k8s-posture v0.2 — kubelet API + RBAC Coverage (WI-K1)

**Date:** 2026-06-11 · Measured **per-tool**, no aggregate (WI-K1).

## Covered at v0.2 (net-new — not present in v0.1)

- **kubelet API client** (`tools/kubelet_client.py`): read-only `/pods` + `/stats/summary` +
  `/healthz` over an injectable transport (kubeconfig-authenticated in prod).
- **Runtime state enumeration** (`runtime/enumerate.py`): pods → containers + security-context
  fields (privileged, runAsUser, added capabilities, hostNetwork/hostPID, read-only root FS).
- **Runtime posture rules** (`runtime/posture_rules.py`): privileged / hostNetwork / hostPID /
  run-as-root / dangerous-caps / privilege-escalation / writable-root-fs → OCSF 2003 (RUNTIME).
- **Basic RBAC analysis** (`rbac/`): enumerate roles + bindings; over-privileged heuristic
  (wildcard `*.*.*`, broad secret access, cluster-admin→ServiceAccount) → OCSF 2003 (RBAC).

## NOT covered (v0.3+)

- **Full effective-permissions RBAC simulation** (cluster-roles × role-bindings resolution) —
  Q4 explicit v0.3; v0.2 is a basic heuristic.
- Runtime drift detection + admission webhooks (Q6 — v0.3 / L3).
- kubelet `/metrics` + `/configz` + per-node throttle backoff (WI-K10 awareness only at v0.2).

## Honest estimate

**~40-50% `[estimate]`** for runtime posture + **~35-45% `[estimate]`** for RBAC — the kubelet
client + runtime rules + RBAC heuristic are net-new and emit OCSF 2003, but the full
effective-perms sim, runtime drift, and admission-time enforcement are deferred. Estimates,
not measured benchmarks.
