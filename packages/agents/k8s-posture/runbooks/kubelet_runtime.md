# Runbook — kubelet Runtime + RBAC Posture (k8s-posture v0.2)

Live runtime posture (kubelet `/pods`) + basic RBAC analysis against a running cluster.

## Setup

1. Grant the agent's principal read access to the kubelet API (via the API-server node proxy)
   and to RBAC objects (`clusterroles`, `roles`, `clusterrolebindings`, `rolebindings`).
2. Point `KUBECONFIG` at the cluster.

## Run (gated live)

```bash
KUBECONFIG=~/.kube/config NEXUS_LIVE_K8S_POSTURE=1 uv run pytest \
  packages/agents/k8s-posture/tests/integration/test_k8s_live_e2e.py -v -k "runtime or rbac"
```

## What it flags

- **Runtime** (`runtime/posture_rules.py`): privileged containers, hostNetwork/hostPID,
  run-as-root, dangerous capabilities, privilege escalation, writable root FS → OCSF 2003.
- **RBAC** (`rbac/over_privileged.py`, Q4 **basic heuristic**): wildcard `*.*.*` roles, broad
  Secret access, cluster-admin bound to a ServiceAccount → OCSF 2003.

## Notes

- **Out of scope at v0.2:** full effective-permissions RBAC simulation (Q4 → v0.3), runtime
  drift detection + admission webhooks (Q6 → v0.3). kubelet per-node rate-limit backoff is
  awareness-only at v0.2 (WI-K10).
- Single-cluster + kubeconfig-secret-safety invariants apply.
