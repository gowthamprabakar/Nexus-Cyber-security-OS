# Runbook — Live kube-bench Scan (k8s-posture v0.2)

Live CIS-benchmark scan against a running cluster (any provider — kubeconfig is the interface).

## Setup

1. Ensure `kube-bench` is runnable against the target cluster (in-cluster Job or a node with
   access). Output must be JSON (`kube-bench --json`).
2. Point `KUBECONFIG` at the cluster (EKS / AKS / GKE / self-managed).

## Run (gated live)

```bash
KUBECONFIG=~/.kube/config NEXUS_LIVE_K8S_POSTURE=1 uv run pytest \
  packages/agents/k8s-posture/tests/integration/test_k8s_live_e2e.py -v
```

## Notes

- Live scan runs **alongside** the offline `read_kube_bench` (Q1) — findings parse
  byte-identical (shared parser) → OCSF 2003 Compliance Findings.
- CIS Kubernetes Benchmark **v1.8** catalog (`cis/benchmark.py`).
- **Single cluster per scan** (Q3/WI-K8): `assert_single_cluster_context` +
  `ClusterScanSession` reject cross-cluster context leak.
- **kubeconfig secrets** (tokens/certs/keys) are never logged — `redact_kubeconfig` (WI-K9).
