# Runbook — Live Polaris Audit (k8s-posture v0.2)

Live Polaris workload-policy audit against a running cluster.

## Setup

1. Ensure `polaris audit` can reach the cluster API server (`polaris audit --format json`).
2. Point `KUBECONFIG` at the cluster.
3. (Optional) Declare custom policies in the customer profile (`customer_context.md`):
   ```yaml
   ---
   polaris_policies:
     - check_id: runAsRootAllowed
       severity: danger
       enabled: true
     - check_id: hostNetworkSet
       enabled: false
   ---
   ```

## Run (gated live)

```bash
KUBECONFIG=~/.kube/config NEXUS_LIVE_K8S_POSTURE=1 uv run pytest \
  packages/agents/k8s-posture/tests/integration/test_k8s_live_e2e.py -v -k polaris
```

## Notes

- Live audit runs alongside the offline `read_polaris` — findings byte-identical → OCSF 2003.
- Custom policies overlay the defaults (`polaris/custom_policy.py`); defaults preserved when
  none are declared.
- Single-cluster + kubeconfig-secret-safety invariants apply (see the kube-bench runbook).
