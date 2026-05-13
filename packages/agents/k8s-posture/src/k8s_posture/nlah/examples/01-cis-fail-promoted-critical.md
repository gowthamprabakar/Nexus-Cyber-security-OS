# Example 1 — CIS FAIL promoted to CRITICAL by upstream marker

**Input:** A snapshot of `kube-bench --json` for a cluster's master node.

**Observation:** One result flags `1.1.1 Ensure API server pod specification file permissions are set to 644 or more restrictive` as **FAIL** with `severity: critical` set upstream. A second result on the same master flags `1.1.2 Ensure API server pod specification file ownership is set to root:root` as **FAIL** without the critical marker.

**Detection (deterministic, no LLM):**

```yaml
- finding_id: CSPM-KUBERNETES-CIS-001-master-1-1-1-ensure-api-server-pod-spec
  finding_type: cspm_k8s_cis
  severity: CRITICAL # upstream `severity: critical` marker promotes from HIGH
  title: '1.1.1: Ensure API server pod specification file permissions are set to 644 or more restrictive'
  rule_id: '1.1.1'
  affected:
    - cloud: kubernetes
      account_id: master
      region: cluster
      resource_type: MasterNode
      resource_id: master/1.1.1
      arn: k8s://cis/master/1.1.1
  evidence:
    kind: kube-bench
    control_id: '1.1.1'
    node_type: master
    status: FAIL
    severity_marker: critical
    audit: 'stat -c %a /etc/kubernetes/manifests/kube-apiserver.yaml'
    actual_value: '777'
    source_finding_type: cspm_k8s_cis

- finding_id: CSPM-KUBERNETES-CIS-002-master-1-1-2-ensure-api-server-pod-spec
  finding_type: cspm_k8s_cis
  severity: HIGH # FAIL without critical marker → HIGH
  title: '1.1.2: Ensure API server pod specification file ownership is set to root:root'
  rule_id: '1.1.2'
  affected:
    - cloud: kubernetes
      account_id: master
      region: cluster
      resource_type: MasterNode
      arn: k8s://cis/master/1.1.2
  evidence:
    kind: kube-bench
    control_id: '1.1.2'
    node_type: master
    status: FAIL
    source_finding_type: cspm_k8s_cis
```

**Markdown report layout** (operator-facing):

```
# Kubernetes Posture Scan
- Total findings: **2**

## Per-namespace breakdown
- **master** (node): 2 findings

## CRITICAL (pinned)
- [CSPM-KUBERNETES-CIS-001-master-1-1-1-…] API server pod-spec permissions (FAIL · critical)

## HIGH
- [CSPM-KUBERNETES-CIS-002-master-1-1-2-…] API server pod-spec ownership (FAIL)
```

**Why this example matters:** Documents that an upstream `severity: critical` marker on a kube-bench control **overrides** the default FAIL→HIGH mapping. Operators reading the report see the critical finding pinned above the per-severity sections — the most-deployed CIS uplift pattern (worker-node TLS, controller-manager auth, etcd encryption-at-rest) all surface through this exact path.
