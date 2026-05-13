# Example 2 — Polaris danger + manifest rule coexist on the same workload

**Input:** A `Deployment` named `frontend` in namespace `production` running container `nginx`. Both a Polaris audit and the bundled manifest analyser scan it.

**Observation:**

- Polaris flags `runAsRootAllowed` as **danger** on container `nginx` (Polaris's wording for "the security context permits root").
- The manifest analyser flags `run-as-root` on the same container (the manifest sets `runAsUser: 0`).
- The manifest analyser ALSO flags `missing-resource-limits` on the same container (no `resources.limits` block).

**Detection (deterministic, no LLM):**

```yaml
- finding_id: CSPM-KUBERNETES-POLARIS-001-runasrootallowed
  finding_type: cspm_k8s_polaris
  severity: HIGH # Polaris `danger`
  title: 'runAsRootAllowed: Should not be allowed to run as root'
  rule_id: runAsRootAllowed
  affected:
    - cloud: kubernetes
      account_id: production
      region: cluster
      resource_type: Deployment
      resource_id: production/frontend/nginx
      arn: k8s://workload/production/Deployment/frontend#nginx
  evidence:
    kind: polaris
    check_id: runAsRootAllowed
    check_level: container
    polaris_severity: danger
    workload_kind: Deployment
    namespace: production
    container_name: nginx
    source_finding_type: cspm_k8s_polaris

- finding_id: CSPM-KUBERNETES-MANIFEST-001-run-as-root-frontend
  finding_type: cspm_k8s_manifest
  severity: HIGH # fixed per-rule for run-as-root
  title: 'run-as-root: Container running as root'
  rule_id: run-as-root
  affected:
    - cloud: kubernetes
      account_id: production
      region: cluster
      resource_type: Deployment
      resource_id: production/frontend/nginx
      arn: k8s://manifest/production/Deployment/frontend#nginx
  evidence:
    kind: manifest
    rule_id: run-as-root
    workload_kind: Deployment
    namespace: production
    container_name: nginx
    manifest_path: /manifests/frontend.yaml
    source_finding_type: cspm_k8s_manifest

- finding_id: CSPM-KUBERNETES-MANIFEST-001-missing-resource-limits-frontend
  finding_type: cspm_k8s_manifest
  severity: MEDIUM # fixed per-rule
  title: 'missing-resource-limits: Missing resource limits'
  rule_id: missing-resource-limits
  affected:
    - cloud: kubernetes
      account_id: production
      region: cluster
      resource_type: Deployment
      arn: k8s://manifest/production/Deployment/frontend#nginx
  evidence:
    kind: manifest
    rule_id: missing-resource-limits
    source_finding_type: cspm_k8s_manifest
```

**Dedup behaviour:** The Polaris finding (`rule_id=runAsRootAllowed`, `arn=k8s://workload/…`) and the manifest finding (`rule_id=run-as-root`, `arn=k8s://manifest/…`) have DIFFERENT composite keys — they do NOT collapse in v0.1. Operators see both findings, which is intentional: the wording of Polaris's check carries different signal than the manifest analyser's bare rule (e.g., Polaris's `danger` severity is config-tunable; the manifest rule is fixed). A future ontology map could merge them; deferred per Q3.

**Markdown report layout** (operator-facing):

```
# Kubernetes Posture Scan
- Total findings: **3**

## Per-namespace breakdown
- **production**: 3 findings (Deployment/frontend: 3)

## HIGH
- [CSPM-KUBERNETES-POLARIS-001-runasrootallowed] runAsRootAllowed (production/frontend/nginx)
- [CSPM-KUBERNETES-MANIFEST-001-run-as-root-frontend] run-as-root (production/frontend/nginx)

## MEDIUM
- [CSPM-KUBERNETES-MANIFEST-001-missing-resource-limits-frontend] missing-resource-limits (production/frontend/nginx)
```

**Why this example matters:** Documents the v0.1 dedup boundary. Two independent posture tools converging on the same workload is the **most-common operator confusion point**; the report layout deliberately preserves both signals so the operator can correlate provenance (`evidences[0].source_finding_type` distinguishes them).
