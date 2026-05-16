# Kubernetes posture scan — operator runbook

Owner: k8s-posture on-call · Audience: a Kubernetes-security operator / SRE with read access to a target cluster (kubeconfig) and the ability to run `kube-bench`, `polaris`, and `helm template` against it · Last reviewed: 2026-05-13.

This runbook walks an operator through pointing the Kubernetes Posture Agent (D.6) at the three v0.1 feeds — kube-bench JSON + Polaris JSON + a manifest directory — interpreting the OCSF Compliance Findings it emits, and routing the findings into the rest of the Nexus pipeline (D.7 Investigation, F.6 Audit).

> **Status:** v0.1. Live cluster API ingest (`kubernetes-client` + Helm chart inventory + admission-webhook posture) ships in Phase 1c. v0.1 reads operator-pinned filesystem snapshots.

---

## Prerequisites

- A working `uv sync` of this repository.
- **At least one** of the three feeds:
  - **kube-bench** JSON output for the target cluster.
  - **Polaris** JSON output for the target cluster.
  - A directory of Kubernetes manifests (`*.yaml` + `*.yml`). Helm-rendered templates are accepted (pre-render with `helm template`).
- An `ExecutionContract` YAML for the run.

The agent **never writes** to the cluster. Every call is a filesystem read — safe to run against snapshots copied off production.

---

## 1. Stage the feeds

### 1a. kube-bench (CIS Kubernetes Benchmark)

```bash
# Run kube-bench against the target cluster (as a Job is the recommended pattern):
kubectl apply -f https://raw.githubusercontent.com/aquasecurity/kube-bench/main/job.yaml
kubectl wait --for=condition=complete --timeout=120s job/kube-bench

# Extract the JSON output (kube-bench writes to stdout; capture from the pod):
POD=$(kubectl get pods -l job-name=kube-bench -o jsonpath='{.items[0].metadata.name}')
kubectl logs "$POD" > /tmp/kube-bench.json

# Or run directly on a control-plane node (when you have SSH access):
kube-bench --json --targets master,etcd,policies > /tmp/kube-bench-master.json
kube-bench --json --targets node > /tmp/kube-bench-worker.json
```

The reader auto-detects the canonical `{"Controls": [...]}` shape and a bare-array shape. Status values: `PASS` / `FAIL` / `WARN` / `INFO`. `PASS` and `INFO` are filtered at the reader (not findings). A `severity: critical` marker on a control promotes its finding to CRITICAL.

### 1b. Polaris (workload posture)

```bash
# Run polaris audit against the active kubeconfig context:
polaris audit \
    --format=json \
    --kubeconfig "$KUBECONFIG" \
    > /tmp/polaris.json

# Polaris also has a `kube` mode that runs inside the cluster:
polaris audit --format=json > /tmp/polaris.json  # inside the cluster
```

The reader walks all three Polaris check levels:

- **workload** — top-level workload checks (e.g. `multipleReplicasForDeployment`)
- **pod** — pod-spec checks (e.g. `hostNetworkSet`, `hostPIDSet`)
- **container** — container-spec checks (e.g. `runAsRootAllowed`, `privilegeEscalationAllowed`)

Only `Success: false` records become findings. Severity values: `danger` → HIGH, `warning` → MEDIUM, `ignore` → filtered.

### 1c. Workload source — pick ONE of 1c.i or 1c.ii

The workload-posture analyser (the 10-rule manifest analyser) reads workloads from **one** of two sources. They are mutually exclusive (Q6 of the v0.2 plan) — supplying both flags is a CLI error.

#### 1c.i. Offline manifest directory (v0.1; default)

Stage a flat directory of `*.yaml` files. Helm-rendered templates work — pre-render with `helm template`:

```bash
mkdir -p /tmp/manifests/
# Plain manifests:
cp k8s/*.yaml /tmp/manifests/
# Helm-rendered:
helm template my-release my-chart/ > /tmp/manifests/my-release.yaml
helm template grafana grafana/grafana > /tmp/manifests/grafana.yaml
# Multi-document YAML supported (split or combined).
```

The bundled 10-rule analyser supports these kinds (pod templates are walked):

- `Pod` — `spec`
- `Deployment` / `StatefulSet` / `DaemonSet` / `ReplicaSet` / `Job` — `spec.template.spec`
- `CronJob` — `spec.jobTemplate.spec.template.spec`

Both `containers` and `initContainers` are walked. Other kinds (Service / Ingress / ConfigMap / Secret / etc.) are silently skipped — they don't carry pod posture.

#### 1c.ii. Live cluster via kubeconfig (v0.2; recommended for ad-hoc scans)

Point the agent at a kubeconfig file. The agent uses the kubernetes Python SDK to read live workloads — no manifest pre-staging required:

```bash
# Use the active kubeconfig:
uv run k8s-posture run \
    --contract /tmp/contract.yaml \
    --kubeconfig "$KUBECONFIG" \
    --cluster-namespace production    # optional; cluster-wide if omitted

# Or point at any operator-pinned kubeconfig:
uv run k8s-posture run \
    --contract /tmp/contract.yaml \
    --kubeconfig /etc/nexus/kubeconfigs/prod-readonly.yaml
```

Live mode reads the same 7 workload kinds (Pod / Deployment / StatefulSet / DaemonSet / ReplicaSet / Job / CronJob) and runs the **same** 10-rule analyser as the offline path. The findings have a sentinel `manifest_path` of the form `cluster:///<namespace>/<kind>/<name>` so operators can distinguish live-sourced from file-sourced findings in `findings.json`.

**RBAC requirements for the agent's read role:**

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: nexus-k8s-posture-reader
rules:
  - apiGroups: ['']
    resources: [pods]
    verbs: [list]
  - apiGroups: [apps]
    resources: [deployments, statefulsets, daemonsets, replicasets]
    verbs: [list]
  - apiGroups: [batch]
    resources: [jobs, cronjobs]
    verbs: [list]
```

A `403 Forbidden` on any of these list calls raises `ClusterReaderError` immediately — the agent refuses to produce partial coverage. Other non-2xx (e.g. `404` on an older cluster that lacks `batch/v1 CronJob`) is silently skipped per-kind so the run still completes against the kinds we can read.

**v0.2 limitations** (Phase 1c+ work):

- **No in-cluster fallback** (Q4) — `--kubeconfig` is required. The Pod-mounted ServiceAccount token path ships in v0.3 once we settle on the mount conventions.
- **Workloads only.** RBAC bindings, admission webhooks, Helm releases, OPA constraints, Pod Security Standards, and NetworkPolicy graphs each get their own follow-on agents/plans.
- **No --kubeconfig + --manifest-dir combo.** Cross-source validation (reading both and asserting parity) is deferred — operators pick one source per run.

---

## 2. Write the `ExecutionContract`

Minimal `contract.yaml`:

```yaml
schema_version: '0.1'
delegation_id: 01J7M3X9Z1K8RPVQNH2T8DBHFZ
source_agent: supervisor
target_agent: k8s_posture
customer_id: cust_acme
task: Kubernetes posture scan — 2026-05-13 quarterly review
required_outputs:
  - findings.json
  - report.md
budget:
  llm_calls: 0 # normalizers + dedup are deterministic; LLM not called in v0.1
  tokens: 0
  wall_clock_sec: 60.0
  cloud_api_calls: 0
  mb_written: 10
permitted_tools:
  - read_kube_bench
  - read_polaris
  - read_manifests
  - read_cluster_workloads # v0.2 — required when using --kubeconfig
completion_condition: findings.json AND report.md exist
escalation_rules: []
workspace: /workspaces/cust_acme/k8s_posture/01J7M3X9.../
persistent_root: /persistent/cust_acme/k8s_posture/
created_at: '2026-05-13T12:00:00Z'
expires_at: '2026-05-13T13:00:00Z'
```

---

## 3. Run the agent

**Offline mode (v0.1):**

```bash
uv run k8s-posture run \
    --contract /tmp/contract.yaml \
    --kube-bench-feed /tmp/kube-bench.json \
    --polaris-feed /tmp/polaris.json \
    --manifest-dir /tmp/manifests/
```

**Live cluster mode (v0.2):**

```bash
uv run k8s-posture run \
    --contract /tmp/contract.yaml \
    --kube-bench-feed /tmp/kube-bench.json \
    --polaris-feed /tmp/polaris.json \
    --kubeconfig "$KUBECONFIG" \
    --cluster-namespace production    # optional; cluster-wide if omitted
```

Each feed flag is optional — supply only what you have. With **no** feeds, the agent emits a clean empty report (useful for validating substrate plumbing). All three feeds run concurrently via `asyncio.TaskGroup`. `--manifest-dir` and `--kubeconfig` are mutually exclusive (Q6); `--cluster-namespace` requires `--kubeconfig`.

Sample output:

```
agent: k8s_posture (v0.1.0)
customer: cust_acme
run_id: 01J7M3X9Z1K8RPVQNH2T8DBHFZ
findings: 14
  critical: 2
  high: 8
  medium: 4
  low: 0
  info: 0
workspace: /workspaces/cust_acme/k8s_posture/01J7M3X9.../
```

---

## 4. Read the three artifacts

| File            | Format                                | Purpose                                                                                                                                          |
| --------------- | ------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| `findings.json` | `FindingsReport.model_dump_json()`    | Wire shape consumed by D.7 Investigation, fabric routing, Meta-Harness. OCSF 2003 array under `findings`. **Identical wire shape to F.3 + D.5.** |
| `report.md`     | Markdown                              | Operator summary. Per-namespace breakdown pinned at top; CRITICAL findings pinned above per-severity sections.                                   |
| `audit.jsonl`   | `charter.audit.AuditEntry` JSON-lines | This run's own hash-chained audit log. F.6 `audit-agent query` reads it.                                                                         |

### Reading `report.md`

Top-down layout:

```
# Kubernetes Posture Scan
- Customer / Run ID / Scan window / Total findings
## Per-namespace breakdown    ← PINNED. Per-namespace totals + per-source split (CIS / Polaris / Manifest)
## Severity breakdown         ← critical → info counts
## Source-type breakdown      ← 3 K8sFindingType discriminators
## Critical findings          ← PINNED (every CRITICAL, drop-everything)
## Findings
### Critical (N)
### High (N)
### Medium (N)
### Low (N)
### Info (N)
```

If you see no `## Critical findings` section, no CRITICAL findings fired — operate from the per-severity sections in order.

### Interpreting kube-bench findings

kube-bench reports against node types (master / worker / etcd / controlplane / policies). The OCSF resource shape uses `account_uid = <node_type>` as a stand-in for namespace (cluster-control scope, not workload scope). So in `report.md` you'll see kube-bench rows grouped under `**master**:`, `**worker**:`, etc. — alongside namespace rows for Polaris + manifest findings.

---

## 5. Severity escalation rules (deterministic, no LLM)

| Source            | Source value                                                               | OCSF `Severity` |
| ----------------- | -------------------------------------------------------------------------- | --------------- |
| kube-bench        | FAIL (default)                                                             | HIGH            |
| kube-bench        | WARN                                                                       | MEDIUM          |
| kube-bench        | PASS / INFO                                                                | (filtered)      |
| kube-bench        | (any) + `severity: critical` marker                                        | **CRITICAL**    |
| Polaris           | danger                                                                     | HIGH            |
| Polaris           | warning                                                                    | MEDIUM          |
| Polaris           | ignore                                                                     | (filtered)      |
| Manifest analyser | run-as-root / privileged / host-{network,pid,ipc} / privesc                | HIGH            |
| Manifest analyser | missing-resource-limits / image-pull-policy / read-only-fs / auto-mount-SA | MEDIUM          |

---

## 6. The DEDUP stage

D.6 is the first agent under ADR-007 with a dedicated DEDUP stage (added between NORMALIZE and SUMMARIZE). It collapses overlapping findings on the composite key:

`(rule_id, namespace, workload_arn, 5min_bucket)`

When two findings collide:

1. **Highest severity wins** (CRITICAL > HIGH > MEDIUM > LOW > INFO via OCSF `severity_id`).
2. **Ties broken by first-seen** (input order is preserved on survivors).
3. **Collapsed loser IDs** appended to the survivor's `evidences` as `{"kind": "dedup-sources", "finding_ids": [...]}`.

**Cross-tool collisions are rare.** kube-bench arns (`k8s://cis/<node_type>/<control_id>`) and Polaris/manifest arns (`k8s://workload/…` / `k8s://manifest/…`) never share a composite key. Within Polaris/manifest, container fragments are preserved (`…#nginx` vs `…#sidecar`) so distinct containers in the same workload stay distinct.

**Polaris's `runAsRootAllowed` and the manifest analyser's `run-as-root` have distinct `rule_id`s** — v0.1 deliberately keeps both signals. A future ontology map could merge them (deferred per Q3); the operator sees both findings and can correlate provenance via `evidences[0].source_finding_type`.

---

## 7. Routing findings downstream

### To D.7 Investigation

Pin the D.6 workspace as a `--sibling-workspace`:

```bash
uv run investigation-agent run \
    --contract /tmp/d7-contract.yaml \
    --sibling-workspace /workspaces/cust_acme/k8s_posture/01J7M3X9.../
```

D.7 reads `findings.json` and folds the Kubernetes posture findings into its 6-stage incident-correlation pipeline. **D.6 emits the same `class_uid 2003` as F.3 + D.5**, so D.7's correlation logic doesn't need K8s-specific code — only the `finding_info.types[0]` discriminator distinguishes the source.

### To F.6 Audit

D.6 emits its own audit chain at `<workspace>/audit.jsonl`:

```bash
uv run audit-agent query \
    --tenant cust_acme \
    --workspace /tmp/audit-query \
    --source /workspaces/cust_acme/k8s_posture/01J7M3X9.../audit.jsonl \
    --format markdown
```

### To remediation (Phase 1c — NOT in v0.1)

D.6 emits findings only; Track-A remediation (A.1-A.3) lands in Phase 1c and acts on the per-finding `rule_id` + `affected.resource_id` to drive Tier-1/2/3 actions (e.g. drop-in PSPs for `run-as-root`, controller patches for `missing-resource-limits`).

---

## 8. Troubleshooting

| Symptom                                                                           | Likely cause                                                                                                              | Fix                                                                                                                                                                              |
| --------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `findings: 0` with feeds clearly populated                                        | All kube-bench results are PASS / INFO; all Polaris records have `Success: true`; manifests use `kind`s we don't analyse. | Inspect raw counts via `jq '.Controls[].tests[].results[].status' /tmp/kube-bench.json` etc. Filtering is intentional — only actionable findings ride through.                   |
| `runAsRootAllowed` finding appears twice in `report.md` for the same container    | Polaris and the manifest analyser both flagged it (different `rule_id`s → distinct composite keys → no dedup).            | Expected v0.1 behaviour. Correlate via `evidences[0].source_finding_type`. Phase 1c may add an ontology map.                                                                     |
| Workload's findings under namespace `default` when manifest declares no namespace | The manifest reader defaults missing namespaces to `default`.                                                             | Add `metadata.namespace: <real-namespace>` to the manifest, or pre-render with `helm template -n <namespace>`.                                                                   |
| CronJob's pod-template rules don't fire                                           | CronJob nesting is `spec.jobTemplate.spec.template.spec` — verify your CronJob conforms to the upstream schema.           | Validate the manifest with `kubectl apply --dry-run=client -f`; the analyser silently skips manifests where the resolver can't find the pod-spec.                                |
| A whole namespace shows zero findings                                             | The namespace has no failing kube-bench / Polaris records AND no manifests with the 10 rule triggers.                     | Genuinely clean. Confirm by greping the source feeds for the namespace string.                                                                                                   |
| `kube-bench` JSON has `Controls: null`                                            | Run was empty (no target sections matched the cluster role).                                                              | Re-run with `--targets master,etcd,policies` on a control-plane node; `--targets node` from worker nodes. The reader is forgiving on null tests but the run won't emit findings. |
| All Polaris findings have `namespace: default`                                    | Polaris-export shape varies; some versions emit per-workload namespace, others bury it under `PodResult`.                 | Verify your Polaris version emits `namespace` at the workload level; if not, the reader defaults to `default`. Upgrade to Polaris 8.x+ for the canonical shape.                  |

---

## 9. Production deployment notes

- **AWS / Azure / GCP coverage** lives in F.3 cloud-posture + D.5 multi-cloud-posture. F.3 + D.5 + D.6 together cover the four most-deployed surfaces (~95% of customer footprint at the cloud-control layer).
- **Live cluster API paths** (`kubernetes-client` + Helm release inventory + admission-webhook posture) land in Phase 1c behind the same reader signatures — operators won't need to change CLI usage when the live path ships.
- **kube-bench RBAC requirement**: cluster-admin (or equivalent) to read the control-plane manifests; worker-node scans need on-node SSH/exec access.
- **Polaris kubeconfig requirement**: any read-only context (verbs `get,list` on every workload kind in scope).
- **Helm chart inventory**: NOT in v0.1. Pre-render with `helm template` and feed via `--manifest-dir`. Phase 1c adds native `read_helm_releases`.
- **The 10-rule v0.1 manifest set** covers the highest-impact posture issues. Deeper rule sets (e.g. PodSecurityPolicy / PodSecurityAdmission compliance, NetworkPolicy gaps, ServiceMesh sidecar checks) land in Phase 1c+.

---

## Cross-references

- D.6 plan: [`docs/superpowers/plans/2026-05-13-d-6-kubernetes-posture.md`](../../../../docs/superpowers/plans/2026-05-13-d-6-kubernetes-posture.md)
- F.3 cloud-posture (AWS reference): [`packages/agents/cloud-posture/`](../../cloud-posture/)
- D.5 multi-cloud-posture (Azure + GCP): [`packages/agents/multi-cloud-posture/`](../../multi-cloud-posture/)
- D.7 Investigation consumer: [`packages/agents/investigation/runbooks/investigation_workflow.md`](../../investigation/runbooks/investigation_workflow.md)
- F.6 Audit query: [`packages/agents/audit/runbooks/audit_query_operator.md`](../../audit/runbooks/audit_query_operator.md)
- ADR-007 (reference NLAH, D.6 is the 9th agent): [`docs/_meta/decisions/ADR-007-cloud-posture-as-reference-agent.md`](../../../../docs/_meta/decisions/ADR-007-cloud-posture-as-reference-agent.md)
