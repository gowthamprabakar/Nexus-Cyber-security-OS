# D.6 v0.3 — In-cluster ServiceAccount mode

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Pause for review after each numbered task.

**Goal:** Add `config.load_incluster_config()` fallback to `read_cluster_workloads` so the agent can run as a **Pod inside the cluster** with a mounted ServiceAccount token, no kubeconfig required. Removes the last v0.2 operator friction. v0.1 + v0.2 paths preserved unchanged.

**Scope:** Reader-level addition + CLI/driver plumbing + RBAC documentation. No new agent surface; no OCSF wire-shape changes; no new analyser rules. **Smallest D.6 slice yet** (4 tasks; ~2 weeks at our cadence).

**Strategic role.** Closes the v0.2 deferral (per [D.6 v0.2 verification record §"Carried-forward risks" item 12](../../_meta/d6-v0-2-verification-2026-05-16.md)). With v0.3 closed, D.6 supports **all three deployment modes** an operator might choose: offline filesystem (v0.1), live cluster via explicit kubeconfig (v0.2), live cluster as a Pod (v0.3). The natural deployment for production is v0.3 — operators run the agent as a CronJob / Deployment with a read-only ServiceAccount; no external kubeconfig to manage.

---

## Resolved questions

| #   | Question                                                          | Resolution                                                                                                                                                                                                                                                                                                                                                                                                          | Task   |
| --- | ----------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ |
| Q1  | Explicit `in_cluster=True` arg or auto-detect?                    | **Explicit opt-in via `in_cluster: bool = False`.** Auto-detection (e.g. probing `/var/run/secrets/kubernetes.io/serviceaccount/token`) is fragile (a developer running locally with the token volume mounted via `kubectl debug` would silently switch modes). Explicit-only matches v0.2's Q4 discipline — the audit trail must be deterministic.                                                                 | Task 1 |
| Q2  | Mutual exclusion with `kubeconfig`?                               | **Yes — `kubeconfig` XOR `in_cluster=True`.** Same Q6 reasoning as v0.2: a single workload source per run. If both are set → `ClusterReaderError` immediately (before config-loader runs).                                                                                                                                                                                                                          | Task 1 |
| Q3  | Should the reader probe whether it's actually running in-cluster? | **No.** The `kubernetes` SDK's `config.load_incluster_config()` raises `ConfigException` when called outside a cluster (missing `KUBERNETES_SERVICE_HOST` / `KUBERNETES_SERVICE_PORT` env vars OR missing CA cert / token files). The reader catches that and re-raises as `ClusterReaderError` — same pattern as the v0.2 kubeconfig-load-failure branch. Operators get a clear error rather than silent fallback. | Task 2 |
| Q4  | CLI flag name?                                                    | **`--in-cluster` (boolean flag).** Mirrors `kubectl --in-cluster` convention. Mutually exclusive with `--kubeconfig` (Click's `cls=GroupOption` or explicit gate in `run_cmd`; we'll match the v0.2 pattern of explicit gates raising `click.UsageError`).                                                                                                                                                          | Task 3 |
| Q5  | RBAC requirements documented?                                     | **Yes — same ClusterRole as v0.2 (`nexus-k8s-posture-reader`)** plus a documented **ServiceAccount + ClusterRoleBinding** Helm-snippet that operators can apply. The runbook adds a v0.3 deployment example showing the Pod manifest with the SA wired in.                                                                                                                                                          | Task 4 |

---

## Architecture

The pipeline shape is **unchanged from v0.2**. Only the config-loader inside `_read_sync` branches:

```
                 ┌─────────────────────────────────────────────────┐
                 │ _read_sync(kubeconfig=?, in_cluster=?, ns=?)    │
                 │                                                 │
                 │   if in_cluster:                                │
                 │       config.load_incluster_config()  ← NEW v0.3│
                 │   elif kubeconfig:                              │
                 │       config.load_kube_config(...)    ← v0.2    │
                 │   else:                                         │
                 │       raise ClusterReaderError(...)             │
                 │                                                 │
                 │   (rest of pipeline identical to v0.2)          │
                 └─────────────────────────────────────────────────┘
```

Only ~10 LOC change in `tools/cluster_workloads.py`. Everything downstream (the 7-workload-kind walk, the K8s-API-JSON serialisation, the `_analyse_manifest` reuse, the sentinel `cluster:///` path rewrite) is **unchanged**.

---

## Execution status

| Task | Status  | Commit    | Notes                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| ---- | ------- | --------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1    | ✅ done | `9477c3f` | `read_cluster_workloads` signature: `kubeconfig` becomes Optional + new `in_cluster: bool = False` param. `_read_sync` branches via `if in_cluster → load_incluster_config` / `elif kubeconfig → load_kube_config`. Q2 mutual exclusion + no-source-error gates run before either loader. ConfigException → `ClusterReaderError` re-raise (Q3). 8 reader tests cover: smoke (load_incluster_config importable), happy path, finding-shape equality with v0.2, ConfigException re-raise, mutual exclusion, no-source error, v0.2 path preserved, namespace scope in in-cluster mode. v0.2 reader's 17 tests still 100% green. |
| 2    | ✅ done | `7f1356a` | `agent.run` gains `in_cluster: bool = False`. `_ingest` routes via `read_cluster_workloads(in_cluster=True, ...)` when set. Workload-source mutual exclusion now spans all three sources (manifest_dir / kubeconfig / in_cluster); ValueError on >1 set. 9 driver tests; v0.1 + v0.2 driver tests stay 100% green.                                                                                                                                                                                                                                                                                                           |
| 3    | ✅ done | `7f1356a` | CLI `--in-cluster` boolean flag. 3-way mutual exclusion via click.UsageError. `--cluster-namespace` now accepts either `--kubeconfig` OR `--in-cluster`. 10 CLI tests; v0.1 + v0.2 CLI tests stay 100% green.                                                                                                                                                                                                                                                                                                                                                                                                                |
| 4    | ✅ done | _(this)_  | README v0.3 banner + triple-source workload bullet + quick-start 3c (in-cluster). Runbook section 1c.iii adds full Pod deployment (ServiceAccount + ClusterRole + ClusterRoleBinding + CronJob manifest); section 3 dual-invocation example becomes triple-invocation. Verification record `docs/_meta/d6-v0-3-verification-2026-05-16.md`. **D.6 v0.3 CLOSED 2026-05-16** (second Phase-1c slice for D.6; all three deployment modes operator-ready).                                                                                                                                                                       |

ADR references: [ADR-005 async-tool-wrapper convention](../../_meta/decisions/ADR-005-async-tool-wrapper-convention.md) · [ADR-007 cloud-posture as reference](../../_meta/decisions/ADR-007-cloud-posture-as-reference-agent.md).

---

## Compatibility contract

- **OCSF wire shape unchanged.** Same `class_uid 2003` + `K8sFindingType.MANIFEST`. Downstream consumers (D.7 / fabric / Meta-Harness) require zero changes.
- **v0.1 + v0.2 paths preserved.** Existing `--manifest-dir` (v0.1) and `--kubeconfig` (v0.2) callers continue to work bit-for-bit.
- **Sentinel manifest_path** continues to be `cluster:///<ns>/<kind>/<name>` regardless of whether the cluster was reached via kubeconfig or in-cluster.

---

## Defers (Phase 1c+ — separate plans)

Unchanged from v0.2's defer list:

- **RBAC overpermissive analyser (D.6 v0.4)** — Role / ClusterRole / RoleBinding / ClusterRoleBinding ingest + the 6-pattern overpermissive table.
- **Admission webhook posture (D.6 v0.5)** — MutatingWebhookConfiguration + ValidatingWebhookConfiguration validation.
- **Helm release inventory (D.6 v0.6)** — `read_helm_releases` via the Helm SDK.
- **OPA / Gatekeeper (D.6 v0.7)** — constraint templates + violations.
- **Pod Security Standards (D.6 v0.8)** — PSA API enforcement check.
- **NetworkPolicy graph (D.6 v0.9)** — depends on F.5 SemanticStore graph queries.

---

## Reference template

**D.6 v0.2** (`2026-05-16-d-6-v0-2-live-cluster-api.md`) — same version-extension pattern; only the config-loader branch changes.

— recorded 2026-05-16
