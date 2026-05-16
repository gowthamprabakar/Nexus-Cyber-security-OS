# D.6 v0.2 — Live cluster API ingest

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Pause for review after each numbered task.

**Goal:** Extend the **Kubernetes Posture Agent** (`packages/agents/k8s-posture/`) from offline filesystem snapshots → **live cluster API ingest** via the `kubernetes` Python SDK. v0.2 keeps the OCSF v1.3 Compliance Finding wire shape (`class_uid 2003`) identical to v0.1 — only the **source side** changes. Operators point at a kubeconfig and run; they no longer pre-stage JSON / YAML snapshots.

**Scope:** This v0.2 ships **live workload ingest only** (Pods / Deployments / StatefulSets / DaemonSets / ReplicaSets / Jobs / CronJobs). RBAC analysis, admission-webhook posture, Helm release inventory, OPA/Gatekeeper, Pod Security Standards, and NetworkPolicy graph analysis remain Phase 1c+ (each gets its own follow-on plan).

**Strategic role.** First D.6 Phase-1c slice. Removes the biggest v0.1 operator friction (pre-staging snapshots) without touching the wire-shape contract that downstream consumers (D.7 / fabric / Meta-Harness) already rely on. Mirrors F.3's LocalStack → live-AWS pattern and D.5's offline-→-live-SDK roadmap.

---

## Resolved questions

| #   | Question                                                | Resolution                                                                                                                                                                                                                                                                                                                     | Task   |
| --- | ------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------ |
| Q1  | New tool or extend existing `read_manifests`?           | **New tool `read_cluster_workloads`.** Keeps the file-based reader untouched (operators still want it for snapshots / CI scans). The new tool emits the **same `ManifestFinding` shape** so the existing `normalize_manifest` lifts it to OCSF 2003 with zero change.                                                          | Task 2 |
| Q2  | Sync vs async SDK?                                      | **Sync `kubernetes` SDK called via `asyncio.to_thread`** (matches ADR-005 + the v0.1 file-reader pattern). The async-native `kubernetes_asyncio` package is less stable; defer to a future ADR if needed.                                                                                                                      | Task 2 |
| Q3  | Namespace scope — cluster-wide or per-namespace?        | **Both, via optional `namespace` arg.** `None` → list across all namespaces (cluster-wide list APIs). String → list within that namespace only. Mirrors the kubernetes-client API surface; lets operators scope by blast radius.                                                                                               | Task 2 |
| Q4  | kubeconfig discovery — explicit path only, or fallback? | **Explicit `kubeconfig` path required.** No in-cluster fallback in v0.2 (deferred to v0.3 — needs ServiceAccount token mount conventions). Explicit-only also makes the audit trail deterministic.                                                                                                                             | Task 2 |
| Q5  | Live test mocking strategy?                             | **Mock the SDK at the import site.** Pattern matches the file-reader tests: monkeypatch the `client.CoreV1Api` / `client.AppsV1Api` / `client.BatchV1Api` factory functions. No envtest / kind-cluster dependency in v0.2 unit tests. Phase 1c may add an opt-in `kind`-based integration suite (gated by `NEXUS_LIVE_K8S=1`). | Task 3 |
| Q6  | Mutually exclusive with `--manifest-dir` or additive?   | **Mutually exclusive in v0.2** (`--kubeconfig` XOR `--manifest-dir`). Both pointing at the same workload would dedup correctly but doubles ingest cost; operators should pick a source per run. Phase 1c may relax this if cross-source validation is needed.                                                                  | Task 5 |

---

## Architecture

The pipeline shape is **unchanged** — v0.2 only swaps the manifest reader. INGEST stage gains a path-vs-cluster branch; everything downstream (NORMALIZE / SCORE / DEDUP / SUMMARIZE / HANDOFF) is identical to v0.1.

```
ExecutionContract (signed)
        │
        ▼
┌──────────────────────────────────────────────────────────────────┐
│ Kubernetes Posture Agent driver                                  │
│                                                                  │
│  Stage 1: INGEST     — 3 feeds concurrent via TaskGroup          │
│                        ├─ kube_bench: file feed (unchanged)      │
│                        ├─ polaris:    file feed (unchanged)      │
│                        └─ workloads:  EITHER manifest dir        │
│                                       OR live cluster API ⭐ NEW │
│  Stages 2-6                            (unchanged from v0.1)     │
└──────────────────────────────────────────────────────────────────┘
```

Only `tools/cluster_workloads.py` (new) and a small branch in `agent._ingest` (modified) change.

---

## Execution status

| Task | Status     | Commit    | Notes                                                                                                                                                                                                                                                                                                                                                       |
| ---- | ---------- | --------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1    | ✅ done    | `58ee0eb` | `kubernetes>=31.0.0` added to k8s-posture pyproject (resolved 35.0.0 in lock). 5 smoke tests covering SDK import / config loader / CoreV1Api / AppsV1Api / BatchV1Api / ApiException + v0.2 anti-marker (cluster_workloads module absent until Task 2). 2035 passed / 11 skipped repo-wide.                                                                 |
| 2    | ⬜ pending | —         | `read_cluster_workloads(*, kubeconfig, namespace=None)` — async wrapper over the sync `kubernetes` SDK; `asyncio.to_thread`; pulls Pods / Deployments / StatefulSets / DaemonSets / ReplicaSets / Jobs / CronJobs; converts each to the same dict shape the file analyser uses; returns `tuple[ManifestFinding, ...]` via the existing `_analyse_manifest`. |
| 3    | ⬜ pending | —         | Comprehensive reader tests with mocked SDK (per Q5). Covers: per-kind list calls, namespace-scoped vs cluster-wide, RBAC errors (`ApiException` 403 → custom `ClusterReaderError`), empty cluster, multi-namespace fan-out, init-containers walked.                                                                                                         |
| 4    | ⬜ pending | —         | Agent driver: `agent.run` gains `kubeconfig: Path \| str \| None` param; `_ingest` routes workloads through `read_cluster_workloads` when `kubeconfig` is set, else through `read_manifests` (existing). The `manifest_dir` param remains.                                                                                                                  |
| 5    | ⬜ pending | —         | CLI `--kubeconfig PATH` flag (mutually exclusive with `--manifest-dir` per Q6; Click `cls=MutuallyExclusiveOption`). Updates eval-runner fixture parser to support a `kubeconfig` key (synthesises a sentinel path).                                                                                                                                        |
| 6    | ⬜ pending | —         | README + runbook update (live-mode section, sample kubeconfig commands, RBAC requirements for the agent's read role); v0.2 verification record `docs/_meta/d6-v0-2-verification-<date>.md`.                                                                                                                                                                 |

ADR references: [ADR-005 async-tool-wrapper convention](../../_meta/decisions/ADR-005-async-tool-wrapper-convention.md) · [ADR-007 cloud-posture as reference](../../_meta/decisions/ADR-007-cloud-posture-as-reference-agent.md).

---

## Compatibility contract

- **OCSF wire shape unchanged.** Same `class_uid 2003`; same `K8sFindingType.MANIFEST` discriminator (`cspm_k8s_manifest`) when the workload findings come from live cluster ingest. Downstream consumers see no schema change.
- **`evidence.kind` unchanged** (`"manifest"`). The reader writes `manifest_path` = `cluster:///{namespace}/{kind}/{name}` (sentinel URL) when live-sourced, so the evidence is still self-describing and operators can tell at a glance which source produced the finding.
- **The file-based `read_manifests` reader stays.** Snapshot mode is still first-class for CI/CD scans against rendered YAML in PRs.
- **Severity mapping unchanged.** The 10-rule table is shared across both reader sources.

---

## Defers (Phase 1c+ — separate plans)

- **RBAC overpermissive analysis** — Role / ClusterRole / RoleBinding / ClusterRoleBinding ingest + the 6-pattern rule table (cluster-admin to non-system; wildcard verbs on `secrets`; etc.).
- **Admission webhook posture** — `MutatingWebhookConfiguration` / `ValidatingWebhookConfiguration` validation (cert health, failurePolicy: Ignore, timeoutSeconds).
- **Helm release inventory** — `read_helm_releases` using the Helm SDK against in-cluster releases.
- **OPA / Gatekeeper** — constraint templates + violations from the `gatekeeper.sh` API group.
- **Pod Security Standards** — restricted / baseline / privileged enforcement check via the PSA API.
- **NetworkPolicy graph analysis** — depends on F.5 SemanticStore graph queries.
- **In-cluster ServiceAccount mode** — fallback path when no kubeconfig is provided but the agent is running as a Pod with a mounted token (sets up `load_incluster_config()`).

---

## Reference template

**D.6 v0.1** (`2026-05-13-d-6-kubernetes-posture.md`) — keep the OCSF + dedup + summarizer surfaces unchanged; only the workload reader's source changes. **F.3 v0.2 LocalStack → live AWS** (when written) will mirror this exact pattern.

— recorded 2026-05-16
