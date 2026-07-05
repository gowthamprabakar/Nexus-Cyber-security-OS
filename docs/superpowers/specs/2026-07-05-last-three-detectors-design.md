# Last Three Detectors → 22/22 — Design

**Date:** 2026-07-05
**Branch:** `feat/last-three-detectors`
**Status:** approved (operator: all 3; #1 join = scan-target-ARN attribution)

## Goal

Light the final three live-cloud-gated attack-path detectors so all 22 fire in the `scan_run` pipeline against offline feeds: `find_rbac_privilege_escalation`, `find_k8s_escape_to_cloud_data`, `find_internet_exposed_host_vulnerable`.

## Background (from deep-scope)

- **The two k8s detectors share ONE keystone.** `find_rbac_privilege_escalation` needs `service-account` + `BINDS` → `is_admin` role; `find_k8s_escape_to_cloud_data` needs `privileged` pod + `USES_SERVICE_ACCOUNT` + `IRSA_MAPPING` → cloud `IDENTITY` + `HAS_ACCESS_TO` + `EXPOSES_DATA`. Every missing leg (`BINDS`, `is_admin`, `IRSA_MAPPING`) is **already written by `record_inventory`** (`k8s_posture/kg_writer.py:55`) from a plain `ClusterInventory`. It has **no live dependency** — only its _caller_ does (`agent.py:203-211`, gated `if kubeconfig is not None or in_cluster:`). The offline path (`agent.py:219-221`) calls only `record_privileged_workloads`. A proven offline builder exists: `inventory_from_reader(reader, cluster_id=...)` (`cluster_inventory.py:89`) over a `ClusterReader` protocol, exercised by `fleet_testkit/k8s_workloads.py::drive_cluster_inventory` (`:126`) with zero cluster. `_parse_service_account` already reads the `eks.amazonaws.com/role-arn` IRSA annotation into `K8sServiceAccount.role_arn` (`cluster_inventory.py:76-86`). So the keystone is: hand the k8s feeder a `ClusterInventory` (or reader) and call `record_inventory` offline.
- **`find_internet_exposed_host_vulnerable` needs a join fix, not a toggle.** `is_public` is written on the EC2 node keyed by **instance ARN** (`cloud_posture/tools/kg_writer.py:224`, `record_ec2_workloads`). The vuln host-scan writes `VULNERABLE_TO` keyed on Trivy's `ArtifactName`/`Target` (a rootfs path / VM ref) — `record_scan_results` (`vulnerability/kg_writer.py:39-77`). The two nodes never converge, and no resolver reconciles them (the intended decoration in `correlation.py:39-41` was never implemented). No live infra is required, but the CVE must be **attributed to the instance ARN** so it lands on the same node.

## The honest ceiling

All three are wireable offline (feeds/fixtures, no live cloud). No true blockers. `scan_run` proves them against injected inventory + workloads + a host-scan attribution; pointing at a live cluster/account stays `NEXUS_LIVE_*`-gated operator work (unchanged). This cycle takes pipeline coverage to **22/22 LIVE-in-pipeline / 0 gated / 0 blocked** (assuming #799 `find_kms_key_access` has landed; if not, 21/22 with `find_kms_key_access` in #799 — reconciled in the coverage doc at close).

## Architecture

Two independent parts.

### Part A — k8s inventory keystone (lights `find_rbac_privilege_escalation` + `find_k8s_escape_to_cloud_data`)

**A1. Injectable ClusterInventory seam in `scan_run`.** Mirror every other agent's offline seam: add `k8s_cluster_reader: object | None = None` (a `ClusterReader`) — or a pre-built `ClusterInventory` — to `ScanSources`. In the k8s-posture feeder (`scan_pipeline.py`), when provided, build the inventory via `inventory_from_reader(reader, cluster_id=<C>)` and pass it to the agent so `run()` calls `record_inventory(inventory)` in the offline path (under `if semantic_store is not None:`). Reuse the proven `fleet_testkit` canned-reader shape for fixtures.

- **`cluster_id` must match** between `record_privileged_workloads` (offline uses `_cluster_context or "offline"`, `agent.py:201`) and the inventory, or the SA nodes won't share keys. Thread a single `cluster_id` through both offline writers.

**A2. Surface the real `serviceAccountName` (so #2's IRSA join is genuine, not a `"default"` fixture hack).** `record_privileged_workloads` hardcodes `service_account="default"` (`agent.py:364-371`) because `_privileged_from_manifest_findings` (`agent.py:336-372`) reads per-container findings, not `pod_spec`. Thread the pod's `serviceAccountName` (from `pod_spec`) through so the privileged pod's `USES_SERVICE_ACCOUNT` points to the SA that carries the IRSA annotation. The join for `find_k8s_escape_to_cloud_data`: privileged pod → SA(name=X) → `IRSA_MAPPING` → `IDENTITY`(role ARN) → `HAS_ACCESS_TO` → resource → `EXPOSES_DATA`. The SA name (X) must match between `record_privileged_workloads` and the inventory's IRSA SA; the role ARN must match the identity feeder's `IDENTITY` node.

### Part B — host-vuln scan-target-ARN attribution (lights `find_internet_exposed_host_vulnerable`)

**B1. Attribute host-scan CVEs to a resource ARN.** Add `vuln_host_target` + `vuln_host_target_arn` (attribution) to `ScanSources`; thread to the vulnerability feeder → `vulnerability_run(host_target=…, host_target_arn=…)`. In the host-scan write path, key the `VULNERABLE_TO` node on the provided **resource ARN** (the instance being scanned) rather than Trivy's target string — so the CVE lands on the same `CLOUD_RESOURCE{instance_arn}` node cloud-posture marked `is_public`. `find_internet_exposed_host_vulnerable` (`kg_query.py:828-856`) is single-hop: one `CLOUD_RESOURCE{is_public}` carrying an outgoing `VULNERABLE_TO`.

- The image-scan path (`record_scan_results` keyed on `ArtifactName`) is UNCHANGED — the ARN attribution applies only when a host-scan `target_arn` is supplied.

## Components

- `packages/runtime/src/nexus_runtime/scan_pipeline.py` — `ScanSources` fields (`k8s_cluster_reader`, `vuln_host_target`, `vuln_host_target_arn`) + k8s and vulnerability feeder wiring.
- `packages/agents/k8s-posture/src/k8s_posture/agent.py` — offline `record_inventory` call (A1); `serviceAccountName` surfacing (A2).
- `packages/agents/k8s-posture/src/k8s_posture/tools/manifests.py` — surface `pod_spec.serviceAccountName` in the privileged finding (A2) if not already available.
- `packages/agents/vulnerability/src/vulnerability/agent.py` + `kg_writer.py` — host-scan `target_arn` attribution (B1).
- `docs/strategy/operating-path-detector-coverage.md` — move the 3 rows to LIVE; update counts to 22/22 (reconciled against #799).

## Data flow / join keys (the load-bearing part)

- **rbac_privesc:** inventory (RBAC manifests/canned) → `record_inventory` → `service-account` + `BINDS` + `is_admin` role, all in one cluster subgraph. No cross-agent join. Fires.
- **k8s_escape:** privileged pod (from manifests, real `serviceAccountName=X`) `USES_SERVICE_ACCOUNT` SA(X); inventory SA(X) carries `role_arn` → `IRSA_MAPPING` → `IDENTITY`(role_arn); identity feeder wrote `HAS_ACCESS_TO` from `IDENTITY`(role_arn) → resource; data-security wrote `EXPOSES_DATA`. Join keys: **SA name X** (pod ↔ inventory) and **role ARN** (IRSA ↔ identity). Both fixture-controlled.
- **host_vulnerable:** cloud-posture `Ec2Workload(instance_arn=A, is_public=True)`; vuln host-scan attributed to `target_arn=A` → `VULNERABLE_TO` on node A. Join key: **instance ARN A**.

## Error handling

Feeder-failure semantics unchanged (try/except → degrades coverage, never aborts). A missing inventory/host-scan source simply skips that feeder (existing tests stay green).

## Testing

- Per-detector e2e in `packages/runtime/tests/integration/test_scan_pipeline_e2e.py`: each asserts the specific `path_type` (`rbac_privilege_escalation`, `k8s_escape_to_cloud_data`, `internet_exposed_host_vulnerable` — grep exact strings) appears in `res.confirmed` from real feeders, green-for-the-right-reason (join keys genuinely line up, not tautologies).
- Unit tests for A2 (`serviceAccountName` surfaced) and B1 (host-scan keyed on the ARN).
- `uv run mypy` + `uv run ruff check` + `uv run pytest packages/runtime -q` + the touched agents' suites clean (env synced — `uv sync --all-packages --all-extras`).

## Build sequence (ranked by effort)

1. **A1 keystone** — inventory seam + offline `record_inventory` → `find_rbac_privilege_escalation` fires (S).
2. **A2** — `serviceAccountName` surfacing + IRSA join → `find_k8s_escape_to_cloud_data` fires (S–M).
3. **B1** — host-scan ARN attribution → `find_internet_exposed_host_vulnerable` fires (M).
4. **Close** — coverage table → 22/22 (reconcile #799) + whole-branch review.

## Out of scope

- Live cluster / live cloud emission (stays `NEXUS_LIVE_*`-gated).
- A full manifest-dir RBAC parser (the injectable-reader seam is sufficient for the pipeline proof; a manifest-dir parser that emits the five RBAC/SA kinds is a reasonable later enhancement, not required here).
- Multi-cloud (Azure/GCP) equivalents.
