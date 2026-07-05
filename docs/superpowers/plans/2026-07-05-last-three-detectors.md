# Last Three Detectors → 22/22 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Light the final 3 gated attack-path detectors (`find_rbac_privilege_escalation`, `find_k8s_escape_to_cloud_data`, `find_internet_exposed_host_vulnerable`) in the `scan_run` pipeline against offline feeds → 22/22 LIVE.

**Architecture:** Two independent parts. **Part A** wires the k8s `record_inventory` writer (which already emits `BINDS`/`is_admin`/`IRSA_MAPPING`) into `scan_run`'s offline path via an injectable `ClusterReader` seam, and surfaces the real `serviceAccountName` so the IRSA join is genuine. **Part B** adds scan-target-ARN attribution to the vuln host-scan so its CVEs land on the same EC2 node cloud-posture marked `is_public`.

**Tech Stack:** Python 3.12, asyncio, `charter.memory` (SemanticStore), `fleet_testkit` (canned readers), pytest. Env: `uv run` (run `uv sync --all-packages --all-extras` first so mypy/tests match CI — the local `.venv` omits per-package deps).

## Global Constraints

- Offline-only: feeds/fixtures/injectable readers; live cluster/cloud stays `NEXUS_LIVE_*`-gated. No task points at live infra.
- Feeder failure degrades coverage, never aborts (`scan_run` try/except → `FeederOutcome`); a `None` source skips its feeder (existing tests stay green).
- `record_inventory` has NO live dependency — only its current caller is gated. Do NOT add a live call; wire it into the OFFLINE path.
- Join keys are load-bearing — fixtures must make them genuinely line up (green-for-the-right-reason, not tautologies): k8s_escape needs **SA name** (pod↔inventory) + **role ARN** (IRSA↔identity); host_vulnerable needs **instance ARN**.
- Husky clean (NEVER `--no-verify`); commit subjects lowercase ≤100 chars, body lines ≤100; ruff + whole-repo mypy pass (verify with `uv run mypy`).
- Image-scan path (`record_scan_results` keyed on Trivy `ArtifactName`) must stay UNCHANGED — ARN attribution applies only to host-scans with a `target_arn`.

---

## File Structure

- **Modify** `packages/runtime/src/nexus_runtime/scan_pipeline.py` — `ScanSources` fields (`k8s_cluster_reader`, `vuln_host_target`, `vuln_host_target_arn`) + k8s/vuln feeder wiring.
- **Modify** `packages/agents/k8s-posture/src/k8s_posture/agent.py` — offline `record_inventory` (A1); real `serviceAccountName` (A2).
- **Modify** `packages/agents/k8s-posture/src/k8s_posture/tools/manifests.py` — surface `serviceAccountName` on the privileged finding (A2).
- **Modify** `packages/agents/vulnerability/src/vulnerability/agent.py` + `.../kg_writer.py` — host-scan `target_arn` attribution (B1).
- **Modify** `docs/strategy/operating-path-detector-coverage.md` — 22/22 (Task 4).
- **Test** `packages/runtime/tests/integration/test_scan_pipeline_e2e.py` — 3 new e2e (one per detector); plus agent unit tests.

---

## Task 1 (A1): k8s ClusterInventory seam → `find_rbac_privilege_escalation`

**Files:**

- Modify: `packages/agents/k8s-posture/src/k8s_posture/agent.py` (`run()` + the `if semantic_store is not None:` offline block, ~:219-221)
- Modify: `packages/runtime/src/nexus_runtime/scan_pipeline.py` (`ScanSources` + k8s feeder)
- Test: `packages/runtime/tests/integration/test_scan_pipeline_e2e.py` (add), `packages/agents/k8s-posture/tests/` (add offline-inventory unit test)

**Interfaces:**

- Consumes: `record_inventory(inventory: ClusterInventory)` (`k8s_posture/kg_writer.py:55`); `inventory_from_reader(reader, cluster_id)` (`k8s_posture/tools/cluster_inventory.py:89`) over the `ClusterReader` protocol (`:62-68`); the canned reader shape in `fleet_testkit/k8s_workloads.py` (`cluster_admin_rbac_reader` `:111`, `drive_cluster_inventory` `:126`).
- Produces: k8s `run()` accepts `cluster_reader: <ClusterReader> | None = None`; offline path calls `record_inventory(inventory_from_reader(cluster_reader, cluster_id=<C>))`. `ScanSources.k8s_cluster_reader: object | None = None`.

**Read first:** `agent.py:195-221` (offline vs live k8s path), `cluster_inventory.py:50-101`, `fleet_testkit/k8s_workloads.py:67-131`, and `find_rbac_privilege_escalation` (`kg_query.py:858-886`) + its `path_type` in `attack_paths.py` (grep `rbac_privilege_escalation`).

- [ ] **Step 1: Write the failing e2e** (`test_scan_pipeline_e2e.py`)

```python
@pytest.mark.asyncio
async def test_scan_run_rbac_privilege_escalation_fires(tmp_path, session_factory) -> None:
    """A wildcard-admin ClusterRole bound to a service account → find_rbac_privilege_escalation."""
    from fleet_testkit.k8s_workloads import cluster_admin_rbac_reader  # canned admin RBAC
    reader = cluster_admin_rbac_reader(namespace="prod", sa_name="deployer", cluster_id="offline")
    sources = ScanSources(k8s_cluster_reader=reader)
    res = await scan_run(session_factory=session_factory, tenant="t-rbac",
                         sources=sources, workspace_root=tmp_path / "ws")
    assert all(f.ok for f in res.feeders), [f for f in res.feeders if not f.ok]
    assert any(p.path_type == "rbac_privilege_escalation" for p in res.confirmed), \
        [p.path_type for p in res.confirmed]
```

(Confirm `cluster_admin_rbac_reader`'s real signature/params + the exact `path_type` string — adjust to match. If the canned reader needs different args, read `k8s_workloads.py:111`.)

- [ ] **Step 2: Run → FAIL** — `uv run pytest packages/runtime/tests/integration/test_scan_pipeline_e2e.py::test_scan_run_rbac_privilege_escalation_fires -v` → the k8s feeder ignores the reader; no `rbac_privilege_escalation` path.

- [ ] **Step 3: Implement.** (a) k8s `run()`: add `cluster_reader` param; in the `if semantic_store is not None:` offline block, if `cluster_reader is not None`, `await kg.record_inventory(inventory_from_reader(cluster_reader, cluster_id=<the same offline cluster_id used by record_privileged_workloads, agent.py:201>))`. (b) `scan_pipeline.py`: add `k8s_cluster_reader: object | None = None` to `ScanSources`; in the k8s feeder, pass `cluster_reader=sources.k8s_cluster_reader` and include it in the feeder's `needed` predicate.

- [ ] **Step 4: Run → PASS** (both the e2e and a small k8s unit test that `record_inventory` is called offline when a reader is passed to `run()`). Then `uv run pytest packages/agents/k8s-posture -q` + `uv run pytest packages/runtime -q`.

- [ ] **Step 5: Commit** — `git commit -am "feat(k8s): wire record_inventory offline via ClusterReader seam → rbac_privilege_escalation"`

---

## Task 2 (A2): real `serviceAccountName` → `find_k8s_escape_to_cloud_data`

**Files:**

- Modify: `packages/agents/k8s-posture/src/k8s_posture/tools/manifests.py` (surface `serviceAccountName`)
- Modify: `packages/agents/k8s-posture/src/k8s_posture/agent.py` (`_privileged_from_manifest_findings` ~:336-372 → use real SA name)
- Test: `test_scan_pipeline_e2e.py` (add), k8s unit test

**Interfaces:**

- Consumes: `record_privileged_workloads` (`kg_writer.py:137`); `_resolve_pod_spec` (`manifests.py:223-252`) which has the pod spec (incl. `serviceAccountName`); Task 1's `record_inventory` seam; the identity feeder's `IDENTITY`-by-role-ARN node + `HAS_ACCESS_TO`; data-security `EXPOSES_DATA`.
- Produces: privileged pods whose `USES_SERVICE_ACCOUNT` edge points to the pod's REAL SA name (not hardcoded `"default"`).

**Read first:** `agent.py:336-372` (privileged derivation, the `ponytail` note at :362-363 about `serviceAccountName` on pod_spec), `manifests.py:223-252` (`_resolve_pod_spec`), `find_k8s_escape_to_cloud_data` (`kg_query.py:1072-1114`) + its `path_type` (grep `k8s_escape_to_cloud_data`), `kg_writer.py:92-98` (IRSA edge on the SA key).

- [ ] **Step 1: Write the failing e2e** — a privileged pod manifest with `spec.serviceAccountName: "irsa-sa"`; a `k8s_cluster_reader` inventory whose SA `irsa-sa` carries `eks.amazonaws.com/role-arn: arn:aws:iam::…:role/pod-role`; an identity listing granting that role `HAS_ACCESS_TO` a resource that data-security marked `EXPOSES_DATA`. Assert `path_type == "k8s_escape_to_cloud_data"` in `res.confirmed`. (The SA name in the pod must equal the SA name in the inventory; the role ARN must equal identity's.)

- [ ] **Step 2: Run → FAIL** — the privileged pod's SA is hardcoded `"default"`, so `USES_SERVICE_ACCOUNT` points to a different SA than the IRSA-annotated one → no join.

- [ ] **Step 3: Implement.** In `manifests.py`, surface the pod's `serviceAccountName` (from `_resolve_pod_spec`'s pod spec; default `"default"` only when absent) onto the privileged finding (e.g. into `unmapped["service_account"]`, matching how `image` was surfaced in the prior cycle). In `_privileged_from_manifest_findings` (`agent.py`), read that real SA name into the `PrivilegedWorkload.service_account` instead of the hardcoded `"default"`.

- [ ] **Step 4: Run → PASS** (the e2e + a unit test asserting a pod with `serviceAccountName: X` yields `USES_SERVICE_ACCOUNT` → SA `X`, not `default`). Then `uv run pytest packages/agents/k8s-posture -q` + `uv run pytest packages/runtime -q`.

- [ ] **Step 5: Commit** — `git commit -am "feat(k8s): surface real serviceAccountName so IRSA join fires k8s_escape_to_cloud_data"`

---

## Task 3 (B1): host-scan ARN attribution → `find_internet_exposed_host_vulnerable`

**Files:**

- Modify: `packages/agents/vulnerability/src/vulnerability/agent.py` (host-scan path ~:228-236) + `.../kg_writer.py` (`record_scan_results` ~:39-77, host-scan node key)
- Modify: `packages/runtime/src/nexus_runtime/scan_pipeline.py` (`ScanSources` + vuln feeder)
- Test: `test_scan_pipeline_e2e.py` (add), vulnerability unit test

**Interfaces:**

- Consumes: cloud-posture `record_ec2_workloads` writes `CLOUD_RESOURCE{instance_arn, is_public}` (already fed via `ScanSources.cloud_ec2_workloads`); vuln host-scan (`agent.py:228-236`, `trivy_host_scan`); `find_internet_exposed_host_vulnerable` (`kg_query.py:828-856`, single-hop: one `CLOUD_RESOURCE{is_public}` with an outgoing `VULNERABLE_TO`).
- Produces: `ScanSources.vuln_host_target: object | None = None` (host-scan feed/target) + `vuln_host_target_arn: str | None = None`; vuln `run()` host-scan path keys its `VULNERABLE_TO` node on `target_arn` when provided.

**Read first:** `agent.py:228-260` (host-scan branch), `kg_writer.py:39-77` (`record_scan_results` node-key derivation, `raw._artifact_name or _target`), `find_internet_exposed_host_vulnerable` + its `path_type` (grep `internet_exposed_host_vulnerable`), `aws_ec2.py:26-43` (`Ec2Workload.instance_arn`).

- [ ] **Step 1: Write the failing e2e** — `cloud_ec2_workloads=(Ec2Workload(instance_arn="arn:aws:ec2:us-east-1:111122223333:instance/i-abc", is_public=True, …),)` + a host-scan source attributed to the SAME ARN (`vuln_host_target=<fixture trivy host result>`, `vuln_host_target_arn="arn:aws:ec2:…:instance/i-abc"`). Assert `path_type == "internet_exposed_host_vulnerable"` in `res.confirmed`.

- [ ] **Step 2: Run → FAIL** — `ScanSources` has no host-target field; the vuln feeder only passes `image_refs`; the CVE (if any) keys on the Trivy target, not the instance ARN → no join with the public EC2 node.

- [ ] **Step 3: Implement.** (a) vuln `run()`: accept `host_target` + `host_target_arn`; in the host-scan write path, when `host_target_arn` is set, key the `VULNERABLE_TO` `CLOUD_RESOURCE` node on `host_target_arn` (thread it into `record_scan_results` as an explicit resource-ARN override, or write a host-scan variant that keys on the ARN). Leave the image-scan path (keyed on `ArtifactName`) UNCHANGED. (b) `scan_pipeline.py`: add `vuln_host_target`/`vuln_host_target_arn` to `ScanSources`; extend the vuln feeder's `needed` predicate + `run()` call to pass them.

- [ ] **Step 4: Run → PASS** (the e2e + a vuln unit test asserting a host-scan with `host_target_arn=A` writes `VULNERABLE_TO` on node `A`, while an image scan is unaffected). Then `uv run pytest packages/agents/vulnerability -q` + `uv run pytest packages/runtime -q`.

- [ ] **Step 5: Commit** — `git commit -am "feat(vulnerability): host-scan target-arn attribution → internet_exposed_host_vulnerable"`

---

## Task 4: honest coverage close → 22/22

**Files:**

- Modify: `docs/strategy/operating-path-detector-coverage.md`

- [ ] **Step 1: Move all 3 rows** (`find_rbac_privilege_escalation`, `find_k8s_escape_to_cloud_data`, `find_internet_exposed_host_vulnerable`) from live-cloud-gated to **LIVE-in-pipeline**, documenting the feeder legs (k8s `record_inventory` for BINDS/is_admin/IRSA; `record_privileged_workloads` with real SA; vuln host-scan ARN attribution; cloud-posture `is_public`).

- [ ] **Step 2: Update the Bottom Line.** If #799 (`find_kms_key_access`) has landed on main by now, the count is **22 LIVE-in-pipeline / 0 live-cloud-gated / 0 BLOCKED** (verify 22+0=22, no stale gated rows). If #799 is NOT yet merged, this branch is off an 18/22 base → the honest count here is **21 LIVE / 1 gated (`find_kms_key_access`, pending in #799) / 0 BLOCKED**; note that #799 lifts it to 22. State whichever is true at close (check `git log origin/main` for #799's squash).

- [ ] **Step 3: Cross-check** — grep each of the 3 detectors' required edge types against the writers now feeding them; no row marked LIVE without every leg written by a feeder. Remove the old blocker notes for the 3.

- [ ] **Step 4: Commit** — `git commit -am "docs(operating-path): last 3 detectors live — coverage 22/22"`

---

## Self-Review

**Spec coverage:** A1 keystone → T1 (rbac_privesc); A2 SA-surfacing → T2 (k8s_escape); B1 ARN-attribution → T3 (host_vulnerable); coverage close → T4. Every spec section maps. ✓

**Placeholder scan:** the bigger tasks (T1/T2/T3) instruct reading the exact seam before writing — deliberate (exact SA/reader/path_type names must be read at the seam, file:lines given). Test code is concrete. No hand-waves. ✓

**Type consistency:** `ScanSources` fields (`k8s_cluster_reader`, `vuln_host_target`, `vuln_host_target_arn`) consistent T1/T3; `cluster_reader` param on k8s `run()` (T1) reused by T2's e2e; `path_type` strings to be grep-confirmed (flagged in each task). ✓

**Known seams the implementer resolves (flagged, not hidden):** exact `cluster_admin_rbac_reader` signature (T1), how `serviceAccountName` is surfaced onto the finding (T2 — mirror the prior `image`→`unmapped` pattern), the cleanest `record_scan_results` ARN-override mechanism (T3), and the #799-dependent count (T4).
