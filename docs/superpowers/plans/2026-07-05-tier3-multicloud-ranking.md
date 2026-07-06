# Tier 3: Multi-Cloud Exposure + Expected-Loss Ranking Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** (A) make `find_exposed_kms_key` + `find_exposed_database` fire on Azure/GCP in the `scan_run` pipeline; (B) rank the pipeline's confirmed paths by real expected loss (blast × belief × KEV/EPSS) instead of flat `_SEVERITY`.

**Architecture:** Part A adds an injectable resource seam to multi-cloud-posture `run()` (mirroring cloud-posture's `ec2_workloads`) + a `scan_run` feeder, so the CI-proven portable writers actually run. Part B surfaces each named path's worst-CVE KEV/EPSS, extracts `build_report_card`'s expected-loss scoring into a reusable ranker, and applies it to `analyze`'s confirmed list.

**Tech Stack:** Python 3.12, asyncio, `charter.memory` SemanticStore, pytest. Env: run `uv sync --all-packages --all-extras` first, then `uv run pytest` / `uv run mypy` (matches CI; local `.venv` omits per-package deps).

## Global Constraints

- **No new collection.** Part A proves against INJECTED Azure/GCP resource records (offline); do NOT touch the dead multi-cloud CIS rule engine or the OCSF-finding path. Live emission stays `NEXUS_LIVE_*`-gated.
- **Honest ceiling.** Part A lights ONLY `find_exposed_kms_key` + `find_exposed_database` cross-cloud. Do NOT claim host-vuln / native Azure-MI-GCP-SA identity / cross-cloud-secrets — those are parked (Task 5 names them).
- **Part B is total + order-only.** The ranker must never drop a confirmed path; it changes order, not the set. Path with no sink → `sink_p = route_p`; unknown blast → 1 (documented fallbacks, not silent).
- `analyze`/`scan_run` keep returning `ScanResult.confirmed: list[AttackPath]` (CLI + scheduler read `.confirmed` — `scan.py:52`, `cli.py:539/551`). Enriching `AttackPath` with new fields is fine; changing the container type is not.
- Husky clean (NEVER `--no-verify`); commit subjects lowercase ≤100 chars; ruff + whole-repo mypy pass (`uv run mypy`).

---

## File Structure

- **Modify** `packages/agents/multi-cloud-posture/src/multi_cloud_posture/agent.py` — `run()` injectable resource seam (A1).
- **Modify** `packages/runtime/src/nexus_runtime/scan_pipeline.py` — `ScanSources` mc\_\* fields + multi-cloud feeder (A2).
- **Modify** `packages/agents/meta-harness/src/meta_harness/attack_paths.py` — `AttackPath.kev/epss` + `_Group` KEV/EPSS tracking (B1).
- **Modify** `packages/agents/meta-harness/src/meta_harness/report_card.py` — reusable expected-loss ranker; real kev/epss; broader blast (B2/B3).
- **Modify** `packages/agents/meta-harness/src/meta_harness/scan.py` — `analyze` applies the ranker to `confirmed` (B3).
- **Modify** `docs/strategy/operating-path-detector-coverage.md` — cross-cloud KMS/DB + parked residual (Task 5).
- **Test:** `packages/runtime/tests/integration/test_scan_pipeline_e2e.py`, multi-cloud-posture + meta-harness unit tests.

---

## Task 1 (A): multi-cloud-posture resource seam + `scan_run` feeder → cross-cloud KMS/DB

**Files:**

- Modify: `packages/agents/multi-cloud-posture/src/multi_cloud_posture/agent.py` (`run()` ~:119-166 + the `semantic_store is not None` path)
- Modify: `packages/runtime/src/nexus_runtime/scan_pipeline.py` (`ScanSources` + feeder)
- Test: `packages/runtime/tests/integration/test_scan_pipeline_e2e.py`, `packages/agents/multi-cloud-posture/tests/`

**Interfaces:**

- Consumes: `KnowledgeGraphWriter.record_kms_keys(Iterable[KmsKeyRecord])` / `record_sql_instances(Iterable[SqlInstanceRecord])` / `record_vm_instances(Iterable[VmInstanceRecord])` (`multi_cloud_posture/tools/kg_writer.py:131/159/173`); the record dataclasses at `:36/51/68`. `find_exposed_kms_key` (`kg_query.py:955`), `find_exposed_database` (`:966`).
- Produces: multi-cloud-posture `run()` accepts `mc_kms_keys` / `mc_sql_instances` / `mc_vm_instances` (Sequence | None). `ScanSources.mc_kms_keys` / `mc_sql_instances` / `mc_vm_instances`.

**Read first:** `cloud_posture/agent.py` (the `ec2_workloads`/`kms_keys` seam + `_write_topology_to_kg`) as the pattern to mirror; `multi_cloud_posture/agent.py:119-166` (run signature — note the reserved/`del`'d scope hints; add the new params alongside `semantic_store`); the `KmsKeyRecord`/`SqlInstanceRecord` fields (`is_public`, `data_type`, `engine`, canonical key).

- [ ] **Step 1: Write the failing e2e** (`test_scan_pipeline_e2e.py`)

```python
@pytest.mark.asyncio
async def test_scan_run_multicloud_exposed_kms_and_db_fire(tmp_path, session_factory) -> None:
    """Injected Azure KMS + GCP SQL (public) → find_exposed_kms_key + find_exposed_database."""
    from multi_cloud_posture.tools.kg_writer import KmsKeyRecord, SqlInstanceRecord
    # Build an Azure Key Vault key + a GCP Cloud SQL instance, both public.
    # (Read KmsKeyRecord/SqlInstanceRecord fields to fill exact args — canonical key, is_public, etc.)
    sources = ScanSources(
        mc_kms_keys=(KmsKeyRecord(...is_public=True...),),
        mc_sql_instances=(SqlInstanceRecord(...is_public=True...),),
    )
    res = await scan_run(session_factory=session_factory, tenant="t-mc",
                         sources=sources, workspace_root=tmp_path / "ws")
    assert all(f.ok for f in res.feeders), [f for f in res.feeders if not f.ok]
    types = {p.path_type for p in res.confirmed}
    assert "exposed_kms_key" in types, types
    assert "exposed_database" in types, types
```

(Grep the exact `path_type` strings + `KmsKeyRecord`/`SqlInstanceRecord` constructors before finalizing.)

- [ ] **Step 2: Run → FAIL** — `ScanSources` has no `mc_*`; multi-cloud-posture isn't a feeder; no cross-cloud nodes → detectors don't fire.

- [ ] **Step 3: Implement.** (a) multi-cloud `run()`: add the 3 `mc_*` params; in the `if semantic_store is not None:` path, when a param is non-None call the matching portable writer via `KnowledgeGraphWriter(semantic_store, contract.customer_id)`. Do NOT alter the feed/OCSF path. (b) `scan_pipeline.py`: add the 3 `mc_*` fields to `ScanSources`; add a multi-cloud-posture feeder (mirror the cloud-posture block ~:325-349), `needed` = any `mc_*` is not None, placed right after cloud-posture (before identity). Add `_MC_TOOLS` (grep multi-cloud-posture's test contract for `permitted_tools`).

- [ ] **Step 4: Run → PASS** (e2e + a multi-cloud unit test: `run(mc_kms_keys=[...], semantic_store=store)` writes the `kind=kms-key` node). Then `uv run pytest packages/agents/multi-cloud-posture -q` + `uv run pytest packages/runtime -q`.

- [ ] **Step 5: Commit** — `git commit -am "feat(multi-cloud): inject KMS/SQL/VM resources into run() + scan_run feeder → cross-cloud exposure"`

---

## Task 2 (B1): surface worst-CVE KEV/EPSS on `AttackPath`

**Files:**

- Modify: `packages/agents/meta-harness/src/meta_harness/attack_paths.py` (`AttackPath` ~:70-87; the per-path CVE aggregation `_Group.worst` ~:113 + wherever severity is derived from CVE nodes)
- Test: `packages/agents/meta-harness/tests/`

**Interfaces:**

- Consumes: the CVE node properties in the graph (threat-intel writes KEV; a CVE node carries `kev` / `epss` — VERIFY the exact property names by reading `threat_intel` `upsert_cve` and how `VULNERABLE_TO` targets are read in `kg_query.py`).
- Produces: `AttackPath.kev: bool` (default False) + `AttackPath.epss: float | None` (default None), populated from the path's worst CVE.

- [ ] **Step 1: Write the failing test** — build a graph where a path's CVE node has `kev=True` (+ an `epss`); run `AttackPathRanker.find_all`; assert the returned `AttackPath` for that path has `.kev is True` (and `.epss` set). Reuse an existing attack_paths test harness that plants a `VULNERABLE_TO` CVE.

- [ ] **Step 2: Run → FAIL** — `AttackPath` has no `kev`/`epss`.

- [ ] **Step 3: Implement.** Add `kev: bool = False`, `epss: float | None = None` to `AttackPath`. In the ranker's CVE aggregation (where it computes worst severity per path/group), also read the CVE node's `kev`/`epss` and carry the worst path's values onto the emitted `AttackPath`. For non-CVE paths, leave defaults.

- [ ] **Step 4: Run → PASS** — the KEV path's `AttackPath.kev is True`. Then `uv run pytest packages/agents/meta-harness -q`.

- [ ] **Step 5: Commit** — `git commit -am "feat(attack-paths): carry worst-CVE KEV/EPSS on AttackPath"`

---

## Task 3 (B2): reusable expected-loss ranker (real kev/epss + broader blast)

**Files:**

- Modify: `packages/agents/meta-harness/src/meta_harness/report_card.py` (extract the scoring; `kev=False` at ~:182; `_blast` ~:166-174; sort ~:238)
- Test: `packages/agents/meta-harness/tests/test_report_card.py` (or a focused new test)

**Interfaces:**

- Consumes: `AttackPath.kev/epss` (Task 2); `path_priors.leaf_probability(severity, *, kev, epss)`; `belief.sink_probability`; `AttackPath.sink_id`.
- Produces: `def rank_by_expected_loss(paths: list[AttackPath], store, tenant) -> list[tuple[AttackPath, float, int]]` (or similar) returning `(path, expected_loss, blast_radius)` ordered by `-expected_loss` — the extracted, reusable scorer.

- [ ] **Step 1: Write the failing test** — two `AttackPath`s with EQUAL severity: one reaching a high-blast sink / KEV CVE, one a single-store non-KEV. Call `rank_by_expected_loss`; assert the high-blast/KEV path ranks first (proving it's expected-loss, not flat severity). A KEV path must outrank an identical non-KEV path.

- [ ] **Step 2: Run → FAIL** — `rank_by_expected_loss` doesn't exist.

- [ ] **Step 3: Implement.** Extract the scoring from `build_report_card` into `rank_by_expected_loss`: for each path, `route_p = leaf_probability(p.severity, kev=p.kev, epss=p.epss)` (real values, NOT `kev=False`); group by `sink_id`; `sink_p = noisy-OR`; `blast = _blast(...)` broadened so more path types get a real estimate (fall back to 1 only when genuinely unknown — document it); `expected_loss = sink_p × blast`; sort by `-expected_loss` (tie-break route_p, title). Keep it total.

- [ ] **Step 4: Run → PASS**. Then `uv run pytest packages/agents/meta-harness -q`.

- [ ] **Step 5: Commit** — `git commit -am "feat(report-card): reusable expected-loss ranker with real KEV/EPSS + broader blast"`

---

## Task 4 (B3): wire the ranker into `analyze`; refactor `build_report_card` to reuse it

**Files:**

- Modify: `packages/agents/meta-harness/src/meta_harness/scan.py` (`analyze` ~:52)
- Modify: `packages/agents/meta-harness/src/meta_harness/report_card.py` (`build_report_card` reuses `rank_by_expected_loss`)
- Test: `packages/runtime/tests/integration/test_scan_pipeline_e2e.py`

**Interfaces:**

- Consumes: `rank_by_expected_loss` (Task 3); `ScanResult` (`scan.py`).
- Produces: `analyze` returns `ScanResult.confirmed` ordered by expected loss (still `list[AttackPath]`).

- [ ] **Step 1: Write the failing e2e** — a scan graph with a crown-jewel (high blast) AND a single-store exposure of EQUAL `_SEVERITY`; assert `res.confirmed[0]` is the crown-jewel (expected-loss order), which the old flat-severity sort would tie/mis-order. Use the existing e2e session_factory + feeders.

- [ ] **Step 2: Run → FAIL** — `analyze` still flat-sorts; the tie resolves by count/title, not blast.

- [ ] **Step 3: Implement.** In `analyze` (`scan.py`), after `find_all()`, order `confirmed` via `rank_by_expected_loss(confirmed, store, tenant)` (keep the `list[AttackPath]` return; attach `expected_loss` only if `AttackPath` gains an optional field, else just reorder). Refactor `build_report_card` to call `rank_by_expected_loss` on the precomputed `find_all()` result instead of its inline scoring (no double-run, no behavior change to the card surface).

- [ ] **Step 4: Run → PASS** (e2e + `uv run pytest packages/agents/meta-harness -q` confirming `build_report_card` still green). Then `uv run pytest packages/runtime -q`.

- [ ] **Step 5: Commit** — `git commit -am "feat(scan): rank pipeline confirmed paths by expected loss (belief + KEV/EPSS + blast)"`

---

## Task 5: honest coverage close

**Files:**

- Modify: `docs/strategy/operating-path-detector-coverage.md`

- [ ] **Step 1: Update `find_exposed_kms_key` + `find_exposed_database`** rows to note they now fire **cross-cloud (AWS + Azure/GCP)** via the multi-cloud-posture feeder.
- [ ] **Step 2: Add a "multi-cloud residual (parked — needs collection)" note** naming precisely: `find_internet_exposed_host_vulnerable` cross-cloud (no Azure/GCP host-CVE source), native Azure-MI/GCP-SA `find_kms_key_access` (no non-AWS principal inventory; `identity/tools/gcp_iam.py` built-but-unwired), cross-cloud `find_stored_secret_to_data` (AWS AKIA/ASIA-only).
- [ ] **Step 3: Add a "ranking" note** — confirmed paths are now ordered by expected loss (blast × belief × KEV/EPSS), not flat severity.
- [ ] **Step 4: Commit** — `git commit -am "docs(tier3): cross-cloud KMS/DB + expected-loss ranking; honest multi-cloud residual"`

---

## Self-Review

**Spec coverage:** A1+A2 → Task 1; B1 → Task 2; B2 → Task 3; B3 → Task 4; honest close → Task 5. Every spec section maps. ✓

**Placeholder scan:** Task 1's e2e + the CVE-property names (Task 2) instruct the implementer to grep exact names at the seam (file:lines given) — deliberate, not hand-waving. Test intent is concrete (KEV outranks non-KEV; high-blast outranks single-store). ✓

**Type consistency:** `AttackPath.kev/epss` defined Task 2, consumed Tasks 3-4; `rank_by_expected_loss` defined Task 3, consumed Task 4; `ScanSources.mc_*` + `KmsKeyRecord`/`SqlInstanceRecord`/`VmInstanceRecord` consistent Task 1. ✓

**Flagged for implementer resolution:** exact CVE `kev`/`epss` property names in the graph (Task 2 — read `threat_intel.upsert_cve` + how `kg_query` reads CVE nodes); the exact `KmsKeyRecord`/`SqlInstanceRecord` constructor args (Task 1); how broadly to broaden `_blast` (Task 3 — real estimate where the graph supports it, documented fallback to 1 otherwise).
