# Tier 3: Multi-Cloud Exposure + Expected-Loss Ranking — Design

**Date:** 2026-07-05
**Branch:** `feat/tier3-multicloud-ranking`
**Status:** approved (operator: Part A = 2 clean detectors + honest park; Part B = full KEV/EPSS + broader blast)

## Goal

Close the two Tier-3 detection gaps that need **no new collection**:

- **Part A (multi-cloud):** make `find_exposed_kms_key` + `find_exposed_database` fire on **Azure/GCP** in the `scan_run` pipeline.
- **Part B (ranking):** rank the pipeline's confirmed attack paths by **real expected loss** (blast-radius × belief-network probability × KEV/EPSS-lifted exploitability) instead of a flat `_SEVERITY` constant.

## Background (from deep-scope, file:line verified)

**Part A — the multi-cloud spine is built but its `run()` never calls it.** multi-cloud-posture's portable writers stamp exactly the AWS markers the detectors filter on — `record_kms_keys` → `CLOUD_RESOURCE{kind="kms-key", is_public}` (+ `EXPOSES_DATA` when `data_type` set), `record_sql_instances` → `{kind="rds-instance", is_public, engine}` (`tools/kg_writer.py:131,159`, records `KmsKeyRecord`/`SqlInstanceRecord`/`VmInstanceRecord` at :36/:51/:68) — and are CI-proven (`fleet_testkit/tests/test_path_multicloud_kms_e2e.py` etc.). But `run()` (`agent.py:119-166`) accepts **only offline feed paths** (no injectable resource seam), and its finding path (`_upsert_findings_to_kg`) writes OCSF `resource_type` strings, not `kind=kms-key`. So the writers are dead from `run()`'s perspective; multi-cloud-posture is not a `scan_run` feeder. data-security's data half is already cloud-agnostic (`data_security/kg_writer.py:184-225`), so the "…to data" sink half works cross-cloud already.

**Part B — the expected-loss model is built but orphaned.** `scan_run`→`analyze` returns `AttackPathRanker.find_all()` sorted by `(-severity, -count, title)` (`attack_paths.py:421`). v0.5 built the real model — `path_priors.leaf_probability(severity, kev, epss)`, `belief.route_probability`/`sink_probability` (noisy-OR), and `report_card.build_report_card` which ranks the **same `AttackPath` objects** by `expected_loss = sink_p × blast_radius` (`report_card.py:147-253`) — but `build_report_card` has **zero production callers**. Two input placeholders make it not-yet-honest: `kev=False` is hard-coded for every named path (`report_card.py:182`), and `blast_radius` is real only for fine-grained-access principals, floor-of-1 otherwise (`report_card.py:166-174`). `AttackPath` carries `severity` + `sink_id` but no `kev`/`epss` (`attack_paths.py:70-87`).

## The honest ceiling (no lipstick)

- **Part A is NOT full multi-cloud parity.** Only `find_exposed_kms_key` + `find_exposed_database` fire cross-cloud without collection (self-contained: `kind` + `is_public`). **Explicitly PARKED as needs-collection:** cross-cloud `find_internet_exposed_host_vulnerable` (no Azure/GCP host-CVE source), native Azure-MI/GCP-SA `find_kms_key_access` (no non-AWS principal inventory — a built-but-unwired `identity/tools/gcp_iam.py` exists; operator chose not to wire it this cycle), and cross-cloud `find_stored_secret_to_data` (AWS `AKIA/ASIA`-regex only). The coverage doc will name these precisely.
- **Part B reaches genuine expected-loss ranking** (blast × belief × KEV/EPSS). It changes the _order_ of confirmed paths, not the set.
- No live cloud: Part A proves against injected Azure/GCP resource records (offline), like every other feeder; live emission stays `NEXUS_LIVE_*`-gated.

## Architecture

### Part A — multi-cloud-posture injectable resource seam + feeder

**A1.** Add typed injectable resource params to multi-cloud-posture `run()` (mirror cloud-posture's `ec2_workloads` seam, `cloud_posture/agent.py`): `mc_kms_keys: Sequence[KmsKeyRecord] | None`, `mc_sql_instances: Sequence[SqlInstanceRecord] | None`, `mc_vm_instances: Sequence[VmInstanceRecord] | None`. When provided (offline), call `record_kms_keys` / `record_sql_instances` / `record_vm_instances` in the `semantic_store is not None` path. Do NOT touch the dead CIS rule engine or the OCSF-finding path.

**A2.** `scan_run` feeder: add `mc_kms_keys` / `mc_sql_instances` / `mc_vm_instances` to `ScanSources`; add a multi-cloud-posture feeder block (mirror the cloud-posture block, `scan_pipeline.py:325-349`) that fires when any `mc_*` source is set and passes them to `run()`. Place it near cloud-posture in the dependency order (before identity, so cross-cloud resource nodes exist when identity expands admin `HAS_ACCESS_TO`).

Result: `find_exposed_kms_key` + `find_exposed_database` fire on Azure/GCP-keyed nodes. (`find_kms_key_access` additionally fires only for an AWS-admin reaching a cross-cloud key — an incidental bonus of identity's cloud-blind admin expansion; not claimed as native-cloud coverage.)

### Part B — expected-loss ranking on the pipeline's confirmed paths

**B1.** Surface exploitability on named paths. Extend `AttackPathRanker`'s per-path worst-CVE tracking (`_Group.worst`, `attack_paths.py:113`, currently worst _severity_) to also capture the worst CVE's **KEV flag + EPSS** from the graph (threat-intel writes KEV; the CVE nodes carry it). Add `kev: bool` + `epss: float | None` to `AttackPath` (`attack_paths.py:70-87`).

**B2.** A reusable expected-loss ranker. Extract `build_report_card`'s scoring (leaf_probability × per-sink noisy-OR × blast) into a function that takes a precomputed `find_all()` result + the store/tenant and returns the paths ordered by `expected_loss`, with `expected_loss` + `blast_radius` attached. Pass each path's real `kev`/`epss` into `leaf_probability` (replacing the `kev=False` hard-code, `report_card.py:182`). Broaden `_blast` beyond fine-grained principals so more path types get a real blast estimate (fall back to 1 only when genuinely unknown).

**B3.** Wire it into the pipeline. `analyze` (or `scan_run`) ranks `confirmed` via the B2 ranker, so `ScanResult.confirmed` is expected-loss-ordered (keeping the `list[AttackPath]` contract that CLI + scheduler read — `scan.py:52`, `cli.py:539/551`). Refactor `build_report_card` to reuse the same ranker (avoid double-running `find_all`).

## Components

- `packages/agents/multi-cloud-posture/src/multi_cloud_posture/agent.py` — `run()` injectable resource seam (A1).
- `packages/runtime/src/nexus_runtime/scan_pipeline.py` — `ScanSources` mc\_\* fields + multi-cloud feeder (A2); `analyze`-side ranking wire (B3).
- `packages/agents/meta-harness/src/meta_harness/attack_paths.py` — `AttackPath.kev/epss` + `_Group.worst` KEV/EPSS (B1).
- `packages/agents/meta-harness/src/meta_harness/report_card.py` — extract reusable ranker, use real kev/epss, broaden blast (B2); refactor to reuse (B3).
- `packages/agents/meta-harness/src/meta_harness/scan.py` — `analyze` applies the expected-loss ranker to `confirmed` (B3).
- `docs/strategy/operating-path-detector-coverage.md` — mark exposed-KMS/DB cross-cloud; name the parked multi-cloud residual honestly.

## Data flow / join keys

- **Part A:** injected `KmsKeyRecord(is_public=True, ...)` (Azure/GCP-keyed) → `record_kms_keys` → `CLOUD_RESOURCE{kind=kms-key,is_public}` → `find_exposed_kms_key`. Same for SQL → `find_exposed_database`. No cross-agent join needed (self-contained resource-exposure detectors).
- **Part B:** `find_all()` paths → each gets `leaf_probability(severity, kev, epss)` → grouped by `sink_id` → `sink_p = noisy-OR` → `expected_loss = sink_p × blast`; `confirmed` sorted by `-expected_loss`.

## Error handling

Part A feeder follows the try/except degrade-not-abort contract; a `None` mc\_\* source skips it (existing tests green). Part B ranking must be total (never drop a confirmed path); a path with no sink falls back to `sink_p = route_p`, unknown blast falls back to 1 — documented, not silent.

## Testing

- **A:** e2e — inject an Azure `KmsKeyRecord(is_public=True)` + a GCP `SqlInstanceRecord(is_public=True)` via `ScanSources` → `scan_run` → assert `find_exposed_kms_key` + `find_exposed_database` fire (Azure/GCP canonical keys in the chain). multi-cloud-posture unit test: the seam calls the writers.
- **B:** unit — `AttackPath` carries kev/epss from a KEV CVE; the ranker orders a high-blast/KEV path above a low-blast one with equal severity (proving expected-loss, not flat severity); a KEV path outranks a non-KEV path of equal severity/blast. e2e — `scan_run`'s `confirmed` is expected-loss-ordered (a crown-jewel with more blast ranks above a single-store exposure even if severity ties).
- `uv run mypy` + `uv run ruff check` + `uv run pytest packages/runtime packages/agents/meta-harness packages/agents/multi-cloud-posture -q` clean (env synced with `uv sync --all-packages --all-extras`).

## Build sequence

1. **A1+A2** — multi-cloud seam + feeder + e2e → exposed-KMS/DB cross-cloud (S–M).
2. **B1** — `AttackPath.kev/epss` + ranker KEV/EPSS tracking (M).
3. **B2** — reusable expected-loss ranker (real kev/epss + broader blast) (M).
4. **B3** — wire into `analyze`/`scan_run`; refactor `build_report_card` to reuse (S–M).
5. **Close** — coverage doc (cross-cloud KMS/DB + honest parked residual) + whole-branch review.

## Out of scope (parked, needs collection or new detection)

- Azure/GCP host-vuln, native Azure-MI/GCP-SA identity access (incl. wiring `gcp_iam.py`), cross-cloud stored-secret patterns.
- Live-cloud emission (stays `NEXUS_LIVE_*`-gated).
- Multi-cloud VM exposure as a _standalone_ detector (there's no `find_exposed_vm`; the VM node only matters via host-vuln, which is parked).
