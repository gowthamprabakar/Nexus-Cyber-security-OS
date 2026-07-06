# Cycle 4: Multi-Cloud Parity (North-Star Gap #13) — Design

**Date:** 2026-07-06
**Branch:** `feat/cycle4-multicloud-parity` (off main `fffbf4dc` = main+#801+#803)
**Status:** design APPROVED by operator (full parity wiring: native identity + data-side + host-vuln; defer RDS→PII + cross-cloud secrets)

## Goal

Close the last known North-Star gap: **a customer who connects a non-AWS (Azure/GCP) account sees the
SAME attack paths as an AWS customer.** The deep-scope established this is overwhelmingly a **wiring**
problem — the Azure/GCP identity resolvers, cross-cloud writers, and readers are already built and
unit-tested; they are simply not imported into the agents' `run()` or exposed as `ScanSources` seams. And
every target detector in `kg_query.py` is already **cloud-agnostic** (no `arn:aws`/`AKIA`/prefix filter),
so lighting them cross-cloud needs **zero detector-file changes → zero conflict with the still-open #802.**

## Baseline (already cross-cloud, post-#801)

`find_exposed_kms_key` + `find_exposed_database` fire on Azure/GCP (via `multi_cloud_posture`
`record_kms_keys`/`record_sql_instances` + `ScanSources.mc_kms_keys`/`mc_sql_instances`). Cross-cloud
storage exposure (`public_resource`) fires via `record_exposed_resources`. `record_vm_instances`
(`kind=vm-instance`+`is_public`) is wired but no `VULNERABLE_TO` reaches those nodes through `scan_run`.

## Scope (approved)

**INCLUDE (pure collection-wiring, offline-provable, no #802 conflict):**

- **P1 — Native identity (GCP-SA + Azure-MI).** Wire the built resolvers → the built writer methods via
  new `ScanSources` seams + an `identity.run()` block mirroring the AWS one (agent.py:220-249).
- **P2 — Data-side (Blob/GCS).** Wire `data_security` `record_data_sources` into `run()` (today S3-only)
  so native Blob/GCS `EXPOSES_DATA → DATA_CLASSIFICATION` lands — the sink half of the native
  fine-grained path.
- **P3 — Host-vuln cross-cloud.** A `scan_run` join so a `kind=vm-instance`+`is_public` node (Azure VM /
  GCP instance) shares an id with its host CVE (`vuln_host_target_arn` = the VM id); widen
  `vuln_host_target_arn` to a list for multi-VM.

**DEFER (operator-confirmed):**

- **RDS→PII** — needs a new content collector + a new writer + a new/deepened detector (the ONLY residual
  touching `attack_paths.py`/`kg_query.py` → would conflict with #802). Parked (as the coverage doc does).
- **Cross-cloud stored secrets** — producer regex gap riding on P1's owner-edges; low value. Fold in later.

## Background (deep-scope, file:line)

- **GCP resolvers** (`identity/tools/gcp_iam.py`, all built + tested in `test_cross_cloud_grants.py`):
  `storage_read_grants`→`(member, gcs_uri)` (:68), `escalation_grants`→4-tuple (:112),
  `sa_key_ownership`→`(sa, fingerprint)` (:143), `external_trust_grants` (:177).
- **Azure resolvers** (`identity/tools/azure_rbac.py` + `azure_ad.py`): `blob_read_grants`→
  `(principal, azure_blob_uri)` (:74), `escalation_grants` (:106), `external_trust_grants` (:130);
  `AzureAdListing.managed_identities` (:102), `sp_credential_ownership`→`(sp, fingerprint)` (:70).
- **Identity writer — already cross-cloud** (`identity/kg_writer.py`): `record_access` (HAS_ACCESS_TO,
  :89), `record_assume_grants` (:104), `record_escalation_grants` (CAN_ESCALATE_TO, :117),
  `record_sa_credential_ownership` (GCP OWNS, :156), `record_sp_credential_ownership` (Azure OWNS, :172),
  `record_external_trust` (:188). All key on arbitrary strings — no AWS assumptions.
- **AWS wiring to mirror:** `identity/agent.py:220-249` (the `if semantic_store is not None` block that
  writes AWS grants); `iam_listing` seam at `:149,209`; `scan_pipeline.py:417` passes it.
- **Data-side:** `data_security/kg_writer.py:184` `record_data_sources` (Blob/GCS `EXPOSES_DATA`) is BUILT
  but `data_security/agent.py:127-142,223` `run()` calls only the S3 `record` path. `azure_blob_inventory.py`/
  `gcs_inventory.py` tools exist.
- **Host-vuln:** `vulnerability/agent.py:248-264` (`host_target_arn` relabels `_artifact_name`) →
  `kg_writer.py:62` keys `VULNERABLE_TO` on that string. `ScanSources.vuln_host_target_arn`
  (`scan_pipeline.py:173,436`) is a scalar. The detector `find_internet_exposed_host_vulnerable`
  (`kg_query.py:892`) is cloud-agnostic.
- **Join keys:** `charter.canonical` `gcs_uri` (:36) / `azure_blob_uri` (:45) — the identity grant's
  resource side and the data-security storage node MUST share these. Host-vuln join key = the native VM
  resource id shared between `mc_vm_instances[].instance_id` and `vuln_host_target_arn`.

## Architecture

### P1 — native identity seam

`identity.run()` gains injectable params (mirror `iam_listing`): `gcp_iam_bindings` / `gcp_sa_keys` /
`azure_role_assignments` / `azure_ad_listing` (exact types = the resolvers' inputs — implementer reads
them). In the `semantic_store is not None` block (agent.py:220-249), when a GCP/Azure input is present,
call the matching resolver(s) → the matching writer method(s):

- GCP: `storage_read_grants`→`record_access`; `escalation_grants`→`record_escalation_grants`;
  `sa_key_ownership`→`record_sa_credential_ownership`; `external_trust_grants`→`record_external_trust`.
- Azure: `blob_read_grants`→`record_access`; `escalation_grants`→`record_escalation_grants`;
  `sp_credential_ownership`→`record_sp_credential_ownership`; `external_trust_grants`→`record_external_trust`.

`ScanSources` gains the 4 fields; the identity feeder (`scan_pipeline.py:417`) passes them. `None` → AWS-only
behavior unchanged. Live readers (gcp_sa_key_reader / azure_sp_secret_reader / azure_ad Graph) stay the
operator-gated follow-on; offline uses the injected inputs.

### P2 — data-side (Blob/GCS EXPOSES_DATA)

`data_security.run()` calls `record_data_sources` (Blob/GCS) in the `semantic_store` path when a
Blob/GCS inventory input is present (mirror the S3 path). `ScanSources` gains a Blob/GCS inventory feed
(mirror `ds_inventory_feed`/`ds_objects_feed`). The resource node keys on `gcs_uri`/`azure_blob_uri` so it
joins P1's identity `HAS_ACCESS_TO`. (Alternatively the already-wired multi-cloud-posture
`record_exposed_resources` provides an `is_public` Blob/GCS source; P2 adds the fine-grained data
classification the native `find_fine_grained_data_exposure` path needs.)

### P3 — host-vuln cross-cloud

Widen `ScanSources.vuln_host_target_arn: str | None` → `vuln_host_targets: tuple[(target, arn), ...]` (or
keep the scalar + add a list seam) so multiple VMs per scan each key their host CVE on the native VM id.
The vuln feeder (`scan_pipeline.py:436`) drives `record_scan_results` with `host_target_arn` = the
`mc_vm_instances[].instance_id`. `find_internet_exposed_host_vulnerable` then fires cross-cloud.

## Detectors lit cross-cloud (the parity result)

`find_fine_grained_data_exposure`, `find_privilege_escalation_to_data` / `find_escalation_method_to_data`
(GCP/Azure use `CAN_ESCALATE_TO`), `find_external_trust_exposure`, native `find_kms_key_access`, and
`find_internet_exposed_host_vulnerable` — all for Azure/GCP principals + resources.

## Testing (all through `scan_run` + `ScanSources` — offline-provable)

- **P1 GCP e2e:** inject `gcp_iam_bindings` (a GCP-SA with `storage_read_grants` to a `gcs_uri`) +
  the Blob/GCS data-side (P2) → `scan_run` → a `fine_grained_data` confirmed path for the GCP-SA →
  the same GCS data. Same for an escalation grant → `escalation_method_to_data`; an external-trust grant
  → `external_trust`.
- **P1 Azure e2e:** the same via `azure_role_assignments`/`azure_ad_listing` (Azure-MI → Blob).
- **P2:** `record_data_sources` writes `EXPOSES_DATA` for an injected Blob/GCS inventory (unit + the e2e).
- **P3 e2e:** `mc_vm_instances` (public Azure VM) + `vuln_host_target_arn`=that VM id → `scan_run` →
  `find_internet_exposed_host_vulnerable` fires cross-cloud.
- Env synced `uv sync --all-packages --all-extras`; whole-repo `uv run mypy` + `uv run ruff check` +
  `uv run pytest packages/agents/identity packages/agents/data-security packages/agents/vulnerability
packages/runtime -q` clean; **full suite + `packages/charter` guard before close** (Cycle-1 lesson).

## Build sequence

1. **P1a — GCP identity seam** (`gcp_iam_bindings`/`gcp_sa_keys` → resolvers → writers) + `ScanSources` +
   feeder + GCP e2e. (M)
2. **P1b — Azure identity seam** (`azure_role_assignments`/`azure_ad_listing`) + `ScanSources` + feeder +
   Azure e2e. (M)
3. **P2 — data-side** (`record_data_sources` Blob/GCS into `data_security.run()`) + `ScanSources` feed +
   the fine-grained-native e2e (proves P1+P2 join on `gcs_uri`/`azure_blob_uri`). (M)
4. **P3 — host-vuln cross-cloud** (`vuln_host_target_arn` list seam) + e2e. (S–M)
5. **Close** — coverage doc (multi-cloud parity: which detectors now fire cross-cloud + the honest
   live-reader deferral) + whole-branch review + full-suite/charter guard.

## Out of scope (parked, honest)

- **RDS→PII** (needs a content collector + writer + detector; #802-conflicting) — Cycle 5+.
- **Cross-cloud stored secrets** (producer regex; rides on P1) — fold in later.
- **Live-cloud emission** — the gcp*sa_key/azure_sp_secret/azure_ad live readers stay `NEXUS_LIVE*\*`-gated;
  Cycle 4 proves offline parity via injected inputs (the fleet's standard bar).
