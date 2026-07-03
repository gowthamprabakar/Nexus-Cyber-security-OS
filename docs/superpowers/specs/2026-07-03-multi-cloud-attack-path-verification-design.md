# Multi-Cloud (Azure/GCP) Attack-Path Verification — Design Spec

**Date:** 2026-07-03
**Gap:** #13 — the last known coverage gap. Close the genuinely-remaining Azure/GCP attack-path gaps and verify the v0.5 ranking works cross-cloud.
**Grounding:** a code-level cascade investigation (not the contradictory strategy docs). ~10 of 19 archetypes are already cross-cloud CI-verified; 16 of 19 detectors are provider-agnostic. This spec closes only the genuinely-remaining, reachable gaps.

## 1. Premise (code-truth, not docs)

The strategy docs contradict each other on #13 (one says "COMPLETE," another lists AWS-only families that v0.5 already closed). The cascade map from `kg_query.py` + the writers + the existing tests is the source of truth:

- **Already cross-cloud CI-verified (do NOT touch):** public_secret (3), public_unencrypted (7), fine_grained_data (4), external_trust (8), internet_exposed_vulnerable (2), crown_jewel (5), privileged_vulnerable (6), exposed_ai_sensitive_data (10), `CAN_ESCALATE_TO`→data escalation (Azure+GCP), leaked_credential (Azure SP + GCP SA, v0.5).
- **16/19 detectors are provider-agnostic** — they join on edges, not cloud-specific ids.

## 2. The keystone gap

Nearly every remaining break has ONE root cause: **multi-cloud-posture (and the absent Azure/GCP KMS/DB/VM writers) never stamp Azure/GCP resources as spine nodes with a unified `kind` + `is_public` + the sink edges the detectors read.** They write `MISCONFIGURATION_FINDING → AFFECTS → CLOUD_RESOURCE` with empty properties. Detectors filter on `kind=="kms-key"` / `kind=="rds-instance"` / `is_public`, so they find nothing. Compounding it, `record_exposed_resources` (which _would_ stamp `is_public`) exists (`multi_cloud_posture/tools/kg_writer.py:84-95`) but the agent driver never calls it — a dormant writer.

## 3. Scope

### In scope (ponytail-narrowed)

1. **Keystone — spine-stamping for Azure/GCP KMS, SQL, VM** with a **unified `kind`** so the detectors stay untouched:
   - Azure Key Vault key / GCP Cloud KMS key → `CLOUD_RESOURCE` node `kind="kms-key"` (+ `is_public` when the policy is open; + `EXPOSES_DATA` to the protected data classification when known) → unblocks `find_exposed_kms_key` + `find_kms_key_access`.
   - Azure SQL / GCP Cloud SQL → `CLOUD_RESOURCE` node `kind="rds-instance"` + `is_public` → unblocks `find_exposed_database`.
   - Azure VM / GCP Compute Engine → `CLOUD_RESOURCE` node `is_public` + a direct `VULNERABLE_TO` edge (host scan) → unblocks `find_internet_exposed_host_vulnerable`.
2. **Wire the dormant `record_exposed_resources`** into the multi-cloud-posture agent driver so Azure/GCP public resources actually stamp `is_public` in production runs (closes the built-but-unwired dormancy).
3. **Per-family cross-cloud tests** (CI-REAL, injectable clients, no real cloud) for the 4 unblocked detectors on both Azure and GCP.
4. **One mixed-cloud ranking test** — a fixture with AWS + Azure + GCP resources → `build_report_card` → assert the v0.5 expected-loss ranking produces a coherent top-N spanning clouds (the v0.5-ranking-cross-cloud gap the pre-v0.5 tests never covered).

**Cascade risk to verify FIRST (plan task 1):** the keystone assumes multi-cloud-posture's CIS rules actually surface the _public/exposed_ signal for Azure/GCP KMS, SQL, and VM (else there is nothing to stamp `is_public` from). Before building the writers, confirm each signal exists in the rules; if a signal is missing (e.g. no "public Cloud SQL" rule), that sub-gap is added to scope or documented as a further defer — do not build a stamper with no data behind it.

### Explicitly deferred (documented, with rationale)

- **resource-based-data on Azure/GCP** (`find_resource_based_data_exposure`): `policy_readers` is an AWS-IAM-JSON parser; Azure RBAC assignment enumeration + GCS IAM policy parsing is large net-new work for one niche path (sev 62). Deferred; leaves a real but low-value Azure/GCP gap.
- **privesc-to-data via `ASSUMES` walk** (`find_privilege_escalation_to_data`): a structural mismatch (detector walks IDENTITY→IDENTITY; Azure/GCP use CLOUD_RESOURCE→ASSUMES + `CAN_ESCALATE_TO`). But cross-cloud **escalation is already covered** by the `CAN_ESCALATE_TO`→data detector (tested Azure+GCP). This is redundant coverage, not missing detection. Deferred.

### Non-goals (YAGNI)

- No detector rewrites where a unified `kind` on the writer side suffices.
- No new datastore, no canonical-key redesign beyond adding the KMS key builder(s) actually needed.
- No live cloud access — all verification is CI-REAL via injectable client Protocols (live lanes stay operator-gated).
- No touching the ~10 already-verified archetypes.

## 4. Global constraints (bind every task)

- **Privacy (P0):** label/hashed ids only; non-AWS cred convergence via `secret_fingerprint`. No plaintext.
- **Done = CI-executes:** every detector-cross-cloud claim lands with a CI test that actually fires it on an Azure/GCP-shaped fixture. "Live cloud scan" stays operator-gated and out of the CI claim.
- **Same vocab → detectors unchanged:** prefer stamping a unified `kind`/`is_public`/edge on the writer over branching the detector. If a detector must change, it's a `kind`-set broadening, never per-cloud logic.
- **Honesty / no lipstick:** the deferred gaps are stated; "cross-cloud verified" means a CI test fires the detector on that cloud's fixture, nothing more.
- **commitlint:** lowercase subject, body ≤100; run husky (no `--no-verify`).
- **Regression:** the full meta-harness + multi-cloud-posture + fleet_testkit suites stay green.

## 5. Canonical-key note

Object storage (`azure_blob_uri`, `gcs_uri`) and `secret_fingerprint` already have cross-cloud key builders. KMS keys have **none** for Azure/GCP — the keystone writer must key them consistently (e.g. the Azure Key Vault key URI / GCP KMS resource name) so a leak⇄owner⇄exposure converge on one node. Add the minimal key builder(s) needed; do not redesign canonical resolution.

## 6. Testing strategy

- Per detector × cloud: plant the resource via the (new or existing) writer with the unified `kind`/`is_public`/edges, run the detector, assert it fires with the right entities. Mirror the existing `test_path*_cross_cloud_e2e.py` pattern (injectable clients, no real cloud).
- Mixed-cloud ranking: one fixture spanning all three clouds → `build_report_card` → assert cards from ≥2 clouds appear and the expected-loss ordering is coherent.
- The keystone wiring: a test that the multi-cloud-posture agent driver, run on a fixture with a public Azure/GCP resource, actually stamps `is_public` on the spine node (guards the dormancy fix).

## 7. Decisions log

- **D1** Unified `kind` on the writer (Azure/GCP KMS → `kind=kms-key`, SQL → `kind=rds-instance`) over detector branching — detectors stay untouched (the codebase's own #13 convention).
- **D2** Keystone spine-stamping is the high-leverage fix; wiring `record_exposed_resources` closes the dormancy.
- **D3** Defer resource-based-data + privesc-ASSUMES (documented rationale: high-effort/niche + already-covered-elsewhere).
- **D4** Add a mixed-cloud ranking test — the v0.5-ranking-cross-cloud gap the pre-v0.5 tests miss.
- **D5** All CI-REAL via injectable clients; no live cloud in the verification claim.
