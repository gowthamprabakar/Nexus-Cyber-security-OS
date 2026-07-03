# Track A — Mixed-Cloud Ranking Verification Report

**Status:** DONE
**File:** `packages/integration/src/fleet_testkit/tests/test_mixed_cloud_ranking_e2e.py`

## What was built

Single test `test_mixed_cloud_ranking_coherence` that plants three public-data attack paths in one
tenant (AWS blast-radius-3 + Azure single-store + GCP single-store) then asserts:

1. `build_report_card` returns at least one card
2. Chains span at least 2 clouds (`arn:` present AND at least one of `blob.core.windows.net` / `gs://`)
3. `expected_loss` list is non-increasing (explicit ranking invariant assertion)
4. AWS card (blast_radius=3) has expected_loss >= any single-store card
5. `render_tenant_report_card` renders with `[P ` and `data store` markers

## Fixture design

- **AWS path**: raw `upsert_entity` + `IdentityKgWriter.record_access` (same pattern as
  `test_probabilistic_ranking.py`); role reaches 3 S3 buckets → blast_radius=3
- **Azure path**: `drive_azure_data_security` (public container, SSN blob) +
  `drive_azure_identity_access` (managed identity granted Storage Blob Data Reader);
  canonical key = `https://mixedcloudstorage.blob.core.windows.net/sensitive-data`
- **GCP path**: `drive_gcs_data_security` (PUBLIC_MEMBER + SA member, SSN blob) +
  `drive_gcp_identity_access` (SA granted roles/storage.objectViewer);
  canonical key = `gs://mixed-cloud-gcs-bucket`

## Verification

- `1 passed in 0.65s`
- ruff check: all checks passed
- ruff format: applied (one reformat)
- mypy: not in scope (integration/tests excluded from mypy files list and by `exclude = ["tests"]`)

## No concerns
