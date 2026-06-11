# Runbook — Live GCS Data Discovery (data-security v0.2)

## Setup

1. Configure GCP credentials (charter Pattern A GCP resolver, as D.5) — e.g.
   `GOOGLE_APPLICATION_CREDENTIALS` — with storage read access to the buckets in scope.
2. (Optional) override the sample rate (default 1%, Q4).

## Run (gated live)

```bash
NEXUS_LIVE_DATA_SECURITY=1 uv run pytest \
  packages/agents/data-security/tests/integration/test_data_security_multi_cloud_e2e.py -v -k gcs
```

## Notes

- Same privacy invariants as the S3 runbook (WI-S8/S9/S10/S12).
- Cloud SQL / Firestore / BigQuery data scanning are v0.3 (Q1).
