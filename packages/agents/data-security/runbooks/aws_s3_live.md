# Runbook — Live AWS S3 Data Discovery (data-security v0.2)

## Setup

1. Configure AWS credentials (boto3 default chain or `AWS_PROFILE=<profile>`) with
   `s3:ListAllMyBuckets` + per-bucket get-\* + `s3:GetObject` on the buckets in scope.
2. (Optional) override the sample rate via the execution contract (default 1%, Q4).

## Run (gated live)

```bash
AWS_PROFILE=dev NEXUS_LIVE_DATA_SECURITY=1 uv run pytest \
  packages/agents/data-security/tests/integration/test_data_security_multi_cloud_e2e.py -v -k s3
```

## Privacy invariants (load-bearing)

- **WI-S8** `assert_privacy_contract`: findings carry classification **label + hash only** —
  never plaintext. Sample bytes stay in the edge and are discarded after classification.
- **WI-S9** every finding carries a SHA-256 privacy hash, never the content.
- **WI-S10** the residency boundary: only metadata (bucket / region / jurisdiction / label /
  count) leaves the edge.
- **WI-S12** every finding includes `sample_basis` (objects_scanned / total_estimate / rate).
