# Runbook — Live Azure Blob Data Discovery (data-security v0.2)

## Setup

1. Configure Azure credentials (charter Pattern A Azure resolver, as D.5) with read access to
   the storage accounts / containers in scope.
2. (Optional) override the sample rate (default 1%, Q4).

## Run (gated live)

```bash
NEXUS_LIVE_DATA_SECURITY=1 uv run pytest \
  packages/agents/data-security/tests/integration/test_data_security_multi_cloud_e2e.py -v -k azure
```

## Notes

- Same privacy invariants as the S3 runbook (WI-S8/S9/S10/S12).
- Azure SQL / Cosmos DB are v0.3 (Q1).
