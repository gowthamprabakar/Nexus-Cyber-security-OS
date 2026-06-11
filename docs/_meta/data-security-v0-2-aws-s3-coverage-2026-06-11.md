# data-security v0.2 — AWS S3 Coverage (WI-S1)

**Date:** 2026-06-11 · Measured **per-source**, no aggregate (WI-S1).

## Covered at v0.2

- Live S3 bucket inventory (`tools/s3_inventory_live.py`, boto3 + charter Pattern A) — ACL /
  public-access-block / encryption / policy / tags → byte-identical `BucketInventory`.
- Live sample-based object scanning (`tools/s3_objects_live.py`) — 1% default (Q4),
  deterministic, mandatory `SampleBasis` (WI-S12).
- Data-residency jurisdiction tagging (`residency/aws_s3.py`).

## NOT covered (v0.3 / Phase D)

- Full-bucket scanning (Q4 → v0.3 cost analysis); RDS / DynamoDB (Q1 → v0.3).
- ML classification (Q3 → v0.3).

## Honest estimate

**~55-65% `[estimate]`** of the S3 DSPM signal — live inventory + sample classification +
residency are solid; full-bucket + behavioural coverage deferred. Estimate, not a benchmark.
