# data-security v0.2 — Azure Blob Coverage (WI-S1)

**Date:** 2026-06-11 · Measured **per-source**, no aggregate (WI-S1).

## Covered at v0.2

- Live Azure Blob container inventory + sampling (`tools/azure_blob_inventory.py`) — public
  access level + encryption + region; reuses the shared `ObjectSample` / `SampleBasis`.
- Net-new at v0.2 (v0.1 was S3-only).

## NOT covered (v0.3 / Phase D)

- Azure SQL / Cosmos DB (Q1 → v0.3); full-container scan (Q4 → v0.3); ML classification (v0.3).

## Honest estimate

**~45-55% `[estimate]`** — live container inventory + sampling shipped; depth (lifecycle,
immutability, full scan) deferred. Estimate, not a benchmark.
