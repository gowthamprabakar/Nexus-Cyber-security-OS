# data-security v0.2 — GCS Coverage (WI-S1)

**Date:** 2026-06-11 · Measured **per-source**, no aggregate (WI-S1).

## Covered at v0.2

- Live GCS bucket inventory + sampling (`tools/gcs_inventory.py`) — public-via-IAM
  (allUsers/allAuthenticatedUsers) + encryption + location; reuses shared sample shapes.
- Net-new at v0.2.

## NOT covered (v0.3 / Phase D)

- Cloud SQL / Firestore / BigQuery data scanning (Q1 → v0.3); full-bucket scan (Q4 → v0.3).

## Honest estimate

**~45-55% `[estimate]`** — live inventory + sampling shipped; depth deferred. Estimate, not a
benchmark.
