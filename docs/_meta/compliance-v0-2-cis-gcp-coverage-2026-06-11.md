# compliance v0.2 — CIS-GCP Coverage (WI-C1)

**Date:** 2026-06-11 · Measured **per-framework**, no aggregate (WI-C1).

## Covered at v0.2

- CIS GCP Foundation Benchmark v2.0 library: **14 representative controls**, **10 wired** to
  the 10 stable `MCSPM-GCP-*` rules D.5 actually emits (STORAGE-001/002, SQL-001/002,
  GCE-001/002, FIREWALL-001/002 = SSH/RDP, KMS-001, BIGQUERY-001).
- Source agent `multi_cloud_posture`; exact matching.

## NOT covered (Phase D / v0.3)

- The full CIS-GCP v2 control set (~60 controls) — v0.2 ships a representative subset.
- Controls (SA key rotation, log sinks, CMEK) with no matching D.5 rule.

## Honest estimate

**~16% `[estimate]`** of the full CIS-GCP v2 set is wired (10 of ~60); 10 of the 14 shipped
controls map to real D.5 rules. Estimate, not a measured benchmark.
