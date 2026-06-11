# compliance v0.2 — CIS-Azure Coverage (WI-C1)

**Date:** 2026-06-11 · Measured **per-framework**, no aggregate (WI-C1).

## Covered at v0.2

- CIS Microsoft Azure Foundations Benchmark v2.0 library: **14 representative controls**,
  **8 wired** to the 8 stable `MCSPM-AZURE-*` rules D.5 actually emits (STORAGE-001/002,
  KEYVAULT-001/002, NSG-001/002 = RDP/SSH, SQL-001, APPSERVICE-001).
- Source agent `multi_cloud_posture`; exact `(source_agent, source_rule_id)` matching.

## NOT covered (Phase D / v0.3)

- The full CIS-Azure v2 control set (~70 controls) — v0.2 ships a representative subset.
- Controls (MFA, Defender plans, Activity-log retention, VM disk encryption, TLS min) with
  no matching D.5 rule — tracks D.5's rule catalog.

## Honest estimate

**~12% `[estimate]`** of the full CIS-Azure v2 control set is wired (8 of ~70); 8 of the 14
shipped controls map to real D.5 rules. Estimate, not a measured benchmark.
