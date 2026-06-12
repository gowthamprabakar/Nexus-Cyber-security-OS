# audit v0.2 — charter audit.jsonl Coverage (WI-F1)

**Date:** 2026-06-12 · Measured **per-source**, no aggregate (WI-F1).

## Covered at v0.2

- Filesystem ingest of `charter.audit.AuditLog` files (`tools/jsonl_reader.py`, direct read —
  the BY_DESIGN_EXEMPT path, ADR-007 v1.3).
- Hash-chain verification + tamper detection/categorization + tamper-alert emission.
- Merkle index + membership proofs; broad typed query (time/tenant/action/agent/status).
- Cross-agent aggregation (this jsonl source alongside F.5 episodes + agent chains).

## NOT covered (v0.3)

- Sigstore-style epoch signing (Q2); SQL-like query DSL (Q3); external SIEM forward (Q1).

## Honest estimate

**~70-80% `[estimate]`** of the charter-jsonl audit signal — read + verify + tamper + index +
query are complete; cryptographic signing + DSL deferred. Estimate, not a benchmark.
