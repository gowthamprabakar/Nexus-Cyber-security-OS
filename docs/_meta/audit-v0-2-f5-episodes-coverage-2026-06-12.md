# audit v0.2 — F.5 Episodes Coverage (WI-F1)

**Date:** 2026-06-12 · Measured **per-source**, no aggregate (WI-F1).

## Covered at v0.2

- Episode-table audit read (`tools/episode_reader.py`) under F.5 RLS tenant isolation.
- Same verification + tamper + Merkle + typed-query pipeline as the jsonl source.
- Cross-tenant queries gated by the admin role (WI-F11 `assert_admin_for_cross_tenant`).

## NOT covered (v0.3)

- Live streaming subscription to episode writes (continuous run-loop wiring is Phase C).
- Sigstore signing (Q2); SQL-like DSL (Q3).

## Honest estimate

**~60-70% `[estimate]`** — read + verify + RLS-isolated query are solid; live subscription is
Phase C. Estimate, not a benchmark.
