"""Audit-chain reconciler — rebuild `promotion.yaml` from a chain of `promotion.*` events.

Task 1 holds the module open so downstream code (Task 8 CLI's `reconcile`
subcommand, Task 13's `test_reconcile_matches_tracker_state` live-cluster
test) can target a stable import path. Task 6 lands the actual chain replay.

The architectural invariant: `promotion.yaml` is a cache, the F.6
hash-chained audit log is the source of truth (safety-verification §3).
`replay()` reads a chain of `AuditEntry` records (filtered to the 9
`promotion.*` events) and rebuilds the `PromotionFile` bit-identically to
what `PromotionTracker.save()` would have produced for the same operation
sequence. Idempotent across re-runs.
"""

from __future__ import annotations

__all__: list[str] = []
