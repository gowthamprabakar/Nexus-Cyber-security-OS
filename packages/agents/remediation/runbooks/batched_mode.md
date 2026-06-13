# Runbook — Batched Multi-Finding Mode (remediation v0.2)

By default A.1 remediates **one finding per run**. Opt into batched mode via the contract field
`batched_remediation: true`. The batch applies up to `min(max_actions_per_run, 10)` actions —
lifting the single-run default of 5 but always under the H5 hard ceiling of 50.

Batch-level safety (atomic, all-or-nothing):

- **Dry-run-first** — EVERY artifact passes `kubectl --dry-run=server` before ANY executes;
  one dry-run failure aborts the whole batch (`assert_all_dry_run_passed`).
- **Rollback on partial failure** — if execution partially fails, the already-succeeded artifacts
  are rolled back (`artifacts_requiring_rollback`).

All per-finding invariants (H1-H6 + the action-specific guards) still apply to each artifact.
