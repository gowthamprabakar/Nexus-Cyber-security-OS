"""Batch-level safety primitives (remediation v0.2 Task 14, Q5/WI-A12).

Batched remediation applies the same per-finding safety primitives as a single run, plus two
batch-level guarantees:

1. **Atomic dry-run-first** — EVERY artifact must pass ``kubectl --dry-run=server`` before ANY
   artifact executes; a single dry-run failure aborts the whole batch (no partial mutation).
2. **Rollback on partial failure** — if execution partially fails, the artifacts that already
   succeeded are rolled back, so the batch is all-or-nothing.

Pure + deterministic over caller-supplied per-artifact results.
"""

from __future__ import annotations

from collections.abc import Mapping


class BatchAbortError(RuntimeError):
    """Raised when a batch must abort before execute because an artifact failed dry-run (WI-A12)."""


def assert_all_dry_run_passed(dry_run_results: Mapping[str, bool]) -> None:
    """Atomicity — raise if ANY artifact failed dry-run (abort before any execute).

    ``dry_run_results`` maps artifact correlation_id -> dry-run success. One failure aborts the
    entire batch so no artifact is partially applied.
    """
    failed = sorted(cid for cid, ok in dry_run_results.items() if not ok)
    if failed:
        raise BatchAbortError(
            f"batch aborted before execute: {len(failed)} artifact(s) failed dry-run {failed}; "
            f"a batch is all-or-nothing (Q5/WI-A12)."
        )


def artifacts_requiring_rollback(execution_results: Mapping[str, bool]) -> tuple[str, ...]:
    """On partial execute failure, the artifacts to roll back (the ones that already succeeded).

    Full success -> empty tuple (nothing to roll back). Any failure -> the succeeded artifacts,
    sorted, so the batch reverts to its pre-execute state (all-or-nothing).
    """
    if all(execution_results.values()):
        return ()
    return tuple(sorted(cid for cid, ok in execution_results.items() if ok))
