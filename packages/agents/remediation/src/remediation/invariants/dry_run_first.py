"""H3 — mandatory-dry-run-before-execute invariant (remediation v0.2 Task 4, WI-A10).

Per **H3** the EXECUTE stage (Stage 5 — the only one that mutates the cluster) is reachable only
after a **successful** DRY-RUN stage (Stage 4, ``kubectl --dry-run=server``). A failed Stage-4
dry-run aborts before Stage 5. ``assert_dry_run_before_execute`` is the hard guard called at the
EXECUTE stage entry: it inspects the per-artifact stage history and raises if EXECUTE was reached
without a prior successful DRY-RUN.
"""

from __future__ import annotations

from collections.abc import Sequence

#: Stage tokens recorded in an artifact's history.
STAGE_DRY_RUN = "dry_run"
STAGE_EXECUTE = "execute"


class MissingDryRunError(RuntimeError):
    """Raised when EXECUTE is reached without a prior successful DRY-RUN (WI-A10/H3)."""


def assert_dry_run_before_execute(stage_history: Sequence[str]) -> None:
    """Hard guard — raise if ``execute`` appears without a preceding ``dry_run`` (H3/WI-A10).

    ``stage_history`` is the ordered list of successfully-completed stage tokens for one artifact.
    Order matters: a ``dry_run`` recorded AFTER ``execute`` does not satisfy the guard.
    """
    if STAGE_EXECUTE not in stage_history:
        return
    execute_index = stage_history.index(STAGE_EXECUTE)
    if STAGE_DRY_RUN not in stage_history[:execute_index]:
        raise MissingDryRunError(
            "EXECUTE stage reached without a prior successful DRY-RUN; a mandatory dry-run must "
            "precede execute (H3/WI-A10)."
        )
