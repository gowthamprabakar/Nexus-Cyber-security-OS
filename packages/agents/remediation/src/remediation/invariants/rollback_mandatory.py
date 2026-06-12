"""H4 — mandatory-rollback-on-failed-validation invariant (remediation v0.2 Task 5, WI-A11).

Per **H4**, after an execute the agent waits ``rollback_window_sec``, re-runs the source detector,
and **auto-reverts** if the finding still fires (the fix did not hold). When validation requires a
rollback, the rollback is **mandatory** — there is no override. ``assert_rollback_on_failed_
validation`` is the hard guard called at HANDOFF before ``assert_complete()``: if validation
required a rollback but none was executed, it raises.
"""

from __future__ import annotations


class RollbackSkippedError(RuntimeError):
    """Raised when a required rollback was not executed (WI-A11/H4)."""


def assert_rollback_on_failed_validation(
    *,
    requires_rollback: bool,
    rollback_executed: bool,
) -> None:
    """Hard guard — raise if ``requires_rollback`` but ``rollback_executed`` is False (H4/WI-A11).

    Rollback is mandatory when post-execute validation says the fix did not hold; no override.
    """
    if requires_rollback and not rollback_executed:
        raise RollbackSkippedError(
            "post-execute validation required a rollback, but none was executed; rollback is "
            "mandatory when validation fails (H4/WI-A11)."
        )
