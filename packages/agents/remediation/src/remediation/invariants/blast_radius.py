"""H5 — blast-radius cap invariant (remediation v0.2 Task 6, WI-A12).

Per **H5** a single run applies at most ``max_actions_per_run`` actions (auth.yaml default 5),
and there is a **hard ceiling of 50** no per-run config can exceed. ``assert_blast_radius_capped``
is the hard guard called at the AUTHZ stage (before action accumulation): it raises if the
authorized action count exceeds ``min(max_per_run, 50)``. The effective cap is the smaller of the
operator's per-run config and the institutional ceiling.
"""

from __future__ import annotations

#: The institutional hard ceiling — no per-run config may exceed this.
HARD_CEILING = 50


class BlastRadiusViolationError(RuntimeError):
    """Raised when a run's action count exceeds the effective blast-radius cap (WI-A12/H5)."""


def effective_cap(max_per_run: int) -> int:
    """The effective cap — the smaller of the per-run config and the hard ceiling of 50."""
    return min(max_per_run, HARD_CEILING)


def assert_blast_radius_capped(action_count: int, max_per_run: int) -> None:
    """Hard guard — raise if ``action_count`` exceeds ``min(max_per_run, 50)`` (H5/WI-A12)."""
    cap = effective_cap(max_per_run)
    if action_count > cap:
        raise BlastRadiusViolationError(
            f"run would apply {action_count} actions, exceeding the effective blast-radius cap of "
            f"{cap} (per-run config {max_per_run}, hard ceiling {HARD_CEILING}) (H5/WI-A12)."
        )
