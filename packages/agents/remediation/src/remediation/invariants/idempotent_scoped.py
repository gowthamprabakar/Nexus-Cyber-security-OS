"""H6 — idempotent + workspace-scoped invariant (remediation v0.2 Task 7, WI-A13).

Per **H6** every remediation artifact is (a) **idempotent** — its ``correlation_id`` derives from
the source finding id, so re-running the same finding produces the same correlation and never a
duplicate mutation — and (b) **workspace-scoped** — every output lands inside the contract
workspace, never elsewhere on disk. ``assert_idempotent_workspace_scoped`` is the hard guard:
a correlation_id not derived from the finding id, or an artifact path outside the workspace, raises.
"""

from __future__ import annotations

from pathlib import Path


class IdempotenceViolationError(RuntimeError):
    """Raised when an artifact is not idempotent or not workspace-scoped (WI-A13/H6)."""


def assert_idempotent_workspace_scoped(
    *,
    correlation_id: str,
    source_finding_id: str,
    artifact_path: str | Path,
    workspace_root: str | Path,
) -> None:
    """Hard guard — raise if the correlation_id is not finding-derived OR the path escapes the
    workspace (H6/WI-A13)."""
    if not source_finding_id or source_finding_id not in correlation_id:
        raise IdempotenceViolationError(
            f"correlation_id {correlation_id!r} is not derived from source finding "
            f"{source_finding_id!r}; idempotence requires finding-derived correlation (H6/WI-A13)."
        )
    root = Path(workspace_root).resolve()
    resolved = Path(artifact_path).resolve()
    if not resolved.is_relative_to(root):
        raise IdempotenceViolationError(
            f"artifact path {resolved} is outside the contract workspace {root}; every output "
            f"must land inside the workspace (H6/WI-A13)."
        )
