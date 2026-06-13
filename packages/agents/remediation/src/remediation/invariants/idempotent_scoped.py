"""H6 — idempotent + workspace-scoped invariant (remediation v0.2 Task 7, WI-A13).

Per **H6** every remediation artifact is (a) **idempotent** — its ``correlation_id`` is the
**deterministic hash-derivation** of the source finding (``corr-<sha256(key)[:16]>``, see
``action_classes.correlation_id_for``), so re-running the same finding yields the same correlation
and never a duplicate mutation — and (b) **workspace-scoped** — every output lands inside the
contract workspace, never elsewhere on disk. ``assert_idempotent_workspace_scoped`` is the hard
guard.

Phase C SS6 PR3 (Option a): the derivation check verifies the deterministic HASH-DERIVED FORMAT (a
sha256 digest, not an arbitrary/random id) rather than a literal substring of the finding id. The
generator hashes a composite key (``namespace/name/.../rule``), so the raw finding id is
intentionally NOT a substring of the digest — the pre-SS6 substring check could never have matched
the real correlation ids and so could not be wired into run() without this reconciliation.
"""

from __future__ import annotations

import re
from pathlib import Path

#: The deterministic correlation-id shape emitted by ``correlation_id_for``: ``corr-`` + a
#: 16-char lowercase-hex sha256 prefix. An id of this shape is provably derived (not arbitrary).
_HASH_DERIVED_CORRELATION_RE = re.compile(r"^corr-[0-9a-f]{16}$")


class IdempotenceViolationError(RuntimeError):
    """Raised when an artifact is not idempotent or not workspace-scoped (WI-A13/H6)."""


def assert_idempotent_workspace_scoped(
    *,
    correlation_id: str,
    source_finding_id: str,
    artifact_path: str | Path,
    workspace_root: str | Path,
) -> None:
    """Hard guard — raise if the source-finding lineage is missing, the correlation_id is not a
    deterministic hash-derived id, OR the artifact path escapes the workspace (H6/WI-A13)."""
    if not source_finding_id:
        raise IdempotenceViolationError(
            "source finding id is missing; idempotence requires the artifact to carry its "
            "finding lineage (H6/WI-A13)."
        )
    if not _HASH_DERIVED_CORRELATION_RE.match(correlation_id):
        raise IdempotenceViolationError(
            f"correlation_id {correlation_id!r} is not a deterministic hash-derived id "
            f"(expected 'corr-<16 hex>' per correlation_id_for); idempotence requires a derived "
            f"correlation so re-running a finding never double-applies, never an arbitrary id "
            f"(H6/WI-A13)."
        )
    root = Path(workspace_root).resolve()
    resolved = Path(artifact_path).resolve()
    if not resolved.is_relative_to(root):
        raise IdempotenceViolationError(
            f"artifact path {resolved} is outside the contract workspace {root}; every output "
            f"must land inside the workspace (H6/WI-A13)."
        )
