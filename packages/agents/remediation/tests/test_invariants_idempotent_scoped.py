"""remediation v0.2 Task 7 — assert_idempotent_workspace_scoped tests (WI-A13/H6).

Phase C SS6 PR3 (Option a): the derivation check now verifies the deterministic HASH-DERIVED format
(``corr-<16 hex>`` per ``correlation_id_for``), not a literal substring of the finding id — the
generator hashes a composite key, so the raw finding id is never a substring of the digest.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from remediation.action_classes._common import correlation_id_for
from remediation.invariants.idempotent_scoped import (
    IdempotenceViolationError,
    assert_idempotent_workspace_scoped,
)

_DERIVED = correlation_id_for("production/frontend/nginx/run-as-root")  # a real corr-<16hex> id


def test_hash_derived_and_scoped_ok(tmp_path: Path) -> None:
    assert_idempotent_workspace_scoped(
        correlation_id=_DERIVED,
        source_finding_id="run-as-root",
        artifact_path=tmp_path / "ws" / "artifacts" / f"{_DERIVED}.json",
        workspace_root=tmp_path / "ws",
    )


def test_non_derived_correlation_raises(tmp_path: Path) -> None:
    with pytest.raises(IdempotenceViolationError, match="hash-derived"):
        assert_idempotent_workspace_scoped(
            correlation_id="random-uuid",
            source_finding_id="run-as-root",
            artifact_path=tmp_path / "ws" / "patch.json",
            workspace_root=tmp_path / "ws",
        )


def test_wrong_shape_correlation_raises(tmp_path: Path) -> None:
    # Right prefix, wrong digest length / charset → not a deterministic derived id.
    with pytest.raises(IdempotenceViolationError, match="hash-derived"):
        assert_idempotent_workspace_scoped(
            correlation_id="corr-NOTHEX",
            source_finding_id="run-as-root",
            artifact_path=tmp_path / "ws" / "patch.json",
            workspace_root=tmp_path / "ws",
        )


def test_empty_finding_id_raises(tmp_path: Path) -> None:
    with pytest.raises(IdempotenceViolationError, match="finding lineage"):
        assert_idempotent_workspace_scoped(
            correlation_id=_DERIVED,
            source_finding_id="",
            artifact_path=tmp_path / "ws" / "p.json",
            workspace_root=tmp_path / "ws",
        )


def test_path_outside_workspace_raises(tmp_path: Path) -> None:
    with pytest.raises(IdempotenceViolationError, match="outside the contract workspace"):
        assert_idempotent_workspace_scoped(
            correlation_id=_DERIVED,
            source_finding_id="run-as-root",
            artifact_path=tmp_path / "elsewhere" / "patch.json",
            workspace_root=tmp_path / "ws",
        )


def test_path_traversal_escape_raises(tmp_path: Path) -> None:
    with pytest.raises(IdempotenceViolationError):
        assert_idempotent_workspace_scoped(
            correlation_id=_DERIVED,
            source_finding_id="run-as-root",
            artifact_path=tmp_path / "ws" / ".." / "secret.json",
            workspace_root=tmp_path / "ws",
        )
