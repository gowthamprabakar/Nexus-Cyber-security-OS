"""remediation v0.2 Task 7 — assert_idempotent_workspace_scoped tests (WI-A13/H6)."""

from __future__ import annotations

from pathlib import Path

import pytest
from remediation.invariants.idempotent_scoped import (
    IdempotenceViolationError,
    assert_idempotent_workspace_scoped,
)


def test_derived_and_scoped_ok(tmp_path: Path) -> None:
    assert_idempotent_workspace_scoped(
        correlation_id="finding-F1-remediation",
        source_finding_id="F1",
        artifact_path=tmp_path / "ws" / "patch.yaml",
        workspace_root=tmp_path / "ws",
    )


def test_non_derived_correlation_raises(tmp_path: Path) -> None:
    with pytest.raises(IdempotenceViolationError, match="finding-derived correlation"):
        assert_idempotent_workspace_scoped(
            correlation_id="random-uuid",
            source_finding_id="F1",
            artifact_path=tmp_path / "ws" / "patch.yaml",
            workspace_root=tmp_path / "ws",
        )


def test_empty_finding_id_raises(tmp_path: Path) -> None:
    with pytest.raises(IdempotenceViolationError):
        assert_idempotent_workspace_scoped(
            correlation_id="anything",
            source_finding_id="",
            artifact_path=tmp_path / "ws" / "p.yaml",
            workspace_root=tmp_path / "ws",
        )


def test_path_outside_workspace_raises(tmp_path: Path) -> None:
    with pytest.raises(IdempotenceViolationError, match="outside the contract workspace"):
        assert_idempotent_workspace_scoped(
            correlation_id="finding-F1",
            source_finding_id="F1",
            artifact_path=tmp_path / "elsewhere" / "patch.yaml",
            workspace_root=tmp_path / "ws",
        )


def test_path_traversal_escape_raises(tmp_path: Path) -> None:
    with pytest.raises(IdempotenceViolationError):
        assert_idempotent_workspace_scoped(
            correlation_id="finding-F1",
            source_finding_id="F1",
            artifact_path=tmp_path / "ws" / ".." / "secret.yaml",
            workspace_root=tmp_path / "ws",
        )
