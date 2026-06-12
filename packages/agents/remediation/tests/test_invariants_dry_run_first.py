"""remediation v0.2 Task 4 — assert_dry_run_before_execute tests (WI-A10/H3)."""

from __future__ import annotations

import pytest
from remediation.invariants.dry_run_first import (
    MissingDryRunError,
    assert_dry_run_before_execute,
)


def test_dry_run_then_execute_ok() -> None:
    assert_dry_run_before_execute(["ingest", "authz", "generate", "dry_run", "execute"])


def test_recommend_only_ok() -> None:
    assert_dry_run_before_execute(["ingest", "authz", "generate"])


def test_dry_run_only_ok() -> None:
    assert_dry_run_before_execute(["ingest", "authz", "generate", "dry_run"])


def test_execute_without_dry_run_raises() -> None:
    with pytest.raises(MissingDryRunError, match="mandatory dry-run"):
        assert_dry_run_before_execute(["ingest", "authz", "generate", "execute"])


def test_dry_run_after_execute_raises() -> None:
    # order matters: a dry_run recorded after execute does not satisfy the guard.
    with pytest.raises(MissingDryRunError):
        assert_dry_run_before_execute(["generate", "execute", "dry_run"])


def test_empty_history_ok() -> None:
    assert_dry_run_before_execute([])
