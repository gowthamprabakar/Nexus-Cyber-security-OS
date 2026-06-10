"""D.3 v0.2 Task 13 — forensic snapshot action tests (Q4/WI-R8 read-only invariant)."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from runtime_threat.actions.snapshot import (
    AUTHORIZED_ACTION_TYPES,
    SnapshotAction,
    UnauthorizedActionError,
    assert_authorized,
    request_workload_snapshot,
)

_T = datetime(2026, 6, 10, 12, 0, 0, tzinfo=UTC)


def test_request_builds_snapshot_action() -> None:
    a = request_workload_snapshot("host-1", "c1", reason="suspicious shell", requested_at=_T)
    assert isinstance(a, SnapshotAction)
    assert a.host_id == "host-1" and a.container_id == "c1"
    assert a.reason == "suspicious shell" and a.requested_at == "2026-06-10T12:00:00+00:00"


def test_action_is_snapshot_and_read_only() -> None:
    a = request_workload_snapshot("h", "c", reason="r", requested_at=_T)
    assert a.action_type == "snapshot" and a.is_read_only is True


def test_requires_a_target() -> None:
    with pytest.raises(ValueError, match="host_id or container_id"):
        request_workload_snapshot("", "", reason="r", requested_at=_T)


def test_only_snapshot_authorized() -> None:
    assert frozenset({"snapshot"}) == AUTHORIZED_ACTION_TYPES
    assert_authorized("snapshot")  # no raise


def test_kill_is_unauthorized() -> None:
    with pytest.raises(UnauthorizedActionError, match="Remediation cycle"):
        assert_authorized("kill")


def test_quarantine_is_unauthorized() -> None:
    with pytest.raises(UnauthorizedActionError, match="not authorized"):
        assert_authorized("quarantine")


def test_module_exposes_no_kill_or_quarantine() -> None:
    # WI-R8/WI-R9: the action surface has no kill/quarantine emitter at v0.2.
    import runtime_threat.actions.snapshot as mod

    assert not hasattr(mod, "request_process_kill")
    assert not hasattr(mod, "request_quarantine")
