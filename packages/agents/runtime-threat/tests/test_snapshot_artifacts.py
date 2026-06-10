"""D.3 v0.2 Task 14 — snapshot artifact handling tests."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from runtime_threat.actions.artifacts import SnapshotArtifact, SnapshotArtifactStore
from runtime_threat.actions.snapshot import request_workload_snapshot

_T = datetime(2026, 6, 10, 12, 0, 0, tzinfo=UTC)


def _action() -> object:
    return request_workload_snapshot("host-1", "c1", reason="shell", requested_at=_T)


def test_store_returns_artifact_reference(tmp_path: Path) -> None:
    store = SnapshotArtifactStore(tmp_path)
    art = store.store(
        _action(), snapshot_id="snap1", audit_ref="audit:abc", data="procs...", created_at=_T
    )
    assert isinstance(art, SnapshotArtifact)
    assert art.snapshot_id == "snap1" and art.audit_ref == "audit:abc"
    assert art.host_id == "host-1" and art.container_id == "c1"
    assert Path(art.artifact_path).is_file()


def test_load_metadata_round_trip(tmp_path: Path) -> None:
    store = SnapshotArtifactStore(tmp_path)
    store.store(_action(), snapshot_id="snap1", audit_ref="audit:abc", data="x", created_at=_T)
    meta = store.load("snap1")
    assert meta is not None and meta.audit_ref == "audit:abc" and meta.container_id == "c1"


def test_read_data(tmp_path: Path) -> None:
    store = SnapshotArtifactStore(tmp_path)
    store.store(_action(), snapshot_id="snap1", audit_ref="a", data="captured-state", created_at=_T)
    assert store.read_data("snap1") == "captured-state"


def test_load_missing_returns_none(tmp_path: Path) -> None:
    store = SnapshotArtifactStore(tmp_path)
    assert store.load("nope") is None and store.read_data("nope") is None


def test_list_artifacts(tmp_path: Path) -> None:
    store = SnapshotArtifactStore(tmp_path)
    store.store(_action(), snapshot_id="snap1", audit_ref="a", data="x", created_at=_T)
    store.store(_action(), snapshot_id="snap2", audit_ref="b", data="y", created_at=_T)
    assert store.list_artifacts() == ("snap1", "snap2")


def test_store_creates_root(tmp_path: Path) -> None:
    store = SnapshotArtifactStore(tmp_path / "nested")
    store.store(_action(), snapshot_id="snap1", audit_ref="a", data="x", created_at=_T)
    assert store.read_data("snap1") == "x"


def test_store_is_write_once_read_only_api() -> None:
    # Captured evidence is immutable — no update/delete surface.
    assert not hasattr(SnapshotArtifactStore, "update")
    assert not hasattr(SnapshotArtifactStore, "delete")
