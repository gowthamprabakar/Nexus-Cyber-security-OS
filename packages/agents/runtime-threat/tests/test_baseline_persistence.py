"""D.3 v0.2 Task 12 — baseline persistence tests."""

from __future__ import annotations

from pathlib import Path

from runtime_threat.baseline.observer import BaselineObserver, WorkloadBaseline
from runtime_threat.baseline.persistence import BaselineStore


def _wb(wl: str) -> WorkloadBaseline:
    return WorkloadBaseline(
        wl, processes={"nginx", "sh"}, connections={"10.0.0.1:443"}, files={"/etc/passwd"}
    )


def test_save_load_round_trip(tmp_path: Path) -> None:
    store = BaselineStore(tmp_path)
    store.save("acme", [_wb("c1")])
    loaded = store.load("acme")
    assert set(loaded) == {"c1"}
    assert loaded["c1"].processes == {"nginx", "sh"}
    assert loaded["c1"].connections == {"10.0.0.1:443"} and loaded["c1"].files == {"/etc/passwd"}


def test_multiple_workloads(tmp_path: Path) -> None:
    store = BaselineStore(tmp_path)
    store.save("acme", [_wb("c1"), _wb("c2")])
    assert set(store.load("acme")) == {"c1", "c2"}


def test_per_customer_isolation(tmp_path: Path) -> None:
    store = BaselineStore(tmp_path)
    store.save("acme", [_wb("c1")])
    store.save("globex", [_wb("c9")])
    assert set(store.load("acme")) == {"c1"}
    assert set(store.load("globex")) == {"c9"}


def test_load_missing_returns_empty(tmp_path: Path) -> None:
    store = BaselineStore(tmp_path)
    assert store.load("nobody") == {}
    assert store.exists("nobody") is False


def test_exists_after_save(tmp_path: Path) -> None:
    store = BaselineStore(tmp_path)
    store.save("acme", [_wb("c1")])
    assert store.exists("acme") is True


def test_save_creates_root_dir(tmp_path: Path) -> None:
    store = BaselineStore(tmp_path / "nested" / "dir")
    path = store.save("acme", [_wb("c1")])
    assert path.is_file()


def test_round_trip_from_observer(tmp_path: Path) -> None:
    obs = BaselineObserver()
    obs.observe_process("c1", "redis")
    obs.observe_file("c1", "/data/db")
    store = BaselineStore(tmp_path)
    store.save("acme", [obs.baseline("c1")])
    loaded = store.load("acme")
    assert loaded["c1"].processes == {"redis"} and loaded["c1"].files == {"/data/db"}
