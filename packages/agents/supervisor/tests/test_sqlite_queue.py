"""supervisor v0.2 Task 11 — SQLite-backed scheduled queue tests (Q5)."""

from __future__ import annotations

from pathlib import Path

import pytest
from supervisor.queue.sqlite_store import SqliteQueueError, SqliteQueueStore


def _store(tmp_path: Path) -> SqliteQueueStore:
    return SqliteQueueStore(tmp_path / "queue.db")


def test_wal_mode_enabled(tmp_path: Path) -> None:
    assert _store(tmp_path).journal_mode == "wal"


def test_enqueue_then_peek(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.enqueue(customer_id="c1", task={"task_id": "t1", "priority": 5})
    tasks = store.peek(customer_id="c1")
    assert len(tasks) == 1 and tasks[0]["task_id"] == "t1" and tasks[0]["priority"] == 5


def test_missing_task_id_rejected(tmp_path: Path) -> None:
    with pytest.raises(SqliteQueueError, match="task_id"):
        _store(tmp_path).enqueue(customer_id="c1", task={"priority": 1})


def test_duplicate_task_id_rejected(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.enqueue(customer_id="c1", task={"task_id": "t1"})
    with pytest.raises(SqliteQueueError, match="already present"):
        store.enqueue(customer_id="c1", task={"task_id": "t1"})


def test_fifo_order(tmp_path: Path) -> None:
    store = _store(tmp_path)
    for i in range(4):
        store.enqueue(customer_id="c1", task={"task_id": f"t{i}"})
    assert [t["task_id"] for t in store.peek(customer_id="c1")] == ["t0", "t1", "t2", "t3"]


def test_drain_returns_and_empties(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.enqueue(customer_id="c1", task={"task_id": "t1"})
    store.enqueue(customer_id="c1", task={"task_id": "t2"})
    drained = store.drain(customer_id="c1")
    assert [t["task_id"] for t in drained] == ["t1", "t2"]
    assert store.peek(customer_id="c1") == []


def test_tenant_isolation(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.enqueue(customer_id="c1", task={"task_id": "t1"})
    store.enqueue(customer_id="c2", task={"task_id": "t1"})  # same id, different customer ok
    assert len(store.peek(customer_id="c1")) == 1
    assert store.drain(customer_id="c1") and store.peek(customer_id="c2")  # c2 untouched


def test_import_tasks_skips_duplicates(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.enqueue(customer_id="c1", task={"task_id": "t1"})
    imported = store.import_tasks(
        [{"task_id": "t1"}, {"task_id": "t2"}, {"task_id": "t3"}], customer_id="c1"
    )
    assert imported == 2  # t1 already present -> skipped
    assert len(store.peek(customer_id="c1")) == 3


def test_durability_across_reopen(tmp_path: Path) -> None:
    db = tmp_path / "queue.db"
    store = SqliteQueueStore(db)
    store.enqueue(customer_id="c1", task={"task_id": "t1"})
    store.close()
    # Reopen the same DB file -> the enqueued task is still there (durable).
    reopened = SqliteQueueStore(db)
    assert [t["task_id"] for t in reopened.peek(customer_id="c1")] == ["t1"]


def test_empty(tmp_path: Path) -> None:
    store = _store(tmp_path)
    assert store.peek(customer_id="c1") == [] and store.drain(customer_id="c1") == []
