"""supervisor v0.2 Task 12 — queue drainer + crash recovery tests (Q5)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from supervisor.queue.drainer import QueueDrainer
from supervisor.queue.sqlite_store import SqliteQueueStore


def _seeded(tmp_path: Path, task_ids: list[str]) -> Path:
    db = tmp_path / "queue.db"
    store = SqliteQueueStore(db)
    for tid in task_ids:
        store.enqueue(customer_id="c1", task={"task_id": tid})
    store.close()
    return db


def test_claim_next_oldest(tmp_path: Path) -> None:
    drainer = QueueDrainer(_seeded(tmp_path, ["t0", "t1"]))
    claimed = drainer.claim_next(customer_id="c1")
    assert claimed is not None and claimed.task["task_id"] == "t0"


def test_claim_marks_in_progress(tmp_path: Path) -> None:
    drainer = QueueDrainer(_seeded(tmp_path, ["t0"]))
    drainer.claim_next(customer_id="c1")
    # The claimed task is not handed out again until recovered.
    assert drainer.claim_next(customer_id="c1") is None


def test_complete_deletes(tmp_path: Path) -> None:
    drainer = QueueDrainer(_seeded(tmp_path, ["t0"]))
    claimed = drainer.claim_next(customer_id="c1")
    assert claimed is not None
    drainer.complete(claimed.seq)
    assert drainer.recover_claimed(customer_id="c1") == 0  # nothing left to recover


@pytest.mark.asyncio
async def test_drain_processes_all_in_order(tmp_path: Path) -> None:
    drainer = QueueDrainer(_seeded(tmp_path, ["t0", "t1", "t2"]))
    seen: list[str] = []

    async def _process(task: dict[str, Any]) -> None:
        seen.append(task["task_id"])

    summary = await drainer.drain(customer_id="c1", process=_process)
    assert seen == ["t0", "t1", "t2"] and summary.drained == 3 and summary.recovered == 0


@pytest.mark.asyncio
async def test_crash_recovery_redequeues(tmp_path: Path) -> None:
    db = _seeded(tmp_path, ["t0", "t1"])

    # "Crash": process the first task by raising before completion.
    crasher = QueueDrainer(db)

    async def _boom(task: dict[str, Any]) -> None:
        raise RuntimeError("crash mid-process")

    with pytest.raises(RuntimeError):
        await crasher.drain(customer_id="c1", process=_boom)
    crasher.close()

    # "Restart": a fresh drainer recovers the claimed task + reprocesses everything.
    restarted = QueueDrainer(db)
    seen: list[str] = []

    async def _process(task: dict[str, Any]) -> None:
        seen.append(task["task_id"])

    summary = await restarted.drain(customer_id="c1", process=_process)
    assert summary.recovered == 1  # the claimed-but-not-completed t0
    assert set(seen) == {"t0", "t1"}  # nothing lost


@pytest.mark.asyncio
async def test_drain_empty(tmp_path: Path) -> None:
    db = tmp_path / "queue.db"
    SqliteQueueStore(db).close()
    drainer = QueueDrainer(db)

    async def _process(task: dict[str, Any]) -> None:  # pragma: no cover - never called
        raise AssertionError("should not process")

    summary = await drainer.drain(customer_id="c1", process=_process)
    assert summary.drained == 0 and summary.recovered == 0


def test_recover_claimed_resets(tmp_path: Path) -> None:
    drainer = QueueDrainer(_seeded(tmp_path, ["t0", "t1"]))
    drainer.claim_next(customer_id="c1")
    assert drainer.recover_claimed(customer_id="c1") == 1
    # After recovery, the task is claimable again.
    assert drainer.claim_next(customer_id="c1") is not None
