"""supervisor v0.2 Task 10 — new vocabulary emission integration tests (Q4/WI-O5)."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from charter.audit import AuditLog
from supervisor.audit_emit import (
    ACTION_DELEGATION_RETRIED,
    ACTION_PARALLEL_BATCH_STARTED,
    ACTION_QUEUE_DRAINED,
    ACTION_SEMAPHORE_WAIT,
    emit_delegation_retried,
    emit_parallel_batch_started,
    emit_queue_drained,
    emit_semaphore_wait,
)
from supervisor.schemas import DelegationContract


def _audit_log(tmp_path: Path) -> AuditLog:
    return AuditLog(tmp_path / "audit.jsonl", agent="supervisor", run_id="tick1")


def _read_entries(path: Path) -> list[dict[str, object]]:
    out: list[dict[str, object]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            out.append(json.loads(line))
    return out


def _contract() -> DelegationContract:
    return DelegationContract(
        delegation_id="d-1",
        customer_id="cust-1",
        target_agent="compliance",
        task_id="t-1",
        budget_wall_clock_sec=30.0,
        budget_max_tool_calls=100,
        created_at=datetime(2026, 6, 1, tzinfo=UTC),
    )


def test_emit_parallel_batch_started(tmp_path: Path) -> None:
    log = _audit_log(tmp_path)
    emit_parallel_batch_started(
        log, customer_id="cust-1", tick_id="tick-1", target_agents=["compliance", "audit"]
    )
    entry = _read_entries(log.path)[0]
    assert entry["action"] == ACTION_PARALLEL_BATCH_STARTED
    assert entry["payload"]["batch_size"] == 2


def test_emit_delegation_retried(tmp_path: Path) -> None:
    log = _audit_log(tmp_path)
    emit_delegation_retried(log, contract=_contract(), attempt=2, failure_class="transient")
    entry = _read_entries(log.path)[0]
    assert entry["action"] == ACTION_DELEGATION_RETRIED
    assert entry["payload"]["attempt"] == 2 and entry["payload"]["failure_class"] == "transient"


def test_emit_semaphore_wait(tmp_path: Path) -> None:
    log = _audit_log(tmp_path)
    emit_semaphore_wait(log, customer_id="cust-1", target_agent="audit", waited_sec=0.5, cap=4)
    entry = _read_entries(log.path)[0]
    assert entry["action"] == ACTION_SEMAPHORE_WAIT
    assert entry["payload"]["target_agent"] == "audit" and entry["payload"]["cap"] == 4


def test_emit_queue_drained(tmp_path: Path) -> None:
    log = _audit_log(tmp_path)
    emit_queue_drained(log, customer_id="cust-1", drained_count=7, queue_name="scheduled")
    entry = _read_entries(log.path)[0]
    assert entry["action"] == ACTION_QUEUE_DRAINED and entry["payload"]["drained_count"] == 7


def test_chain_links_preserved_across_new_emits(tmp_path: Path) -> None:
    # The new emitters share the append-only hash chain: each entry's previous_hash links to
    # the prior entry's entry_hash (F.6 chain integrity, unchanged).
    log = _audit_log(tmp_path)
    emit_parallel_batch_started(log, customer_id="c", tick_id="t", target_agents=["audit"])
    emit_delegation_retried(log, contract=_contract(), attempt=2, failure_class="transient")
    emit_queue_drained(log, customer_id="c", drained_count=1, queue_name="scheduled")
    entries = _read_entries(log.path)
    assert len(entries) == 3
    assert entries[1]["previous_hash"] == entries[0]["entry_hash"]
    assert entries[2]["previous_hash"] == entries[1]["entry_hash"]
