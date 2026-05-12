"""Tests for `audit.agent.run` (F.6 Task 12).

Production contract:

- Multi-source fan-out via `asyncio.TaskGroup` (mirrors D.3's three-feed
  pattern). Sources: zero or more jsonl paths + optional F.5
  `episodes`-table reader via `memory_session_factory`.
- Ingests via `AuditStore.ingest` (idempotent on (tenant_id, entry_hash)).
- Verifies each source's chain — jsonl sources sequentially, memory
  source non-sequentially. Both reports are written into the workspace
  alongside the query result.
- Returns the typed `AuditQueryResult` for the operator's filter.
- Writes `report.md` + `events.json` + `audit.jsonl` to the workspace.
- **Always-on budget exception (ADR-007 v1.3 candidate):** the driver
  honours only `wall_clock_sec` from the contract's `BudgetSpec`.
  Every other budget axis logs a structlog warning when exceeded and
  proceeds. F.6 is the first agent in the always-on class.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import pytest_asyncio
from audit.agent import run as audit_run
from audit.store import AuditStore
from charter.contract import BudgetSpec, ExecutionContract
from charter.memory.episodic import EpisodicStore
from charter.memory.models import Base
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)


@pytest_asyncio.fixture
async def engine() -> AsyncIterator[AsyncEngine]:
    eng = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield eng
    await eng.dispose()


@pytest_asyncio.fixture
async def session_factory(
    engine: AsyncEngine,
) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, expire_on_commit=False)


@pytest_asyncio.fixture
async def audit_store(
    session_factory: async_sessionmaker[AsyncSession],
) -> AuditStore:
    return AuditStore(session_factory)


_TENANT_A = "01HV0T0000000000000000TENA"


def _contract(workspace: Path, *, wall_clock_sec: float = 60.0) -> ExecutionContract:
    return ExecutionContract(
        schema_version="0.1",
        delegation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
        source_agent="supervisor",
        target_agent="audit",
        customer_id=_TENANT_A,
        task="Audit query",
        required_outputs=["report.md", "events.json"],
        budget=BudgetSpec(
            llm_calls=1,
            tokens=1,
            wall_clock_sec=wall_clock_sec,
            cloud_api_calls=10,
            mb_written=10,
        ),
        permitted_tools=["audit_jsonl_read", "episode_audit_read"],
        completion_condition="report.md exists",
        escalation_rules=[],
        workspace=str(workspace / "ws"),
        persistent_root=str(workspace / "p"),
        created_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(hours=1),
    )


def _write_audit_jsonl_chain(path: Path, *, n: int = 3) -> None:
    """Build a real, hash-chained audit.jsonl file."""
    from charter.audit import GENESIS_HASH, _hash_entry

    lines: list[str] = []
    previous = GENESIS_HASH
    base = datetime(2026, 5, 1, tzinfo=UTC)
    for i in range(n):
        emitted = (base + timedelta(seconds=i)).isoformat().replace("+00:00", "Z")
        payload = {"i": i}
        entry_hash = _hash_entry(
            timestamp=emitted,
            agent="cloud_posture",
            run_id=f"corr-{i:03d}",
            action="episode_appended",
            payload=payload,
            previous_hash=previous,
        )
        lines.append(
            json.dumps(
                {
                    "timestamp": emitted,
                    "agent": "cloud_posture",
                    "run_id": f"corr-{i:03d}",
                    "action": "episode_appended",
                    "payload": payload,
                    "previous_hash": previous,
                    "entry_hash": entry_hash,
                }
            )
        )
        previous = entry_hash
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


# ---------------------------- empty source set --------------------------


@pytest.mark.asyncio
async def test_run_with_no_sources_returns_empty_result(
    tmp_path: Path,
    audit_store: AuditStore,
) -> None:
    contract = _contract(tmp_path)
    result = await audit_run(
        contract,
        audit_store=audit_store,
        sources=(),
        memory_session_factory=None,
    )
    assert result.total == 0
    # Workspace artifacts still emitted so the contract's
    # `required_outputs` is satisfied.
    assert (Path(contract.workspace) / "report.md").is_file()
    assert (Path(contract.workspace) / "events.json").is_file()


# ---------------------------- file-only -------------------------------


@pytest.mark.asyncio
async def test_run_file_only_ingests_and_queries(
    tmp_path: Path,
    audit_store: AuditStore,
) -> None:
    feed = tmp_path / "audit.jsonl"
    _write_audit_jsonl_chain(feed, n=3)

    contract = _contract(tmp_path)
    result = await audit_run(
        contract,
        audit_store=audit_store,
        sources=(feed,),
        memory_session_factory=None,
    )
    assert result.total == 3


# ---------------------------- memory-only -----------------------------


@pytest.mark.asyncio
async def test_run_memory_only_ingests_episodes(
    tmp_path: Path,
    audit_store: AuditStore,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    episodic = EpisodicStore(session_factory)
    for i in range(2):
        await episodic.append_event(
            tenant_id=_TENANT_A,
            correlation_id=f"corr-{i}",
            agent_id="cloud_posture",
            action="finding.created",
            payload={"i": i},
        )

    contract = _contract(tmp_path)
    result = await audit_run(
        contract,
        audit_store=audit_store,
        sources=(),
        memory_session_factory=session_factory,
    )
    assert result.total == 2


# ---------------------------- file + memory merge ---------------------


@pytest.mark.asyncio
async def test_run_file_and_memory_merge(
    tmp_path: Path,
    audit_store: AuditStore,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    feed = tmp_path / "audit.jsonl"
    _write_audit_jsonl_chain(feed, n=2)

    episodic = EpisodicStore(session_factory)
    await episodic.append_event(
        tenant_id=_TENANT_A,
        correlation_id="from-memory",
        agent_id="runtime_threat",
        action="finding.created",
        payload={"src": "memory"},
    )

    contract = _contract(tmp_path)
    result = await audit_run(
        contract,
        audit_store=audit_store,
        sources=(feed,),
        memory_session_factory=session_factory,
    )
    # 2 jsonl + 1 memory = 3.
    assert result.total == 3


# ---------------------------- query filters ---------------------------


@pytest.mark.asyncio
async def test_run_honours_time_window(
    tmp_path: Path,
    audit_store: AuditStore,
) -> None:
    feed = tmp_path / "audit.jsonl"
    _write_audit_jsonl_chain(feed, n=3)

    contract = _contract(tmp_path)
    # Empty window (after data).
    result = await audit_run(
        contract,
        audit_store=audit_store,
        sources=(feed,),
        memory_session_factory=None,
        since=datetime(2026, 6, 1, tzinfo=UTC),
        until=datetime(2026, 6, 30, tzinfo=UTC),
    )
    assert result.total == 0


@pytest.mark.asyncio
async def test_run_honours_agent_id_filter(
    tmp_path: Path,
    audit_store: AuditStore,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    episodic = EpisodicStore(session_factory)
    await episodic.append_event(
        tenant_id=_TENANT_A,
        correlation_id="c1",
        agent_id="cloud_posture",
        action="x",
        payload={},
    )
    await episodic.append_event(
        tenant_id=_TENANT_A,
        correlation_id="c2",
        agent_id="runtime_threat",
        action="x",
        payload={},
    )

    contract = _contract(tmp_path)
    result = await audit_run(
        contract,
        audit_store=audit_store,
        sources=(),
        memory_session_factory=session_factory,
        agent_id="runtime_threat",
    )
    assert result.total == 1
    assert result.events[0].agent_id == "runtime_threat"


# ---------------------------- always-on budget exception -------------


@pytest.mark.asyncio
async def test_run_logs_warning_when_non_wall_clock_budget_overrun(
    tmp_path: Path,
    audit_store: AuditStore,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The driver's always-on bit: a non-wall-clock budget overrun must
    log a warning and **not** raise. Other agents would raise
    BudgetExhausted; F.6 alone is allowed to proceed.
    """
    import logging

    feed = tmp_path / "audit.jsonl"
    _write_audit_jsonl_chain(feed, n=3)

    contract = _contract(tmp_path)
    with caplog.at_level(logging.WARNING):
        result = await audit_run(
            contract,
            audit_store=audit_store,
            sources=(feed,),
            memory_session_factory=None,
            simulate_budget_overrun_dim="mb_written",
        )
    # Run still produced a result.
    assert result.total == 3
    # Warning fired with the budget-axis name.
    assert any("mb_written" in r.getMessage() for r in caplog.records)


@pytest.mark.asyncio
async def test_run_raises_on_wall_clock_overrun(
    tmp_path: Path,
    audit_store: AuditStore,
) -> None:
    """`wall_clock_sec` is the **only** budget axis that still stops the
    Audit Agent — a runaway query must be killable.
    """
    from charter.exceptions import BudgetExhausted

    contract = _contract(tmp_path)
    with pytest.raises(BudgetExhausted) as exc_info:
        await audit_run(
            contract,
            audit_store=audit_store,
            sources=(),
            memory_session_factory=None,
            simulate_budget_overrun_dim="wall_clock_sec",
        )
    assert exc_info.value.dimension == "wall_clock_sec"


# ---------------------------- chain integrity emitted ---------------


@pytest.mark.asyncio
async def test_run_writes_chain_integrity_into_report(
    tmp_path: Path,
    audit_store: AuditStore,
) -> None:
    feed = tmp_path / "audit.jsonl"
    _write_audit_jsonl_chain(feed, n=2)

    contract = _contract(tmp_path)
    await audit_run(
        contract,
        audit_store=audit_store,
        sources=(feed,),
        memory_session_factory=None,
    )

    report = (Path(contract.workspace) / "report.md").read_text()
    assert "## Chain integrity" in report
    assert "Chain valid" in report
