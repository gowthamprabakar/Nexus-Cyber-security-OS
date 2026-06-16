"""Tests for the runtime-threat knowledge-graph writer (v0.4 Stage 1.1).

Exercised end-to-end through ``agent.run()`` against a real in-memory
``SemanticStore`` (aiosqlite) — the runtime inventory the agent actually produces
lands in the fleet graph. Opt-in: default (no store) writes nothing.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
import pytest_asyncio
from charter.contract import BudgetSpec, ExecutionContract
from charter.memory.models import Base
from charter.memory.semantic import SemanticStore
from runtime_threat import agent as agent_mod
from runtime_threat.agent import run
from runtime_threat.tools.falco import FalcoAlert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

pytestmark = pytest.mark.asyncio

NOW = datetime(2026, 5, 11, tzinfo=UTC)
_TENANT = "cust_test"


def _contract(tmp_path: Path) -> ExecutionContract:
    return ExecutionContract(
        schema_version="0.1",
        delegation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
        source_agent="supervisor",
        target_agent="runtime_threat",
        customer_id=_TENANT,
        task="Runtime threat scan",
        required_outputs=["findings.json", "summary.md"],
        budget=BudgetSpec(
            llm_calls=5, tokens=10_000, wall_clock_sec=60.0, cloud_api_calls=10, mb_written=10
        ),
        permitted_tools=["falco_alerts_read", "tracee_alerts_read", "osquery_run"],
        completion_condition="findings.json AND summary.md exist",
        escalation_rules=[],
        workspace=str(tmp_path / "ws"),
        persistent_root=str(tmp_path / "p"),
        created_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )


def _patch_falco(monkeypatch: pytest.MonkeyPatch, alerts: Sequence[FalcoAlert]) -> None:
    async def fake(**_: Any) -> tuple[FalcoAlert, ...]:
        return tuple(alerts)

    monkeypatch.setattr(agent_mod, "falco_alerts_read", fake)


def _falco() -> FalcoAlert:
    return FalcoAlert(
        time=NOW,
        rule="Terminal shell in container",
        priority="Critical",
        output="shell spawned",
        output_fields={"container.id": "abc123def456", "k8s.pod.name": "frontend"},
        tags=("container", "shell", "process"),
    )


@pytest_asyncio.fixture
async def store() -> AsyncIterator[SemanticStore]:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory: async_sessionmaker[AsyncSession] = async_sessionmaker(engine, expire_on_commit=False)
    yield SemanticStore(factory)
    await engine.dispose()


async def test_run_with_store_writes_host_and_event_nodes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, store: SemanticStore
) -> None:
    _patch_falco(monkeypatch, [_falco()])
    report = await run(_contract(tmp_path), falco_feed=tmp_path / "f.jsonl", semantic_store=store)
    assert report.total >= 1

    # The L6 process event node landed (the shell-in-container behaviour).
    events = await store.list_entities_by_type(tenant_id=_TENANT, entity_type="process_event")
    assert len(events) >= 1
    event_id = events[0].entity_id

    # The host node landed (no k8s namespace on this alert → VM/cloud_resource) and
    # is reachable from the event via EXECUTED_ON.
    hosts = await store.list_entities_by_type(tenant_id=_TENANT, entity_type="cloud_resource")
    assert len(hosts) >= 1
    assert hosts[0].external_id == "abc123def456"
    neighbors = await store.neighbors(tenant_id=_TENANT, entity_id=event_id, depth=1)
    assert any(n.entity_type in {"cloud_resource", "k8s_object"} for n in neighbors)


async def test_run_without_store_writes_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, store: SemanticStore
) -> None:
    # Default path: no semantic_store passed → graph stays empty (byte-identical run).
    _patch_falco(monkeypatch, [_falco()])
    await run(_contract(tmp_path), falco_feed=tmp_path / "f.jsonl")
    assert await store.list_entities_by_type(tenant_id=_TENANT, entity_type="process_event") == []


async def test_within_run_host_event_edge_deduped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, store: SemanticStore
) -> None:
    # Two identical alerts → same finding behaviour → the EXECUTED_ON edge is deduped.
    _patch_falco(monkeypatch, [_falco(), _falco()])
    await run(_contract(tmp_path), falco_feed=tmp_path / "f.jsonl", semantic_store=store)
    events = await store.list_entities_by_type(tenant_id=_TENANT, entity_type="process_event")
    for ev in events:
        neighbors = await store.neighbors(tenant_id=_TENANT, entity_id=ev.entity_id, depth=1)
        hosts = [n for n in neighbors if n.entity_type in {"cloud_resource", "k8s_object"}]
        # at most one edge to any given host (within-run dedup in the base)
        assert len(hosts) == len({n.entity_id for n in hosts})
