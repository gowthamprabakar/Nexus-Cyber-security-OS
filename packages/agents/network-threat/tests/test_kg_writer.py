"""Tests for the network-threat knowledge-graph writer (v0.4 Stage 1.4/D.4).

End-to-end through ``agent.run()`` against a real in-memory ``SemanticStore``: the
typed ``FlowRecord``s the agent ingests land as network-endpoint nodes with
``COMMUNICATES_WITH`` edges (observed topology only — computed reachability stays
Stage 3 per #715a). Opt-in: default (no store) writes nothing. The VPC-flow reader is
patched at module level (the typed source, not OCSF dicts), matching the unit-test rig.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
import pytest_asyncio
from charter.contract import BudgetSpec, ExecutionContract
from charter.memory.models import Base
from charter.memory.semantic import SemanticStore
from network_threat import agent as agent_mod
from network_threat.agent import run
from network_threat.schemas import FlowRecord
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

pytestmark = pytest.mark.asyncio

_TENANT = "cust_test"
_NOW = datetime(2026, 5, 13, 12, 0, 0, tzinfo=UTC)


def _contract(tmp_path: Path) -> ExecutionContract:
    return ExecutionContract(
        schema_version="0.1",
        delegation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
        source_agent="supervisor",
        target_agent="network_threat",
        customer_id=_TENANT,
        task="Network threat scan",
        required_outputs=["findings.json", "report.md"],
        budget=BudgetSpec(
            llm_calls=5, tokens=10_000, wall_clock_sec=60.0, cloud_api_calls=10, mb_written=10
        ),
        permitted_tools=["read_suricata_alerts", "read_vpc_flow_logs", "read_dns_logs"],
        completion_condition="findings.json AND report.md exist",
        escalation_rules=[],
        workspace=str(tmp_path / "ws"),
        persistent_root=str(tmp_path / "p"),
        created_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )


def _flow(*, src: str, dst: str, dst_port: int = 443, index: int = 0) -> FlowRecord:
    t = _NOW + timedelta(seconds=index)
    return FlowRecord(
        src_ip=src,
        dst_ip=dst,
        src_port=49152,
        dst_port=dst_port,
        protocol=6,
        bytes_transferred=100,
        packets=1,
        start_time=t,
        end_time=t + timedelta(seconds=0.5),
        action="ACCEPT",
    )


def _patch_vpc_flow(monkeypatch: pytest.MonkeyPatch, flows: list[FlowRecord]) -> None:
    async def fake(*, path: Path, **_: Any) -> tuple[FlowRecord, ...]:
        return tuple(flows)

    monkeypatch.setattr(agent_mod, "read_vpc_flow_logs", fake)


@pytest_asyncio.fixture
async def store() -> AsyncIterator[SemanticStore]:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory: async_sessionmaker[AsyncSession] = async_sessionmaker(engine, expire_on_commit=False)
    yield SemanticStore(factory)
    await engine.dispose()


async def test_run_with_store_writes_endpoints_and_edges(
    tmp_path: Path, store: SemanticStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Two distinct conversations + a repeat of the first (dedup target).
    _patch_vpc_flow(
        monkeypatch,
        [
            _flow(src="10.0.0.5", dst="8.8.8.8", dst_port=443, index=0),
            _flow(src="10.0.0.5", dst="8.8.8.8", dst_port=443, index=1),
            _flow(src="10.0.0.9", dst="1.1.1.1", dst_port=53, index=2),
        ],
    )
    feed = tmp_path / "flow.log"
    feed.write_text("placeholder")

    await run(_contract(tmp_path), vpc_flow_feed=feed, semantic_store=store)

    endpoints = await store.list_entities_by_type(tenant_id=_TENANT, entity_type="cloud_resource")
    ips = {e.external_id for e in endpoints}
    assert ips == {"10.0.0.5", "8.8.8.8", "10.0.0.9", "1.1.1.1"}
    assert all(e.properties["kind"] == "network-endpoint" for e in endpoints)

    # COMMUNICATES_WITH: 10.0.0.5 reaches 8.8.8.8 exactly once (within-run dedup).
    src_node = next(e for e in endpoints if e.external_id == "10.0.0.5")
    neighbors = await store.neighbors(tenant_id=_TENANT, entity_id=src_node.entity_id, depth=1)
    dst_ids = [n.external_id for n in neighbors]
    assert dst_ids.count("8.8.8.8") == 1


async def test_run_without_store_writes_nothing(
    tmp_path: Path, store: SemanticStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_vpc_flow(monkeypatch, [_flow(src="10.0.0.5", dst="8.8.8.8", index=0)])
    feed = tmp_path / "flow.log"
    feed.write_text("placeholder")

    await run(_contract(tmp_path), vpc_flow_feed=feed)
    assert await store.list_entities_by_type(tenant_id=_TENANT, entity_type="cloud_resource") == []
