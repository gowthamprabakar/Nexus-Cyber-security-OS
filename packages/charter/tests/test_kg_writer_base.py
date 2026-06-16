"""Tests for the shared knowledge-graph writer base (ADR-019)."""

from __future__ import annotations

from collections.abc import AsyncIterator

import pytest
import pytest_asyncio
from charter.memory.graph_types import EdgeType, NodeCategory
from charter.memory.kg_writer_base import KnowledgeGraphWriterBase
from charter.memory.models import Base
from charter.memory.semantic import SemanticStore
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

pytestmark = pytest.mark.asyncio

_TENANT = "01HV0T0000000000000000TEN1"


@pytest_asyncio.fixture
async def store() -> AsyncIterator[SemanticStore]:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory: async_sessionmaker[AsyncSession] = async_sessionmaker(engine, expire_on_commit=False)
    yield SemanticStore(factory)
    await engine.dispose()


async def test_inert_when_no_store() -> None:
    w = KnowledgeGraphWriterBase(None, _TENANT)
    assert w.enabled is False
    assert await w.upsert_node(NodeCategory.CLOUD_RESOURCE, "arn:x") is None
    # add_edge is a no-op (does not raise) when inert
    await w.add_edge("a", "b", EdgeType.AFFECTS)


async def test_upsert_node_and_edge_persist(store: SemanticStore) -> None:
    w = KnowledgeGraphWriterBase(store, _TENANT)
    assert w.enabled is True
    finding = await w.upsert_node(
        NodeCategory.CVE_FINDING, "CVE-2021-44228", {"severity": "critical"}
    )
    asset = await w.upsert_node(NodeCategory.CLOUD_RESOURCE, "arn:aws:ec2:...:i-1")
    assert finding is not None and asset is not None
    await w.add_edge(finding, asset, EdgeType.AFFECTS)

    rows = await store.list_entities_by_type(tenant_id=_TENANT, entity_type="cve_finding")
    assert len(rows) == 1
    assert rows[0].external_id == "CVE-2021-44228"
    # the edge is traversable
    neighbors = await store.neighbors(tenant_id=_TENANT, entity_id=finding, depth=1)
    assert any(n.entity_id == asset for n in neighbors)


async def test_within_run_edge_dedup(store: SemanticStore) -> None:
    w = KnowledgeGraphWriterBase(store, _TENANT)
    a = await w.upsert_node(NodeCategory.CVE_FINDING, "CVE-1")
    b = await w.upsert_node(NodeCategory.CLOUD_RESOURCE, "arn-1")
    assert a is not None and b is not None
    # same (src, dst, edge) triple three times → exactly one edge
    for _ in range(3):
        await w.add_edge(a, b, EdgeType.AFFECTS)
    neighbors = await store.neighbors(tenant_id=_TENANT, entity_id=a, depth=1)
    assert len([n for n in neighbors if n.entity_id == b]) == 1


async def test_add_edge_skips_none_endpoints(store: SemanticStore) -> None:
    w = KnowledgeGraphWriterBase(store, _TENANT)
    a = await w.upsert_node(NodeCategory.CVE_FINDING, "CVE-2")
    assert a is not None
    # an upstream inert/failed upsert yields an empty id → edge skipped, no raise
    await w.add_edge(a, "", EdgeType.AFFECTS)
    assert await store.neighbors(tenant_id=_TENANT, entity_id=a, depth=1) == []
