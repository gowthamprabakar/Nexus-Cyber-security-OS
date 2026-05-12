"""Tests for `investigation.tools.memory_walk` (D.7 Task 4).

F.5 SemanticStore consumer. Wraps `SemanticStore.neighbors` as an
async tool per ADR-005, scoped to D.7's needs: the investigation
supplies tenant + a seed entity + a depth (1-3), and the tool returns
the tuple of `EntityRow` reachable in that many hops.

Production contract:

- `memory_neighbors_walk(*, semantic_store, tenant_id, entity_id,
  depth, edge_types)` returns `tuple[EntityRow, ...]` — the same
  shape F.5 emits.
- Respects `MAX_TRAVERSAL_DEPTH = 3` from F.5; out-of-range raises
  `ValueError` (the underlying store raises, the tool propagates).
- Optional `edge_types` filter forwards verbatim.
- Tenant isolation pass-through — same defence-in-depth as the audit
  tool.
"""

from __future__ import annotations

import itertools
from collections.abc import AsyncIterator

import pytest
import pytest_asyncio
from charter.memory import EntityRow, SemanticStore
from charter.memory.models import Base
from investigation.tools.memory_walk import memory_neighbors_walk
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine


@pytest_asyncio.fixture
async def session_factory() -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield async_sessionmaker(engine, expire_on_commit=False)
    await engine.dispose()


@pytest_asyncio.fixture
async def semantic_store(
    session_factory: async_sessionmaker[AsyncSession],
) -> SemanticStore:
    return SemanticStore(session_factory)


_TENANT_A = "01HV0T0000000000000000TENA"
_TENANT_B = "01HV0T0000000000000000TENB"


# ---------------------------- happy path -------------------------------


@pytest.mark.asyncio
async def test_returns_tuple_of_entity_rows(semantic_store: SemanticStore) -> None:
    a = await semantic_store.upsert_entity(tenant_id=_TENANT_A, entity_type="host", external_id="a")
    b = await semantic_store.upsert_entity(tenant_id=_TENANT_A, entity_type="host", external_id="b")
    await semantic_store.add_relationship(
        tenant_id=_TENANT_A, src_entity_id=a, dst_entity_id=b, relationship_type="LINKS"
    )

    out = await memory_neighbors_walk(
        semantic_store=semantic_store,
        tenant_id=_TENANT_A,
        entity_id=a,
        depth=1,
    )
    assert isinstance(out, tuple)
    assert len(out) == 1
    assert isinstance(out[0], EntityRow)
    assert out[0].external_id == "b"


@pytest.mark.asyncio
async def test_returns_two_hop_neighbors_at_depth_2(
    semantic_store: SemanticStore,
) -> None:
    ids: list[str] = []
    for label in "abcd":
        ids.append(
            await semantic_store.upsert_entity(
                tenant_id=_TENANT_A, entity_type="host", external_id=label
            )
        )
    # a → b → c → d
    for src, dst in itertools.pairwise(ids):
        await semantic_store.add_relationship(
            tenant_id=_TENANT_A,
            src_entity_id=src,
            dst_entity_id=dst,
            relationship_type="LINKS",
        )

    out = await memory_neighbors_walk(
        semantic_store=semantic_store,
        tenant_id=_TENANT_A,
        entity_id=ids[0],
        depth=2,
    )
    assert {e.external_id for e in out} == {"b", "c"}


@pytest.mark.asyncio
async def test_returns_three_hop_neighbors_at_depth_3(
    semantic_store: SemanticStore,
) -> None:
    ids: list[str] = []
    for label in "abcd":
        ids.append(
            await semantic_store.upsert_entity(
                tenant_id=_TENANT_A, entity_type="host", external_id=label
            )
        )
    for src, dst in itertools.pairwise(ids):
        await semantic_store.add_relationship(
            tenant_id=_TENANT_A,
            src_entity_id=src,
            dst_entity_id=dst,
            relationship_type="LINKS",
        )

    out = await memory_neighbors_walk(
        semantic_store=semantic_store,
        tenant_id=_TENANT_A,
        entity_id=ids[0],
        depth=3,
    )
    assert {e.external_id for e in out} == {"b", "c", "d"}


# ---------------------------- depth cap pass-through -------------------


@pytest.mark.asyncio
async def test_rejects_depth_greater_than_three(semantic_store: SemanticStore) -> None:
    a = await semantic_store.upsert_entity(tenant_id=_TENANT_A, entity_type="host", external_id="a")
    # F.5 caps at MAX_TRAVERSAL_DEPTH = 3. The tool propagates the
    # underlying store's ValueError; D.7 doesn't re-validate.
    with pytest.raises(ValueError):
        await memory_neighbors_walk(
            semantic_store=semantic_store,
            tenant_id=_TENANT_A,
            entity_id=a,
            depth=4,
        )


@pytest.mark.asyncio
async def test_rejects_depth_zero(semantic_store: SemanticStore) -> None:
    a = await semantic_store.upsert_entity(tenant_id=_TENANT_A, entity_type="host", external_id="a")
    with pytest.raises(ValueError):
        await memory_neighbors_walk(
            semantic_store=semantic_store,
            tenant_id=_TENANT_A,
            entity_id=a,
            depth=0,
        )


# ---------------------------- edge_types filter -----------------------


@pytest.mark.asyncio
async def test_forwards_edge_types_filter(semantic_store: SemanticStore) -> None:
    a = await semantic_store.upsert_entity(tenant_id=_TENANT_A, entity_type="host", external_id="a")
    b = await semantic_store.upsert_entity(tenant_id=_TENANT_A, entity_type="host", external_id="b")
    c = await semantic_store.upsert_entity(tenant_id=_TENANT_A, entity_type="host", external_id="c")
    await semantic_store.add_relationship(
        tenant_id=_TENANT_A, src_entity_id=a, dst_entity_id=b, relationship_type="LINKS"
    )
    await semantic_store.add_relationship(
        tenant_id=_TENANT_A, src_entity_id=a, dst_entity_id=c, relationship_type="OWNS"
    )

    out = await memory_neighbors_walk(
        semantic_store=semantic_store,
        tenant_id=_TENANT_A,
        entity_id=a,
        depth=1,
        edge_types=("OWNS",),
    )
    assert {e.external_id for e in out} == {"c"}


# ---------------------------- tenant isolation -------------------------


@pytest.mark.asyncio
async def test_tenant_isolation_pass_through(semantic_store: SemanticStore) -> None:
    a_t1 = await semantic_store.upsert_entity(
        tenant_id=_TENANT_A, entity_type="host", external_id="a"
    )
    b_t1 = await semantic_store.upsert_entity(
        tenant_id=_TENANT_A, entity_type="host", external_id="b"
    )
    await semantic_store.add_relationship(
        tenant_id=_TENANT_A,
        src_entity_id=a_t1,
        dst_entity_id=b_t1,
        relationship_type="LINKS",
    )

    a_t2 = await semantic_store.upsert_entity(
        tenant_id=_TENANT_B, entity_type="host", external_id="a"
    )
    out = await memory_neighbors_walk(
        semantic_store=semantic_store,
        tenant_id=_TENANT_B,
        entity_id=a_t2,
        depth=2,
    )
    assert out == ()


# ---------------------------- unknown seed ----------------------------


@pytest.mark.asyncio
async def test_unknown_entity_returns_empty(semantic_store: SemanticStore) -> None:
    out = await memory_neighbors_walk(
        semantic_store=semantic_store,
        tenant_id=_TENANT_A,
        entity_id="01HV0XXXXXXXXXXXXXXXXXXXNO",
        depth=2,
    )
    assert out == ()
