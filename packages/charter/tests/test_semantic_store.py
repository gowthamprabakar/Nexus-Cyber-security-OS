"""Tests for `charter.memory.semantic.SemanticStore` (F.5 Task 6).

Production contract:

- `upsert_entity` is idempotent on `(tenant_id, entity_type, external_id)`
  — calling it twice with the same natural key returns the same
  synthetic `entity_id` (ULID) and merges properties into the stored
  row.
- `add_relationship` writes a directed edge `src --type--> dst`.
- `neighbors(entity_id, depth)` does a breadth-first graph traversal
  out to `depth` hops. v0.1 caps depth at 3 to keep the recursive CTE
  cheap; `depth > 3` raises.
- Optional `edge_types` filter restricts the relationships followed
  during traversal.
- Postgres path uses a recursive CTE on the `relationships` table.
  Aiosqlite path runs an iterative BFS in Python over the same data
  — same observable behaviour.
- Tenant isolation applies to both nodes and edges; an off-tenant
  entity must not appear in another tenant's traversal.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from itertools import pairwise

import pytest
import pytest_asyncio
from charter.memory.models import Base
from charter.memory.semantic import SemanticStore
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine


@pytest_asyncio.fixture
async def session_factory() -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield async_sessionmaker(engine, expire_on_commit=False)
    await engine.dispose()


@pytest_asyncio.fixture
async def store(session_factory: async_sessionmaker[AsyncSession]) -> SemanticStore:
    return SemanticStore(session_factory)


_TENANT = "01HV0T0000000000000000TEN1"
_OTHER = "01HV0T0000000000000000TEN2"


# ---------------------------- upsert idempotency -------------------------


@pytest.mark.asyncio
async def test_upsert_entity_returns_26_char_ulid(store: SemanticStore) -> None:
    eid = await store.upsert_entity(tenant_id=_TENANT, entity_type="host", external_id="i-abc123")
    assert len(eid) == 26


@pytest.mark.asyncio
async def test_upsert_entity_is_idempotent_on_natural_key(store: SemanticStore) -> None:
    a = await store.upsert_entity(
        tenant_id=_TENANT,
        entity_type="host",
        external_id="i-abc",
        properties={"region": "us-east-1"},
    )
    b = await store.upsert_entity(
        tenant_id=_TENANT,
        entity_type="host",
        external_id="i-abc",
        properties={"public_ip": "1.2.3.4"},
    )
    assert a == b

    entity = await store.get_entity(tenant_id=_TENANT, entity_id=a)
    assert entity is not None
    assert entity.properties == {"region": "us-east-1", "public_ip": "1.2.3.4"}


@pytest.mark.asyncio
async def test_upsert_distinguishes_entity_types(store: SemanticStore) -> None:
    host = await store.upsert_entity(tenant_id=_TENANT, entity_type="host", external_id="x")
    principal = await store.upsert_entity(
        tenant_id=_TENANT, entity_type="principal", external_id="x"
    )
    assert host != principal


# ---------------------------- add_relationship ---------------------------


@pytest.mark.asyncio
async def test_add_relationship_returns_positive_id(store: SemanticStore) -> None:
    a = await store.upsert_entity(tenant_id=_TENANT, entity_type="host", external_id="a")
    b = await store.upsert_entity(tenant_id=_TENANT, entity_type="finding", external_id="F-1")
    rid = await store.add_relationship(
        tenant_id=_TENANT,
        src_entity_id=a,
        dst_entity_id=b,
        relationship_type="HAS_FINDING",
    )
    assert isinstance(rid, int) and rid > 0


# ---------------------------- cross-run edge dedup (ADR-022) -------------


@pytest.mark.asyncio
async def test_add_relationship_is_idempotent_on_edge_key(store: SemanticStore) -> None:
    """Re-writing the same edge (cross-run) collapses to one row and returns the
    first-written id (ON CONFLICT DO NOTHING, first-wins)."""
    a = await store.upsert_entity(tenant_id=_TENANT, entity_type="host", external_id="a")
    b = await store.upsert_entity(tenant_id=_TENANT, entity_type="finding", external_id="F-1")
    first = await store.add_relationship(
        tenant_id=_TENANT, src_entity_id=a, dst_entity_id=b, relationship_type="AFFECTS"
    )
    second = await store.add_relationship(
        tenant_id=_TENANT, src_entity_id=a, dst_entity_id=b, relationship_type="AFFECTS"
    )
    assert second == first  # same id, no second row

    # The graph carries exactly one edge → b (external_id "F-1") appears once.
    rows = await store.neighbors(tenant_id=_TENANT, entity_id=a, depth=1)
    assert [r.external_id for r in rows] == ["F-1"]


@pytest.mark.asyncio
async def test_add_relationship_dedup_ignores_properties(store: SemanticStore) -> None:
    """Properties are not part of the key — a re-write with different properties is
    still a dedup hit (first-wins; properties not overwritten)."""
    a = await store.upsert_entity(tenant_id=_TENANT, entity_type="host", external_id="a")
    b = await store.upsert_entity(tenant_id=_TENANT, entity_type="finding", external_id="F-1")
    first = await store.add_relationship(
        tenant_id=_TENANT,
        src_entity_id=a,
        dst_entity_id=b,
        relationship_type="AFFECTS",
        properties={"severity": "high"},
    )
    second = await store.add_relationship(
        tenant_id=_TENANT,
        src_entity_id=a,
        dst_entity_id=b,
        relationship_type="AFFECTS",
        properties={"severity": "low"},
    )
    assert second == first


@pytest.mark.asyncio
async def test_add_relationship_distinguishes_edge_type(store: SemanticStore) -> None:
    """Different relationship_type between the same endpoints is a distinct edge."""
    a = await store.upsert_entity(tenant_id=_TENANT, entity_type="host", external_id="a")
    b = await store.upsert_entity(tenant_id=_TENANT, entity_type="finding", external_id="F-1")
    one = await store.add_relationship(
        tenant_id=_TENANT, src_entity_id=a, dst_entity_id=b, relationship_type="AFFECTS"
    )
    two = await store.add_relationship(
        tenant_id=_TENANT, src_entity_id=a, dst_entity_id=b, relationship_type="HAS_FINDING"
    )
    assert one != two


@pytest.mark.asyncio
async def test_add_relationship_dedup_is_tenant_scoped(store: SemanticStore) -> None:
    """The same edge under two tenants is two distinct rows (tenant in the key)."""
    a = await store.upsert_entity(tenant_id=_TENANT, entity_type="host", external_id="a")
    b = await store.upsert_entity(tenant_id=_TENANT, entity_type="finding", external_id="F-1")
    other = await store.upsert_entity(tenant_id=_OTHER, entity_type="host", external_id="a")
    other_b = await store.upsert_entity(tenant_id=_OTHER, entity_type="finding", external_id="F-1")
    rid1 = await store.add_relationship(
        tenant_id=_TENANT, src_entity_id=a, dst_entity_id=b, relationship_type="AFFECTS"
    )
    rid2 = await store.add_relationship(
        tenant_id=_OTHER,
        src_entity_id=other,
        dst_entity_id=other_b,
        relationship_type="AFFECTS",
    )
    assert rid1 != rid2


# ---------------------------- get_relationships_from (edge accessor) ------


@pytest.mark.asyncio
async def test_get_relationships_from_returns_outgoing_edges(store: SemanticStore) -> None:
    a = await store.upsert_entity(tenant_id=_TENANT, entity_type="host", external_id="a")
    b = await store.upsert_entity(tenant_id=_TENANT, entity_type="finding", external_id="F-1")
    c = await store.upsert_entity(tenant_id=_TENANT, entity_type="cve", external_id="CVE-1")
    await store.add_relationship(
        tenant_id=_TENANT, src_entity_id=a, dst_entity_id=b, relationship_type="AFFECTS"
    )
    await store.add_relationship(
        tenant_id=_TENANT, src_entity_id=a, dst_entity_id=c, relationship_type="VULNERABLE_TO"
    )
    # An inbound edge to `a` must NOT appear (outgoing-only).
    await store.add_relationship(
        tenant_id=_TENANT, src_entity_id=b, dst_entity_id=a, relationship_type="AFFECTS"
    )

    edges = await store.get_relationships_from(tenant_id=_TENANT, src_entity_id=a)
    assert {(e.src_entity_id, e.dst_entity_id, e.relationship_type) for e in edges} == {
        (a, b, "AFFECTS"),
        (a, c, "VULNERABLE_TO"),
    }


@pytest.mark.asyncio
async def test_get_relationships_from_filters_by_edge_type(store: SemanticStore) -> None:
    a = await store.upsert_entity(tenant_id=_TENANT, entity_type="host", external_id="a")
    b = await store.upsert_entity(tenant_id=_TENANT, entity_type="finding", external_id="F-1")
    c = await store.upsert_entity(tenant_id=_TENANT, entity_type="cve", external_id="CVE-1")
    await store.add_relationship(
        tenant_id=_TENANT, src_entity_id=a, dst_entity_id=b, relationship_type="AFFECTS"
    )
    await store.add_relationship(
        tenant_id=_TENANT, src_entity_id=a, dst_entity_id=c, relationship_type="VULNERABLE_TO"
    )
    edges = await store.get_relationships_from(
        tenant_id=_TENANT, src_entity_id=a, edge_types=("AFFECTS",)
    )
    assert [e.dst_entity_id for e in edges] == [b]


@pytest.mark.asyncio
async def test_get_relationships_from_is_tenant_scoped(store: SemanticStore) -> None:
    a = await store.upsert_entity(tenant_id=_TENANT, entity_type="host", external_id="a")
    b = await store.upsert_entity(tenant_id=_TENANT, entity_type="finding", external_id="F-1")
    await store.add_relationship(
        tenant_id=_TENANT, src_entity_id=a, dst_entity_id=b, relationship_type="AFFECTS"
    )
    # Same src ULID queried under another tenant returns nothing (tenant in the filter).
    edges = await store.get_relationships_from(tenant_id=_OTHER, src_entity_id=a)
    assert edges == []


@pytest.mark.asyncio
async def test_get_relationships_from_rejects_empty_args(store: SemanticStore) -> None:
    with pytest.raises(ValueError, match="tenant_id"):
        await store.get_relationships_from(tenant_id="", src_entity_id="x")
    with pytest.raises(ValueError, match="src_entity_id"):
        await store.get_relationships_from(tenant_id=_TENANT, src_entity_id="")


# ---------------------------- neighbors at depth 1 / 2 / 3 ---------------


@pytest.mark.asyncio
async def test_neighbors_depth_one_returns_direct_neighbors(
    store: SemanticStore,
) -> None:
    a = await store.upsert_entity(tenant_id=_TENANT, entity_type="host", external_id="a")
    b = await store.upsert_entity(tenant_id=_TENANT, entity_type="host", external_id="b")
    c = await store.upsert_entity(tenant_id=_TENANT, entity_type="host", external_id="c")
    await store.add_relationship(
        tenant_id=_TENANT, src_entity_id=a, dst_entity_id=b, relationship_type="LINKS"
    )
    await store.add_relationship(
        tenant_id=_TENANT, src_entity_id=b, dst_entity_id=c, relationship_type="LINKS"
    )

    rows = await store.neighbors(tenant_id=_TENANT, entity_id=a, depth=1)
    external_ids = {r.external_id for r in rows}
    assert external_ids == {"b"}


@pytest.mark.asyncio
async def test_neighbors_depth_two_reaches_two_hops(store: SemanticStore) -> None:
    a = await store.upsert_entity(tenant_id=_TENANT, entity_type="host", external_id="a")
    b = await store.upsert_entity(tenant_id=_TENANT, entity_type="host", external_id="b")
    c = await store.upsert_entity(tenant_id=_TENANT, entity_type="host", external_id="c")
    d = await store.upsert_entity(tenant_id=_TENANT, entity_type="host", external_id="d")
    await store.add_relationship(
        tenant_id=_TENANT, src_entity_id=a, dst_entity_id=b, relationship_type="LINKS"
    )
    await store.add_relationship(
        tenant_id=_TENANT, src_entity_id=b, dst_entity_id=c, relationship_type="LINKS"
    )
    await store.add_relationship(
        tenant_id=_TENANT, src_entity_id=c, dst_entity_id=d, relationship_type="LINKS"
    )

    rows = await store.neighbors(tenant_id=_TENANT, entity_id=a, depth=2)
    external_ids = {r.external_id for r in rows}
    assert external_ids == {"b", "c"}


@pytest.mark.asyncio
async def test_neighbors_depth_three_reaches_three_hops(store: SemanticStore) -> None:
    chain = []
    for label in "abcd":
        chain.append(
            await store.upsert_entity(tenant_id=_TENANT, entity_type="host", external_id=label)
        )
    for src, dst in pairwise(chain):
        await store.add_relationship(
            tenant_id=_TENANT,
            src_entity_id=src,
            dst_entity_id=dst,
            relationship_type="LINKS",
        )

    rows = await store.neighbors(tenant_id=_TENANT, entity_id=chain[0], depth=3)
    external_ids = {r.external_id for r in rows}
    assert external_ids == {"b", "c", "d"}


# ---------------------------- depth cap ---------------------------------


@pytest.mark.asyncio
async def test_neighbors_rejects_depth_greater_than_three(
    store: SemanticStore,
) -> None:
    eid = await store.upsert_entity(tenant_id=_TENANT, entity_type="host", external_id="x")
    with pytest.raises(ValueError):
        await store.neighbors(tenant_id=_TENANT, entity_id=eid, depth=4)


@pytest.mark.asyncio
async def test_neighbors_rejects_non_positive_depth(store: SemanticStore) -> None:
    eid = await store.upsert_entity(tenant_id=_TENANT, entity_type="host", external_id="x")
    with pytest.raises(ValueError):
        await store.neighbors(tenant_id=_TENANT, entity_id=eid, depth=0)


# ---------------------------- edge_types filter --------------------------


@pytest.mark.asyncio
async def test_neighbors_respects_edge_types_filter(store: SemanticStore) -> None:
    a = await store.upsert_entity(tenant_id=_TENANT, entity_type="host", external_id="a")
    b = await store.upsert_entity(tenant_id=_TENANT, entity_type="host", external_id="b")
    c = await store.upsert_entity(tenant_id=_TENANT, entity_type="host", external_id="c")
    await store.add_relationship(
        tenant_id=_TENANT, src_entity_id=a, dst_entity_id=b, relationship_type="LINKS"
    )
    await store.add_relationship(
        tenant_id=_TENANT, src_entity_id=a, dst_entity_id=c, relationship_type="OWNS"
    )

    rows = await store.neighbors(tenant_id=_TENANT, entity_id=a, depth=1, edge_types=("OWNS",))
    assert {r.external_id for r in rows} == {"c"}


# ---------------------------- tenant isolation ---------------------------


@pytest.mark.asyncio
async def test_upsert_is_tenant_scoped(store: SemanticStore) -> None:
    a = await store.upsert_entity(tenant_id=_TENANT, entity_type="host", external_id="shared")
    b = await store.upsert_entity(tenant_id=_OTHER, entity_type="host", external_id="shared")
    assert a != b


@pytest.mark.asyncio
async def test_neighbors_is_tenant_scoped(store: SemanticStore) -> None:
    a_t1 = await store.upsert_entity(tenant_id=_TENANT, entity_type="host", external_id="a")
    b_t1 = await store.upsert_entity(tenant_id=_TENANT, entity_type="host", external_id="b")
    await store.add_relationship(
        tenant_id=_TENANT,
        src_entity_id=a_t1,
        dst_entity_id=b_t1,
        relationship_type="LINKS",
    )

    a_t2 = await store.upsert_entity(tenant_id=_OTHER, entity_type="host", external_id="a")
    rows = await store.neighbors(tenant_id=_OTHER, entity_id=a_t2, depth=2)
    assert rows == []


@pytest.mark.asyncio
async def test_neighbors_returns_empty_for_unknown_entity(store: SemanticStore) -> None:
    rows = await store.neighbors(
        tenant_id=_TENANT,
        entity_id="01HV0XXXXXXXXXXXXXXXXXXXNO",
        depth=2,
    )
    assert rows == []


# ---------------------------- list_entities_by_type ----------------------


@pytest.mark.asyncio
async def test_list_entities_by_type_returns_all_matching(store: SemanticStore) -> None:
    await store.upsert_entity(
        tenant_id=_TENANT,
        entity_type="aws_account_region",
        external_id="us-east-1",
        properties={"asset_count": 42},
    )
    await store.upsert_entity(
        tenant_id=_TENANT,
        entity_type="aws_account_region",
        external_id="eu-west-3",
        properties={"asset_count": 17},
    )
    await store.upsert_entity(
        tenant_id=_TENANT,
        entity_type="host",
        external_id="other-type-should-not-appear",
    )

    rows = await store.list_entities_by_type(tenant_id=_TENANT, entity_type="aws_account_region")
    external_ids = {r.external_id for r in rows}
    assert external_ids == {"us-east-1", "eu-west-3"}


@pytest.mark.asyncio
async def test_list_entities_by_type_returns_empty_when_none_match(
    store: SemanticStore,
) -> None:
    rows = await store.list_entities_by_type(tenant_id=_TENANT, entity_type="nonexistent_type")
    assert rows == []


@pytest.mark.asyncio
async def test_list_entities_by_type_is_tenant_scoped(store: SemanticStore) -> None:
    """Per ADR-007 v1.1 — must not return rows from other tenants."""
    await store.upsert_entity(
        tenant_id=_TENANT,
        entity_type="aws_account_region",
        external_id="us-east-1",
    )
    await store.upsert_entity(
        tenant_id=_OTHER,
        entity_type="aws_account_region",
        external_id="us-east-1",
    )

    rows = await store.list_entities_by_type(tenant_id=_TENANT, entity_type="aws_account_region")
    assert len(rows) == 1
    assert rows[0].tenant_id == _TENANT


@pytest.mark.asyncio
async def test_list_entities_by_type_rejects_empty_tenant_id(
    store: SemanticStore,
) -> None:
    with pytest.raises(ValueError, match="tenant_id"):
        await store.list_entities_by_type(tenant_id="", entity_type="x")


@pytest.mark.asyncio
async def test_list_entities_by_type_rejects_empty_entity_type(
    store: SemanticStore,
) -> None:
    with pytest.raises(ValueError, match="entity_type"):
        await store.list_entities_by_type(tenant_id=_TENANT, entity_type="")
