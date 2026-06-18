"""Tests — `meta_harness.kg_query` (Stage 3 PR2, A.4 fleet-graph read queries).

Real e2e against an in-memory `SemanticStore` (sqlite) seeded with a small typed graph. Covers
blast-radius (downstream BFS), attack-path reconstruction (BFS over the ADR-022 edge accessor),
the depth-3 cap, cycle exclusion, edge-type filtering, and tenant isolation.

Sample graph (tenant A), modelling a cloud→code blast surface:

    cluster --RUNS_ON--> node --AFFECTS--> finding --VULNERABLE_TO--> cve
                          node --AFFECTS--> finding2
    repo    --AFFECTS--> finding            (a second inbound path to `finding`)
"""

from __future__ import annotations

from collections.abc import AsyncIterator

import pytest
import pytest_asyncio
from charter.memory.models import Base
from charter.memory.semantic import MAX_TRAVERSAL_DEPTH, SemanticStore
from meta_harness.kg_query import AttackPathResult, BlastRadiusResult, KgQuery, PathEdge
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

_TENANT = "01HV0T0000000000000000TEN1"
_OTHER = "01HV0T0000000000000000TEN2"


@pytest_asyncio.fixture
async def store() -> AsyncIterator[SemanticStore]:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory: async_sessionmaker[AsyncSession] = async_sessionmaker(engine, expire_on_commit=False)
    yield SemanticStore(factory)
    await engine.dispose()


async def _seed(store: SemanticStore, tenant: str) -> dict[str, str]:
    """Build the sample graph; return a name → entity_id map."""
    ids = {}
    for name, etype in (
        ("cluster", "k8s_cluster"),
        ("node", "k8s_object"),
        ("finding", "misconfiguration_finding"),
        ("finding2", "misconfiguration_finding"),
        ("cve", "cve_finding"),
        ("repo", "code_repository"),
    ):
        ids[name] = await store.upsert_entity(tenant_id=tenant, entity_type=etype, external_id=name)
    edges = [
        ("cluster", "node", "RUNS_ON"),
        ("node", "finding", "AFFECTS"),
        ("node", "finding2", "AFFECTS"),
        ("finding", "cve", "VULNERABLE_TO"),
        ("repo", "finding", "AFFECTS"),
    ]
    for src, dst, etype in edges:
        await store.add_relationship(
            tenant_id=tenant,
            src_entity_id=ids[src],
            dst_entity_id=ids[dst],
            relationship_type=etype,
        )
    return ids


# ---------------------------- blast radius -------------------------------


@pytest.mark.asyncio
async def test_blast_radius_reaches_three_hops(store: SemanticStore) -> None:
    ids = await _seed(store, _TENANT)
    q = KgQuery(store, _TENANT)
    result = await q.blast_radius(entity_id=ids["cluster"], depth=3)
    assert isinstance(result, BlastRadiusResult)
    # cluster → node → {finding, finding2} → cve  (all within 3 hops)
    reached = {r.external_id for r in result.reachable}
    assert reached == {"node", "finding", "finding2", "cve"}
    assert result.count == 4


@pytest.mark.asyncio
async def test_blast_radius_depth_one(store: SemanticStore) -> None:
    ids = await _seed(store, _TENANT)
    q = KgQuery(store, _TENANT)
    result = await q.blast_radius(entity_id=ids["cluster"], depth=1)
    assert {r.external_id for r in result.reachable} == {"node"}


@pytest.mark.asyncio
async def test_blast_radius_edge_type_filter(store: SemanticStore) -> None:
    ids = await _seed(store, _TENANT)
    q = KgQuery(store, _TENANT)
    # Only AFFECTS edges → from node we reach finding/finding2 but not via RUNS_ON or VULNERABLE_TO.
    result = await q.blast_radius(entity_id=ids["node"], depth=3, edge_types=("AFFECTS",))
    assert {r.external_id for r in result.reachable} == {"finding", "finding2"}


@pytest.mark.asyncio
async def test_blast_radius_rejects_out_of_range_depth(store: SemanticStore) -> None:
    q = KgQuery(store, _TENANT)
    with pytest.raises(ValueError, match=r"depth must be in"):
        await q.blast_radius(entity_id="x", depth=MAX_TRAVERSAL_DEPTH + 1)
    with pytest.raises(ValueError, match=r"depth must be in"):
        await q.blast_radius(entity_id="x", depth=0)


# ---------------------------- attack path --------------------------------


@pytest.mark.asyncio
async def test_attack_path_reconstructs_chain(store: SemanticStore) -> None:
    ids = await _seed(store, _TENANT)
    q = KgQuery(store, _TENANT)
    result = await q.attack_path(src_entity_id=ids["cluster"], dst_entity_id=ids["cve"])
    assert isinstance(result, AttackPathResult)
    assert result.found
    # cluster --RUNS_ON--> node --AFFECTS--> finding --VULNERABLE_TO--> cve (3 hops)
    shortest = result.shortest
    assert shortest is not None
    assert [e.relationship_type for e in shortest] == ["RUNS_ON", "AFFECTS", "VULNERABLE_TO"]
    assert shortest[0].src_entity_id == ids["cluster"]
    assert shortest[-1].dst_entity_id == ids["cve"]


@pytest.mark.asyncio
async def test_attack_path_returns_all_simple_paths(store: SemanticStore) -> None:
    ids = await _seed(store, _TENANT)
    # Add a second route cluster → node already exists; add repo→finding gives another inbound to
    # finding, but from `cluster` there is exactly one route to `finding`. Add a direct shortcut.
    await store.add_relationship(
        tenant_id=_TENANT,
        src_entity_id=ids["cluster"],
        dst_entity_id=ids["finding"],
        relationship_type="AFFECTS",
    )
    q = KgQuery(store, _TENANT)
    result = await q.attack_path(src_entity_id=ids["cluster"], dst_entity_id=ids["finding"])
    # Two simple paths: cluster→finding (1 hop) and cluster→node→finding (2 hops).
    lengths = sorted(len(p) for p in result.paths)
    assert lengths == [1, 2]
    assert len(result.shortest) == 1  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_attack_path_respects_depth_cap(store: SemanticStore) -> None:
    ids = await _seed(store, _TENANT)
    q = KgQuery(store, _TENANT)
    # cve is 3 hops from cluster; cap at 2 → no path found.
    result = await q.attack_path(
        src_entity_id=ids["cluster"], dst_entity_id=ids["cve"], max_depth=2
    )
    assert not result.found
    assert result.paths == ()


@pytest.mark.asyncio
async def test_attack_path_no_path_when_unreachable(store: SemanticStore) -> None:
    ids = await _seed(store, _TENANT)
    q = KgQuery(store, _TENANT)
    # cve has no outgoing edges → nothing reachable from it.
    result = await q.attack_path(src_entity_id=ids["cve"], dst_entity_id=ids["cluster"])
    assert not result.found


@pytest.mark.asyncio
async def test_attack_path_same_src_dst_is_empty(store: SemanticStore) -> None:
    ids = await _seed(store, _TENANT)
    q = KgQuery(store, _TENANT)
    result = await q.attack_path(src_entity_id=ids["node"], dst_entity_id=ids["node"])
    assert result.paths == ()


@pytest.mark.asyncio
async def test_attack_path_excludes_cycles(store: SemanticStore) -> None:
    ids = await _seed(store, _TENANT)
    # Introduce a cycle: finding --AFFECTS--> node (back-edge).
    await store.add_relationship(
        tenant_id=_TENANT,
        src_entity_id=ids["finding"],
        dst_entity_id=ids["node"],
        relationship_type="AFFECTS",
    )
    q = KgQuery(store, _TENANT)
    # Path to cve must still terminate (no infinite loop through node↔finding).
    result = await q.attack_path(src_entity_id=ids["cluster"], dst_entity_id=ids["cve"])
    assert result.found
    for path in result.paths:
        node_ids = [path[0].src_entity_id, *(e.dst_entity_id for e in path)]
        assert len(node_ids) == len(set(node_ids))  # no node repeats within a path


@pytest.mark.asyncio
async def test_attack_path_edge_type_filter(store: SemanticStore) -> None:
    ids = await _seed(store, _TENANT)
    q = KgQuery(store, _TENANT)
    # Restricting to AFFECTS only breaks the cluster→node (RUNS_ON) hop → no path to cve.
    result = await q.attack_path(
        src_entity_id=ids["cluster"], dst_entity_id=ids["cve"], edge_types=("AFFECTS",)
    )
    assert not result.found


# ---------------------------- tenant isolation ---------------------------


@pytest.mark.asyncio
async def test_queries_are_tenant_scoped(store: SemanticStore) -> None:
    ids = await _seed(store, _TENANT)
    await _seed(store, _OTHER)  # an identical graph under another tenant
    q_other = KgQuery(store, _OTHER)

    # A query bound to _OTHER must not traverse _TENANT's nodes (different entity_ids).
    blast = await q_other.blast_radius(entity_id=ids["cluster"], depth=3)
    assert blast.reachable == ()  # _TENANT's cluster id is invisible to _OTHER
    path = await q_other.attack_path(src_entity_id=ids["cluster"], dst_entity_id=ids["cve"])
    assert not path.found


@pytest.mark.asyncio
async def test_path_edge_is_read_only_dto() -> None:
    edge = PathEdge(src_entity_id="a", dst_entity_id="b", relationship_type="AFFECTS")
    with pytest.raises((AttributeError, TypeError)):
        edge.relationship_type = "X"  # type: ignore[misc]
