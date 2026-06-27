"""B2 proof: the generic walker re-discovers known named attack-path shapes by traversal alone.

If the generic BFS, given a graph that lights up a named archetype, finds the same source→sink path
(same edge signature) the named detector reports, the traversal + taxonomy are correct. B4 will then
DROP these (a named detector already reports them better) and keep only novel paths — but first the
walker must correctly find them.
"""

import pytest
from charter.memory.graph_types import EdgeType, NodeCategory
from fleet_testkit import in_memory_semantic_store
from meta_harness.path_engine import find_generic_paths

_R = NodeCategory.CLOUD_RESOURCE.value
_DC = NodeCategory.DATA_CLASSIFICATION.value
_CVE = NodeCategory.CVE_FINDING.value
_ID = NodeCategory.IDENTITY.value


async def _node(store, t, etype, ext, props):
    return await store.upsert_entity(
        tenant_id=t, entity_type=etype, external_id=ext, properties=props
    )


async def _edge(store, t, src, dst, rel):
    await store.add_relationship(
        tenant_id=t, src_entity_id=src, dst_entity_id=dst, relationship_type=rel, properties={}
    )


@pytest.mark.asyncio
async def test_walker_rediscovers_public_data_path():
    """public_secret/public_unencrypted shape: public resource —EXPOSES_DATA→ sensitive data."""
    t = "t"
    async with in_memory_semantic_store() as store:
        b = await _node(store, t, _R, "arn:aws:s3:::pii", {"is_public": True})
        d = await _node(store, t, _DC, "arn:aws:s3:::pii:ssn", {"data_type": "ssn"})
        await _edge(store, t, b, d, EdgeType.EXPOSES_DATA.value)

        paths = await find_generic_paths(store, t)
        assert len(paths) == 1
        p = paths[0]
        assert p.source_marker == "public_resource"
        assert p.sink_marker == "sensitive_data"
        assert p.edge_signature == ("EXPOSES_DATA",)
        assert p.node_ids == (b, d)


@pytest.mark.asyncio
async def test_walker_rediscovers_exposed_vulnerable_path():
    """internet_exposed_vulnerable shape: public workload —RUNS_IMAGE→ image —VULNERABLE_TO→ CVE."""
    t = "t"
    async with in_memory_semantic_store() as store:
        wl = await _node(store, t, _R, "arn:ecs:svc/web", {"is_public": True})
        img = await _node(store, t, _R, "myreg/app:1.0", {"kind": "container-image"})
        cve = await _node(store, t, _CVE, "CVE-2020-7471", {"severity": "CRITICAL"})
        await _edge(store, t, wl, img, EdgeType.RUNS_IMAGE.value)
        await _edge(store, t, img, cve, EdgeType.VULNERABLE_TO.value)

        paths = await find_generic_paths(store, t)
        sigs = {p.edge_signature for p in paths}
        assert ("RUNS_IMAGE", "VULNERABLE_TO") in sigs
        p = next(p for p in paths if p.edge_signature == ("RUNS_IMAGE", "VULNERABLE_TO"))
        assert p.source_marker == "public_resource" and p.sink_marker == "known_vulnerability"


@pytest.mark.asyncio
async def test_walker_respects_depth_bound():
    """A source→sink chain longer than max_depth is not found; raising the bound finds it.

    Intermediates are non-public CLOUD_RESOURCE nodes (NOT sources, NOT sinks), so the only source
    is the public head and the only sink is the data tail — a clean 4-hop chain.
    """
    t = "t"
    async with in_memory_semantic_store() as store:
        a = await _node(store, t, _R, "pub", {"is_public": True})  # the only source
        r1 = await _node(store, t, _R, "r1", {})  # non-public resource → not a source
        r2 = await _node(store, t, _R, "r2", {})
        r3 = await _node(store, t, _R, "r3", {})
        sink = await _node(store, t, _DC, "r3:ssn", {"data_type": "ssn"})  # the only sink
        await _edge(store, t, a, r1, EdgeType.CONTAINS.value)
        await _edge(store, t, r1, r2, EdgeType.CONTAINS.value)
        await _edge(store, t, r2, r3, EdgeType.CONTAINS.value)
        await _edge(store, t, r3, sink, EdgeType.EXPOSES_DATA.value)  # sink at depth 4

        assert await find_generic_paths(store, t, max_depth=3) == []
        deeper = await find_generic_paths(store, t, max_depth=4)
        assert any(p.sink_id == sink and p.source_id == a for p in deeper)


@pytest.mark.asyncio
async def test_walker_ignores_non_attack_edges():
    """A path reachable only via a non-traversable edge (e.g. AFFECTS) is not discovered."""
    t = "t"
    async with in_memory_semantic_store() as store:
        src = await _node(store, t, _R, "pub", {"is_public": True})
        dc = await _node(store, t, _DC, "pub:ssn", {"data_type": "ssn"})
        await _edge(store, t, src, dc, EdgeType.AFFECTS.value)  # not attack progression
        assert await find_generic_paths(store, t) == []


@pytest.mark.asyncio
async def test_walker_empty_graph():
    async with in_memory_semantic_store() as store:
        assert await find_generic_paths(store, "t") == []
