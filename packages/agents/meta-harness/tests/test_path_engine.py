"""B2 proof: the generic walker re-discovers known named attack-path shapes by traversal alone.

If the generic BFS, given a graph that lights up a named archetype, finds the same source→sink path
(same edge signature) the named detector reports, the traversal + taxonomy are correct. B4 will then
DROP these (a named detector already reports them better) and keep only novel paths — but first the
walker must correctly find them.
"""

import pytest
from charter.memory.graph_types import EdgeType, NodeCategory
from fleet_testkit import in_memory_semantic_store
from meta_harness.attack_paths import _SEVERITY
from meta_harness.path_engine import (
    CANDIDATE_SCORE_CAP,
    NAMED_SHAPES,
    GenericPath,
    PathHop,
    find_candidate_paths,
    find_generic_paths,
    score_path,
)
from meta_harness.path_taxonomy import SINK_MARKERS, SOURCE_MARKERS, is_traversable

_R = NodeCategory.CLOUD_RESOURCE.value
_DC = NodeCategory.DATA_CLASSIFICATION.value
_CVE = NodeCategory.CVE_FINDING.value
_ID = NodeCategory.IDENTITY.value
_PE = NodeCategory.PROCESS_EVENT.value
_K8S = NodeCategory.K8S_OBJECT.value


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


@pytest.mark.asyncio
async def test_bp5_cte_walker_matches_python_oracle():
    """BP5: the recursive-CTE walk (find_generic_paths) is identical to the in-Python BFS oracle.

    A multi-source graph exercising: a direct data path, a 2-hop transitive route, a vuln chain, a
    cycle (must be excluded), and a depth-5 chain truncated at the bound."""
    from meta_harness.path_engine import find_generic_paths_python

    t = "t"
    async with in_memory_semantic_store() as store:
        pub = await _node(store, t, _R, "arn:pub", {"is_public": True})
        mid = await _node(store, t, _R, "arn:mid", {})
        data = await _node(store, t, _DC, "arn:mid:ssn", {"data_type": "ssn"})
        img = await _node(store, t, _R, "img:1", {"kind": "container-image"})
        cve = await _node(store, t, _CVE, "CVE-1", {"severity": "HIGH", "kev": True})
        await _edge(store, t, pub, data, EdgeType.EXPOSES_DATA.value)  # direct
        await _edge(store, t, pub, mid, EdgeType.CONTAINS.value)  # transitive...
        await _edge(store, t, mid, data, EdgeType.EXPOSES_DATA.value)  # ...to same data
        await _edge(store, t, pub, img, EdgeType.RUNS_IMAGE.value)
        await _edge(store, t, img, cve, EdgeType.VULNERABLE_TO.value)
        await _edge(store, t, mid, pub, EdgeType.CONTAINS.value)  # cycle mid->pub

        cte = await find_generic_paths(store, t, max_depth=4)
        oracle = await find_generic_paths_python(store, t, max_depth=4)
        assert frozenset(cte) == frozenset(oracle)
        assert cte, "the graph yields paths (guards against both returning empty)"
        # Sink risk-signals (BP2) survived the CTE round-trip.
        vuln = next(p for p in cte if p.sink_marker == "known_vulnerability")
        assert vuln.sink_severity == "HIGH" and vuln.sink_kev is True


@pytest.mark.asyncio
async def test_bp5_node_count_guard():
    from charter.memory.semantic import PathWalkTooLarge

    t = "t"
    async with in_memory_semantic_store() as store:
        src = await _node(store, t, _R, "arn:pub", {"is_public": True})
        with pytest.raises(PathWalkTooLarge):
            await store.walk_paths(
                tenant_id=t,
                source_ids=[src],
                traversable_edges=frozenset({"EXPOSES_DATA"}),
                sink_categories=frozenset({_DC}),
                max_depth=3,
                max_nodes=0,  # any non-empty graph trips the guard
            )


# --- B3/B4: novelty filter + scoring -------------------------------------------------------------


def test_named_shapes_use_valid_markers_and_edges():
    sources = {m.name for m in SOURCE_MARKERS}
    sinks = {m.name for m in SINK_MARKERS}
    for src, sink, signature in NAMED_SHAPES:
        assert src in sources, f"{src} not a source marker"
        assert sink in sinks, f"{sink} not a sink marker"
        assert signature, f"{src}->{sink}: empty edge signature"
        for edge in signature:
            assert is_traversable(edge), f"{src}->{sink}: edge {edge} not traversable"


def test_candidate_cap_is_below_every_named_severity():
    # A confirmed finding must always outrank an unverified candidate.
    assert min(_SEVERITY.values()) > CANDIDATE_SCORE_CAP


def _gp(source, sink, edges, **sink_props):
    hops = tuple(PathHop(e, f"n{i}", f"node{i}") for i, e in enumerate(edges))
    return GenericPath("s", source, "k", sink, hops, **sink_props)


def test_bp2_scoring_reflects_exploitability_sensitivity_and_edge_risk():
    # Same shape, worse CVE → higher score; KEV bumps it further.
    crit = _gp(
        "public_resource", "known_vulnerability", ["VULNERABLE_TO"], sink_severity="CRITICAL"
    )
    low = _gp("public_resource", "known_vulnerability", ["VULNERABLE_TO"], sink_severity="LOW")
    crit_kev = _gp(
        "public_resource",
        "known_vulnerability",
        ["VULNERABLE_TO"],
        sink_severity="HIGH",
        sink_kev=True,
    )
    high = _gp("public_resource", "known_vulnerability", ["VULNERABLE_TO"], sink_severity="HIGH")
    assert score_path(crit) > score_path(low)
    assert score_path(crit_kev) > score_path(high)  # KEV raises a HIGH CVE

    # Regulated data sink outscores a generic-data sink (same shape).
    ssn = _gp("identity_principal", "sensitive_data", ["HAS_ACCESS_TO"], sink_data_type="ssn")
    generic = _gp("identity_principal", "sensitive_data", ["HAS_ACCESS_TO"], sink_data_type="logs")
    assert score_path(ssn) > score_path(generic)

    # A weak progression edge (DEPLOYED_VIA) gates the score below a strong one (EXPOSES_DATA).
    strong = _gp("public_resource", "sensitive_data", ["EXPOSES_DATA"], sink_data_type="ssn")
    weak = _gp("public_resource", "sensitive_data", ["DEPLOYED_VIA"], sink_data_type="ssn")
    assert score_path(strong) > score_path(weak)

    # The cap holds for the strongest possible candidate.
    assert score_path(crit) <= CANDIDATE_SCORE_CAP < min(_SEVERITY.values())


@pytest.mark.asyncio
async def test_named_covered_path_is_not_a_candidate():
    """public_resource → sensitive_data is a NAMED pair → dropped (a named detector reports it)."""
    t = "t"
    async with in_memory_semantic_store() as store:
        b = await _node(store, t, _R, "arn:aws:s3:::pii", {"is_public": True})
        d = await _node(store, t, _DC, "arn:aws:s3:::pii:ssn", {"data_type": "ssn"})
        await _edge(store, t, b, d, EdgeType.EXPOSES_DATA.value)
        assert await find_candidate_paths(store, t) == []


@pytest.mark.asyncio
async def test_bp1_novel_route_between_named_pair_surfaces():
    """BP1 keystone: a NEW ROUTE between an already-named (source, sink) pair is novel.

    public_resource -> sensitive_data is named ONLY via the direct (EXPOSES_DATA,) shape. A public
    resource that reaches the same data via a 2-hop (CONTAINS, EXPOSES_DATA) route is a different
    shape -> a candidate. The old pair-based filter dropped it (same pair); shape-novelty keeps it."""
    t = "t"
    async with in_memory_semantic_store() as store:
        pub = await _node(store, t, _R, "pub", {"is_public": True})
        mid = await _node(store, t, _R, "mid", {})  # non-public resource (not a source/sink)
        data = await _node(store, t, _DC, "mid:ssn", {"data_type": "ssn"})
        await _edge(store, t, pub, mid, EdgeType.CONTAINS.value)
        await _edge(store, t, mid, data, EdgeType.EXPOSES_DATA.value)

        candidates = await find_candidate_paths(store, t)
        assert len(candidates) == 1
        c = candidates[0]
        assert c.pair == ("public_resource", "sensitive_data")  # a NAMED pair...
        assert c.path.edge_signature == ("CONTAINS", "EXPOSES_DATA")  # ...via a novel route


@pytest.mark.asyncio
async def test_novel_combination_surfaces_as_scored_candidate():
    """runtime_detection → sensitive_data is NOT a named pair → a novel candidate.

    'An active runtime detection on a host that can reach sensitive data' — a real escalation no
    named detector covers (named runtime only joins to vulnerabilities, not data)."""
    t = "t"
    async with in_memory_semantic_store() as store:
        event = await _node(store, t, _PE, "RUNTIME-PROCESS-X-001-e", {"finding_type": "process"})
        host = await _node(store, t, _R, "host-1", {})
        data = await _node(store, t, _DC, "host-1:ssn", {"data_type": "ssn"})
        await _edge(store, t, event, host, EdgeType.EXECUTED_ON.value)
        await _edge(store, t, host, data, EdgeType.EXPOSES_DATA.value)

        candidates = await find_candidate_paths(store, t)
        assert len(candidates) == 1
        c = candidates[0]
        assert c.pair == ("runtime_detection", "sensitive_data")
        assert c.confidence == "candidate"
        assert 0 < c.score < min(_SEVERITY.values())  # scored, but below every named


@pytest.mark.asyncio
async def test_candidates_dedup_to_shortest_per_pair():
    """Two routes between the same source and sink collapse to one (shortest) candidate."""
    t = "t"
    async with in_memory_semantic_store() as store:
        # privileged_workload → sensitive_data is novel (named covers privileged→vuln, not →data).
        pod = await _node(store, t, _K8S, "pod-1", {"privileged": True})
        mid = await _node(store, t, _R, "mid", {})
        data = await _node(store, t, _DC, "d:ssn", {"data_type": "ssn"})
        await _edge(store, t, pod, data, EdgeType.CONTAINS.value)  # direct, 1 hop
        await _edge(store, t, pod, mid, EdgeType.CONTAINS.value)  # indirect, 2 hops
        await _edge(store, t, mid, data, EdgeType.EXPOSES_DATA.value)

        candidates = await find_candidate_paths(store, t)
        assert len(candidates) == 1  # both routes → one (source, sink) pair
        assert len(candidates[0].path.hops) == 1  # the shortest route kept
