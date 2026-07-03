"""NEX-302 e2e — cross-VPC peering lateral movement emerges as an attack path.

Two complementary walks both proven here:

1. **CVE walk** (generic candidate): ``public host --PEERED_WITH--> private host --VULNERABLE_TO--> CVE``
   — the peering-to-exploitable-host path, not yet a named shape, surfaces as a novel candidate.

2. **Data-exposure walk** (named detector, D-2):
   ``public host --PEERED_WITH--> private resource --EXPOSES_DATA--> DATA_CLASSIFICATION``
   — the peering-to-sensitive-data path; drives ``find_vpc_peered_lateral_to_data`` via the REAL
   writer (record_peering_reachability).
"""

import pytest
from charter.memory.graph_types import EdgeType, NodeCategory
from meta_harness.coverage import measure_coverage
from meta_harness.kg_query import KgQuery
from meta_harness.path_engine import find_candidate_paths
from network_threat.kg_writer import KnowledgeGraphWriter as NetKgWriter
from network_threat.tools.reachability import VpcInstance, peering_reach_grants

from fleet_testkit import in_memory_semantic_store

_T = "tenant-peer"
_PUB = "arn:aws:ec2:us-east-1:1:instance/i-pub"  # VPC-A, public
_PRV = "arn:aws:ec2:us-east-1:1:instance/i-prv"  # VPC-B, vulnerable


@pytest.mark.asyncio
async def test_cross_vpc_peering_lateral_path_emerges() -> None:
    """CVE walk: public foothold --PEERED_WITH--> private host --VULNERABLE_TO--> CVE.

    This shape is NOT in NAMED_SHAPES so it surfaces as a novel generic candidate; the
    PEERED_WITH key edge in the candidate's signature drives the ``network_topology_lateral``
    coverage family.
    """
    grants = peering_reach_grants(
        (VpcInstance(_PUB, "vpc-a"), VpcInstance(_PRV, "vpc-b")),
        frozenset({frozenset({"vpc-a", "vpc-b"})}),
    )
    async with in_memory_semantic_store() as store:
        await store.upsert_entity(
            tenant_id=_T,
            entity_type=NodeCategory.CLOUD_RESOURCE.value,
            external_id=_PUB,
            properties={"is_public": True},
        )
        await NetKgWriter(store, _T).record_peering_reachability(grants)
        # the peered private host is vulnerable
        prv = await store.upsert_entity(
            tenant_id=_T,
            entity_type=NodeCategory.CLOUD_RESOURCE.value,
            external_id=_PRV,
            properties={},
        )
        cve = await store.upsert_entity(
            tenant_id=_T,
            entity_type=NodeCategory.CVE_FINDING.value,
            external_id="CVE-2024-VPC",
            properties={"severity": "CRITICAL"},
        )
        await store.add_relationship(
            tenant_id=_T,
            src_entity_id=prv,
            dst_entity_id=cve,
            relationship_type=EdgeType.VULNERABLE_TO.value,
            properties={},
        )

        cands = await find_candidate_paths(store, _T)
        peered = [c for c in cands if "PEERED_WITH" in c.path.edge_signature]
        assert peered, "a cross-VPC peering lateral path must surface"
        assert peered[0].path.edge_signature == ("PEERED_WITH", "VULNERABLE_TO")
        assert "network_topology_lateral" in (await measure_coverage(store, _T)).produced


@pytest.mark.asyncio
async def test_vpc_peered_lateral_to_data_named_detector() -> None:
    """Data-exposure walk (D-2 named detector): public --PEERED_WITH--> private --EXPOSES_DATA--> data.

    Drives the REAL writer (record_peering_reachability); asserts
    ``find_vpc_peered_lateral_to_data`` returns the hit.  This shape IS in NAMED_SHAPES so the
    generic engine drops it as a duplicate of the named detector — only the named detector surfaces
    it.
    """
    _T2 = "tenant-peer-data"
    _PUB2 = "arn:aws:ec2:us-east-1:2:instance/i-pub"  # VPC-A, public
    _PRV2 = "arn:aws:s3:::private-bucket"  # VPC-B, exposes sensitive data
    grants = peering_reach_grants(
        (VpcInstance(_PUB2, "vpc-a"), VpcInstance(_PRV2, "vpc-b")),
        frozenset({frozenset({"vpc-a", "vpc-b"})}),
    )
    async with in_memory_semantic_store() as store:
        await store.upsert_entity(
            tenant_id=_T2,
            entity_type=NodeCategory.CLOUD_RESOURCE.value,
            external_id=_PUB2,
            properties={"is_public": True},
        )
        await NetKgWriter(store, _T2).record_peering_reachability(grants)
        # the peered private resource exposes sensitive data
        prv = await store.upsert_entity(
            tenant_id=_T2,
            entity_type=NodeCategory.CLOUD_RESOURCE.value,
            external_id=_PRV2,
            properties={},
        )
        data_node = await store.upsert_entity(
            tenant_id=_T2,
            entity_type=NodeCategory.DATA_CLASSIFICATION.value,
            external_id=f"{_PRV2}/pii",
            properties={"data_type": "ssn"},
        )
        await store.add_relationship(
            tenant_id=_T2,
            src_entity_id=prv,
            dst_entity_id=data_node,
            relationship_type=EdgeType.EXPOSES_DATA.value,
            properties={},
        )

        # Named detector surfaces the path
        hits = await KgQuery(store, _T2).find_vpc_peered_lateral_to_data()
        assert hits, "find_vpc_peered_lateral_to_data must return a hit"
        assert hits[0].foothold_id is not None
        assert hits[0].data_type == "ssn"

        # The generic engine drops this shape (it is in NAMED_SHAPES) — no candidate duplicate
        cands = await find_candidate_paths(store, _T2)
        peered_data_cands = [
            c for c in cands if c.path.edge_signature == ("PEERED_WITH", "EXPOSES_DATA")
        ]
        assert not peered_data_cands, (
            "PEERED_WITH→EXPOSES_DATA is a NAMED shape and must NOT surface as a generic candidate"
        )
