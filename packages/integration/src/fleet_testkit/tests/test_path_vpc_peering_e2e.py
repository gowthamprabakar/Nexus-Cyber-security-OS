"""NEX-302 e2e — cross-VPC peering lateral movement emerges as an attack path.

A public foothold in VPC-A pivots across a VPC peering into VPC-B's vulnerable host. Drives the REAL
writer (record_peering_reachability) and proves the walk:
``public host --PEERED_WITH--> private host (peered VPC) --VULNERABLE_TO--> CVE``.
"""

import pytest
from charter.memory.graph_types import EdgeType, NodeCategory
from meta_harness.coverage import measure_coverage
from meta_harness.path_engine import find_candidate_paths
from network_threat.kg_writer import KnowledgeGraphWriter as NetKgWriter
from network_threat.tools.reachability import VpcInstance, peering_reach_grants

from fleet_testkit import in_memory_semantic_store

_T = "tenant-peer"
_PUB = "arn:aws:ec2:us-east-1:1:instance/i-pub"  # VPC-A, public
_PRV = "arn:aws:ec2:us-east-1:1:instance/i-prv"  # VPC-B, vulnerable


@pytest.mark.asyncio
async def test_cross_vpc_peering_lateral_path_emerges() -> None:
    grants = peering_reach_grants(
        (VpcInstance(_PUB, "vpc-a"), VpcInstance(_PRV, "vpc-b")),
        frozenset({frozenset({"vpc-a", "vpc-b"})}),
    )
    async with in_memory_semantic_store() as store:
        await store.upsert_entity(tenant_id=_T, entity_type=NodeCategory.CLOUD_RESOURCE.value,
                                  external_id=_PUB, properties={"is_public": True})
        await NetKgWriter(store, _T).record_peering_reachability(grants)
        # the peered private host is vulnerable
        prv = await store.upsert_entity(tenant_id=_T, entity_type=NodeCategory.CLOUD_RESOURCE.value,
                                        external_id=_PRV, properties={})
        cve = await store.upsert_entity(tenant_id=_T, entity_type=NodeCategory.CVE_FINDING.value,
                                        external_id="CVE-2024-VPC", properties={"severity": "CRITICAL"})
        await store.add_relationship(tenant_id=_T, src_entity_id=prv, dst_entity_id=cve,
                                     relationship_type=EdgeType.VULNERABLE_TO.value, properties={})

        cands = await find_candidate_paths(store, _T)
        peered = [c for c in cands if "PEERED_WITH" in c.path.edge_signature]
        assert peered, "a cross-VPC peering lateral path must surface"
        assert peered[0].path.edge_signature == ("PEERED_WITH", "VULNERABLE_TO")
        assert "network_topology_lateral" in (await measure_coverage(store, _T)).produced
