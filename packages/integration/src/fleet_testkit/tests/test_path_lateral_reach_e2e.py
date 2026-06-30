"""Slice #2 e2e — a CAN_REACH edge makes a lateral-movement path EMERGE.

Without derived reachability, a public foothold and a private vulnerable host are disconnected
nodes — the attack stops at the edge of the box it landed on. This drives network-threat's REAL
``record_reachability`` to lay the lateral edge and proves the generic engine now surfaces a path
``public instance --CAN_REACH--> private instance --VULNERABLE_TO--> CVE`` that did not exist before.
"""

import pytest
from charter.memory.graph_types import EdgeType, NodeCategory
from meta_harness.path_engine import find_candidate_paths
from network_threat.kg_writer import KnowledgeGraphWriter as NetworkKgWriter
from network_threat.tools.reachability import (
    IngressRule,
    NetworkInstance,
    SecurityGroup,
    reach_grants,
)

from fleet_testkit import in_memory_semantic_store

_T = "tenant-lateral"
_PUBLIC = "arn:aws:ec2:us-east-1:111:instance/i-public"  # internet-facing foothold
_PRIVATE = "arn:aws:ec2:us-east-1:111:instance/i-private"  # private, vulnerable


@pytest.mark.asyncio
async def test_lateral_movement_path_emerges() -> None:
    instances = (
        NetworkInstance(_PUBLIC, ("sg-web",)),
        NetworkInstance(_PRIVATE, ("sg-db",)),
    )
    # The private DB's SG admits the public box's SG on 5432 → lateral reach.
    sgs = (
        SecurityGroup(
            "sg-db",
            (IngressRule(protocol="tcp", from_port=5432, to_port=5432, source_sgs=("sg-web",)),),
        ),
    )
    async with in_memory_semantic_store() as store:
        # 1) network-threat's REAL writer lays the derived reachability edge.
        await NetworkKgWriter(store, _T).record_reachability(reach_grants(instances, sgs))

        # 2) the public box is the attacker's foothold (is_public source marker); the private box
        #    has a known exploitable CVE (the sink other agents write).
        async def _id(external_id: str) -> str:
            for r in await store.list_entities_by_type(
                tenant_id=_T, entity_type=NodeCategory.CLOUD_RESOURCE.value
            ):
                if r.external_id == external_id:
                    return r.entity_id
            raise AssertionError(f"no resource node {external_id}")

        await store.upsert_entity(
            tenant_id=_T,
            entity_type=NodeCategory.CLOUD_RESOURCE.value,
            external_id=_PUBLIC,
            properties={"is_public": True},
        )
        cve = await store.upsert_entity(
            tenant_id=_T,
            entity_type=NodeCategory.CVE_FINDING.value,
            external_id="CVE-2024-9999",
            properties={"severity": "critical"},
        )
        await store.add_relationship(
            tenant_id=_T,
            src_entity_id=await _id(_PRIVATE),
            dst_entity_id=cve,
            relationship_type=EdgeType.VULNERABLE_TO.value,
            properties={},
        )

        # 3) the lateral path emerges: public --CAN_REACH--> private --VULNERABLE_TO--> CVE.
        cands = await find_candidate_paths(store, _T)
        lateral = [c for c in cands if "CAN_REACH" in c.path.edge_signature]
        assert lateral, "a lateral-movement-to-vuln path must surface once CAN_REACH is traversable"
        path = lateral[0].path
        assert path.source_id == await _id(_PUBLIC)
        assert path.sink_marker == "known_vulnerability"
        assert path.edge_signature == ("CAN_REACH", "VULNERABLE_TO")
