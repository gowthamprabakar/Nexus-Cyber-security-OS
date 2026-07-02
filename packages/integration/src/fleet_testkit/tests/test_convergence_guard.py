"""NEX-103 — cross-agent convergence guard (Seam A keystone).

The whole moat depends on independent agents keying the SAME real resource identically, so their
signals collapse onto ONE graph node. This is convention (the canonical builders in
``charter.canonical``), not an enforced contract — and it broke once (S3 bucket-name vs ARN). This
test drives THREE agents at one fixture resource and asserts exactly one node carries all their edges;
a mis-keyed trap must FAIL it. Runs before (and gates) the NEX-101/102 canonical-builder refactor.
"""

import pytest
from charter.canonical import s3_bucket_arn
from charter.memory.graph_types import EdgeType, NodeCategory
from cloud_posture.tools.kg_writer import KnowledgeGraphWriter as CloudKgWriter
from identity.kg_writer import KnowledgeGraphWriter as IdentityKgWriter

from fleet_testkit import in_memory_semantic_store

_T = "conv-guard"
_BUCKET_NAME = "crown-jewels"
_ARN = s3_bucket_arn(_BUCKET_NAME)  # the ONE canonical key all agents must use


async def _resources(store):
    return await store.list_entities_by_type(
        tenant_id=_T, entity_type=NodeCategory.CLOUD_RESOURCE.value
    )


@pytest.mark.asyncio
async def test_three_agents_converge_on_one_resource_node() -> None:
    async with in_memory_semantic_store() as store:
        # cloud-posture: the bucket as a public asset (keyed canonically)
        await CloudKgWriter(store, _T).upsert_asset("s3-bucket", _ARN, {"is_public": True})
        # identity: a principal HAS_ACCESS_TO the same bucket (keyed canonically)
        await IdentityKgWriter(store, _T).record_access([("arn:aws:iam::1:role/r", _ARN)])
        # data-security side: the bucket EXPOSES_DATA (same key)
        data = await store.upsert_entity(
            tenant_id=_T,
            entity_type=NodeCategory.DATA_CLASSIFICATION.value,
            external_id=f"{_ARN}/pii",
            properties={"data_type": "ssn"},
        )
        bucket_nodes = [r for r in await _resources(store) if r.external_id == _ARN]
        assert len(bucket_nodes) == 1, "3 agents must resolve to ONE bucket node"
        await store.add_relationship(
            tenant_id=_T,
            src_entity_id=bucket_nodes[0].entity_id,
            dst_entity_id=data,
            relationship_type=EdgeType.EXPOSES_DATA.value,
            properties={},
        )

        # the single node carries all three signals (is_public + HAS_ACCESS_TO in + EXPOSES_DATA out)
        node = bucket_nodes[0]
        assert node.properties.get("is_public") is True
        outs = {
            e.relationship_type
            for e in await store.get_relationships_from(
                tenant_id=_T,
                src_entity_id=node.entity_id,
                edge_types=(EdgeType.EXPOSES_DATA.value,),
            )
        }
        assert EdgeType.EXPOSES_DATA.value in outs


@pytest.mark.asyncio
async def test_trap_mis_keyed_agent_creates_a_second_node() -> None:
    # The guard must FAIL (2 nodes) if an agent keys the bucket by NAME instead of the canonical ARN
    # — the exact bug shape that disconnected the graph once.
    async with in_memory_semantic_store() as store:
        await CloudKgWriter(store, _T).upsert_asset("s3-bucket", _ARN, {"is_public": True})
        await IdentityKgWriter(store, _T).record_access(
            [("arn:aws:iam::1:role/r", _BUCKET_NAME)]
        )  # BAD key
        keys = {r.external_id for r in await _resources(store)}
        assert _ARN in keys and _BUCKET_NAME in keys
        assert len(keys) == 2, "mis-keying must produce a divergent node — proves the guard bites"
