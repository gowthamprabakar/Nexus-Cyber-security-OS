"""NEX-202 spike proof — KMS/DB impact needs NO new sink category or walker change.

The feared problem: `walk_paths` matches sinks by entity-type CATEGORY, so KMS/DB (written as
CLOUD_RESOURCE) can't be a sink without breaking the walker or orphaning access edges. The reframe:
a KMS key / database that ``EXPOSES_DATA`` to a DATA_CLASSIFICATION node reaches the EXISTING data
sink — ``principal → HAS_ACCESS_TO → kms-key → EXPOSES_DATA → data`` traverses today. This proves it,
so NEX-202-IMPL is a DETECTION ticket (write EXPOSES_DATA for KMS/DB), not a substrate rewrite.
"""

import pytest
from charter.memory.graph_types import EdgeType, NodeCategory
from identity.kg_writer import KnowledgeGraphWriter as IdentityKgWriter
from meta_harness.attack_paths import AttackPathRanker
from meta_harness.kg_query import KgQuery

from fleet_testkit import in_memory_semantic_store

_T = "kms-spike"


@pytest.mark.parametrize(
    "kind,key",
    [
        ("kms-key", "arn:aws:kms:us-east-1:1:key/abc"),
        ("database", "arn:aws:rds:us-east-1:1:db/crown"),
    ],
)
@pytest.mark.asyncio
async def test_kms_or_db_access_reaches_data_with_no_walker_change(kind, key) -> None:
    async with in_memory_semantic_store() as store:
        # a principal can use the KMS key / reach the DB (record_access upserts the resource node)
        await IdentityKgWriter(store, _T).record_access([("arn:aws:iam::1:role/app", key)])
        # the KMS key protects (or the DB holds) sensitive data — modeled as EXPOSES_DATA (the reframe)
        res_id = await store.upsert_entity(
            tenant_id=_T,
            entity_type=NodeCategory.CLOUD_RESOURCE.value,
            external_id=key,
            properties={"kind": kind},
        )
        data_id = await store.upsert_entity(
            tenant_id=_T,
            entity_type=NodeCategory.DATA_CLASSIFICATION.value,
            external_id=f"{key}:data",
            properties={"data_type": "ssn"},
        )
        await store.add_relationship(
            tenant_id=_T,
            src_entity_id=res_id,
            dst_entity_id=data_id,
            relationship_type=EdgeType.EXPOSES_DATA.value,
            properties={},
        )

        # the existing named ranker (fine_grained) surfaces it — reaching the KMS/DB reaches data
        paths = await AttackPathRanker(KgQuery(store, _T)).find_all()
        assert any(res_id in p.entities and data_id in p.entities for p in paths), (
            f"access to a {kind} that EXPOSES_DATA must reach the existing data sink (no walker change)"
        )
