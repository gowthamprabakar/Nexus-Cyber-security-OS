"""Cross-agent entity-resolution test — bucket is ONE node across cloud-posture and data-security.

Task 1 of the toxic-combination slice: cloud-posture keys its CLOUD_RESOURCE spine node
by ARN; data-security must use the SAME key so the two writes collapse to one node (via
upsert_entity's idempotency on (tenant, type, external_id)). This test is the
precondition for any cross-agent correlation.
"""

from __future__ import annotations

import pytest
from cloud_posture.tools.kg_writer import KnowledgeGraphWriter as CpWriter
from data_security.canonical import s3_bucket_arn
from data_security.kg_writer import KnowledgeGraphWriter as DsWriter

from fleet_testkit import in_memory_semantic_store


@pytest.mark.asyncio
async def test_bucket_is_one_node_across_cloud_posture_and_data_security():
    """The SAME bucket written by cloud-posture (by ARN) and data-security (now also
    by ARN) must collapse to ONE graph node — precondition for cross-agent correlation."""
    name = "acme-pii"
    arn = s3_bucket_arn(name)
    async with in_memory_semantic_store() as store:
        # cloud-posture writes the resource keyed by ARN (return value intentionally ignored):
        await CpWriter(store, "tenant-1").upsert_asset("s3-bucket", arn, {"region": "us-east-1"})
        # data-security, after the fix, keys its storage node by the SAME ARN:
        assert DsWriter._storage_external_id(name) == arn
        # simulate data-security's storage-node write at that key:
        await store.upsert_entity(
            tenant_id="tenant-1", entity_type="cloud_resource", external_id=arn, properties={}
        )
        # invariant: exactly ONE cloud_resource node exists for that ARN, not two.
        nodes = await store.list_entities_by_type(
            tenant_id="tenant-1", entity_type="cloud_resource"
        )
        assert [n.external_id for n in nodes].count(arn) == 1
        assert len(nodes) == 1
