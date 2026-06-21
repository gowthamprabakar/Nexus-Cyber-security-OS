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
    """The SAME bucket written by cloud-posture (by ARN) and data-security must
    collapse to ONE graph node — the precondition for any cross-agent correlation."""
    name = "acme-pii"
    arn = s3_bucket_arn(name)
    async with in_memory_semantic_store() as store:
        cp = CpWriter(store, "tenant-1")
        cp_id = await cp.upsert_asset("s3-bucket", arn, {"region": "us-east-1"})

        ds = DsWriter(store, "tenant-1")
        ds_id = await store.upsert_entity(
            tenant_id="tenant-1",
            entity_type="cloud_resource",
            external_id=arn,
            properties={},
        )
        # data-security's writer, after the fix, must use the same key:
        assert ds._storage_external_id(name) == arn  # helper added in Step 3
        assert cp_id == ds_id  # one bucket, one node
