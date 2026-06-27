"""Keystone test: the ARN-group writers (cloud-posture, data-security, identity),
writing INDEPENDENTLY about the same bucket, converge to ONE CLOUD_RESOURCE node.

This proves the canonical-key foundation by RUNNING the real writers (ADR-023) — the
template for verifying every future cross-agent path actually joins, not by assumption."""

import pytest
from charter.canonical import s3_bucket_arn
from charter.memory.graph_types import NodeCategory
from cloud_posture.tools.kg_writer import KnowledgeGraphWriter as CpWriter
from data_security.kg_writer import KnowledgeGraphWriter as DsWriter
from data_security.schemas import ClassifierLabel
from identity.kg_writer import KnowledgeGraphWriter as IdWriter

from fleet_testkit import assert_single_node, in_memory_semantic_store


class _Acl:
    grants_all_users = True
    grants_authenticated_users = False


class _Enc:
    algorithm = "NONE"


class _Bucket:
    def __init__(self, name: str) -> None:
        self.name = name
        self.region = "us-east-1"
        self.acl = _Acl()
        self.encryption = _Enc()


@pytest.mark.asyncio
async def test_arn_group_writers_converge_to_one_node():
    name = "acme-pii"
    arn = s3_bucket_arn(name)
    role_arn = "arn:aws:iam::1:role/app"
    async with in_memory_semantic_store() as store:
        # Three agents, independently, about the SAME bucket:
        await CpWriter(store, "t").upsert_asset("s3-bucket", arn, {"region": "us-east-1"})
        await DsWriter(store, "t").record([_Bucket(name)], {name: [ClassifierLabel.SSN]})
        await IdWriter(store, "t").record_access([(role_arn, arn)])

        # They MUST collapse to ONE cloud_resource node, keyed by the canonical ARN.
        await assert_single_node(
            store,
            tenant_id="t",
            entity_type=NodeCategory.CLOUD_RESOURCE.value,
            external_id=arn,
        )
