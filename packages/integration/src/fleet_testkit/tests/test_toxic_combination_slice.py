"""End-to-end proof: public bucket + PII + over-permissioned role → ONE toxic finding.

Drives the REAL agent writers (not hand-built edges) so the slice proves the
cross-agent wiring, not just the detector in isolation."""

import pytest
from charter.memory.graph_types import NodeCategory
from cloud_posture.tools.kg_writer import KnowledgeGraphWriter as CpWriter
from data_security.canonical import s3_bucket_arn
from data_security.kg_writer import KnowledgeGraphWriter as DsWriter
from data_security.schemas import ClassifierLabel
from identity.kg_writer import KnowledgeGraphWriter as IdWriter
from investigation.toxic_combination import ToxicCombinationWriter, to_hypothesis
from meta_harness.kg_query import KgQuery

from fleet_testkit import in_memory_semantic_store


class _Acl:
    grants_all_users = True
    grants_authenticated_users = False


class _Enc:
    algorithm = "NONE"


class _Bucket:  # minimal stand-in for BucketInventory
    def __init__(self, name, public):
        self.name = name
        self.region = "us-east-1"
        self.acl = (
            _Acl()
            if public
            else type("A", (), {"grants_all_users": False, "grants_authenticated_users": False})()
        )
        self.encryption = _Enc()


async def _run_slice(store, *, public, has_access):
    t = "tenant-1"
    name = "acme-pii"
    arn = s3_bucket_arn(name)
    role_arn = "arn:aws:iam::1:role/app"

    await CpWriter(store, t).upsert_asset("s3-bucket", arn, {"region": "us-east-1"})
    await DsWriter(store, t).record([_Bucket(name, public)], {name: [ClassifierLabel.SSN]})
    if has_access:
        await IdWriter(store, t).record_access([(role_arn, arn)])

    role_id = await store.upsert_entity(
        tenant_id=t, entity_type=NodeCategory.IDENTITY.value, external_id=role_arn, properties={}
    )
    return await KgQuery(store, t).find_public_data_exposure(
        over_permissioned_principal_ids=[role_id]
    )


@pytest.mark.asyncio
async def test_full_slice_lights_up_one_toxic_combination():
    async with in_memory_semantic_store() as store:
        hits = await _run_slice(store, public=True, has_access=True)
        assert len(hits) == 1
        node_id = await ToxicCombinationWriter(store, "tenant-1").record(hits[0])
        assert node_id
        h = to_hypothesis(hits[0], evidence_refs=("finding:dspm-acme-pii-SSN",))
        assert h.confidence == 1.0


@pytest.mark.asyncio
async def test_full_slice_dark_when_private():
    async with in_memory_semantic_store() as store:
        assert await _run_slice(store, public=False, has_access=True) == []


@pytest.mark.asyncio
async def test_full_slice_dark_when_no_access():
    async with in_memory_semantic_store() as store:
        assert await _run_slice(store, public=True, has_access=False) == []
