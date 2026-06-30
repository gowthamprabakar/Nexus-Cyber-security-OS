"""Slice #1 on GCP — the GCP identity graph SPINE now exists and is productive.

Mirror of the AWS/Azure e2e on the third cloud: drives the data GCP already computes
(``storage_read_grants`` + ``escalation_grants``) through the existing writers and proves the GCP
identity spine is productive — principals graphed, CAN_ESCALATE_TO works, an access→data path emerges.
"""

import pytest
from charter.canonical import gcs_uri
from charter.memory.graph_types import EdgeType, NodeCategory
from identity.kg_writer import KnowledgeGraphWriter as IdentityKgWriter
from identity.tools.gcp_iam import GcpIamBinding, escalation_grants, storage_read_grants
from meta_harness.attack_paths import AttackPathRanker
from meta_harness.kg_query import KgQuery

from fleet_testkit import in_memory_semantic_store

_T = "tenant-gcpescal"
_ATTACKER = "user:attacker@corp.example"  # securityAdmin
_OWNER = "user:owner@corp.example"  # roles/owner
_READER = "user:reader@corp.example"  # storage.objectViewer
_BUCKET = "pii-bucket"
_PROJECT = "projects/prod"


def _project_bindings() -> tuple[GcpIamBinding, ...]:
    return (
        GcpIamBinding(_PROJECT, "roles/iam.securityAdmin", (_ATTACKER,)),
        GcpIamBinding(_PROJECT, "roles/owner", (_OWNER,)),
    )


def _bucket_bindings() -> tuple[GcpIamBinding, ...]:
    return (GcpIamBinding(_BUCKET, "roles/storage.objectViewer", (_READER,)),)


async def _id_of(store, external_id: str) -> str:
    for r in await store.list_entities_by_type(
        tenant_id=_T, entity_type=NodeCategory.IDENTITY.value
    ):
        if r.external_id == external_id:
            return r.entity_id
    raise AssertionError(f"no identity node {external_id}")


@pytest.mark.asyncio
async def test_gcp_identity_spine_is_productive() -> None:
    blob_uri = gcs_uri(_BUCKET)
    async with in_memory_semantic_store() as store:
        writer = IdentityKgWriter(store, _T)
        await writer.record_escalation_grants(escalation_grants(_project_bindings()))
        await writer.record_access(storage_read_grants(_bucket_bindings()))
        blob = await store.upsert_entity(
            tenant_id=_T,
            entity_type=NodeCategory.CLOUD_RESOURCE.value,
            external_id=blob_uri,
            properties={"is_public": True},
        )
        data = await store.upsert_entity(
            tenant_id=_T,
            entity_type=NodeCategory.DATA_CLASSIFICATION.value,
            external_id=f"{blob_uri}:pii",
            properties={"data_type": "ssn"},
        )
        await store.add_relationship(
            tenant_id=_T,
            src_entity_id=blob,
            dst_entity_id=data,
            relationship_type=EdgeType.EXPOSES_DATA.value,
            properties={},
        )

        # (1) GCP principals are now on the spine.
        idents = {
            r.external_id
            for r in await store.list_entities_by_type(
                tenant_id=_T, entity_type=NodeCategory.IDENTITY.value
            )
        }
        assert {_ATTACKER, _OWNER, _READER} <= idents

        # (2) CAN_ESCALATE_TO works on GCP (attacker -> owner).
        escal = await store.get_relationships_from(
            tenant_id=_T,
            src_entity_id=await _id_of(store, _ATTACKER),
            edge_types=(EdgeType.CAN_ESCALATE_TO.value,),
        )
        assert escal and escal[0].dst_entity_id == await _id_of(store, _OWNER)
        assert escal[0].properties.get("method") == "self_grant_admin"

        # (3) A GCP access→data attack path emerges — the spine is productive.
        paths = await AttackPathRanker(KgQuery(store, _T)).find_all()
        fine = [p for p in paths if p.path_type == "fine_grained_data"]
        assert fine, "the storage-reader's access to the public GCS bucket is now an attack path"
        assert any(blob_uri in p.entities or data in p.entities for p in fine)
