"""Slice #1 on Azure — the Azure identity graph SPINE now exists and is productive.

Azure identity previously wrote ZERO nodes/edges to the fleet graph (the structural reason Azure
coverage was stuck). This drives the data Azure already computes (blob access + escalation) through
the existing writers, and proves: (1) Azure principals + access + escalation edges now land on the
graph, (2) the SAME CAN_ESCALATE_TO edge works on a second cloud, (3) an Azure access→data attack
path EMERGES — the spine is productive, not dormant.
"""

import pytest
from charter.canonical import azure_blob_uri
from charter.memory.graph_types import EdgeType, NodeCategory
from identity.kg_writer import KnowledgeGraphWriter as IdentityKgWriter
from identity.tools.azure_rbac import AzureRoleAssignment, blob_read_grants, escalation_grants
from meta_harness.attack_paths import AttackPathRanker
from meta_harness.kg_query import KgQuery

from fleet_testkit import in_memory_semantic_store

_T = "tenant-azescal"
_ATTACKER = "11111111-1111-1111-1111-111111111111"  # User Access Administrator
_OWNER = "22222222-2222-2222-2222-222222222222"  # Owner
_READER = "33333333-3333-3333-3333-333333333333"  # Storage Blob Data Reader on a container
_SUB = "/subscriptions/sub-1"
_CONTAINER = f"{_SUB}/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/acct/blobServices/default/containers/pii"


def _assignments() -> tuple[AzureRoleAssignment, ...]:
    return (
        AzureRoleAssignment(_ATTACKER, "User Access Administrator", _SUB),
        AzureRoleAssignment(_OWNER, "Owner", _SUB),
        AzureRoleAssignment(_READER, "Storage Blob Data Reader", _CONTAINER),
    )


async def _id_of(store, external_id: str) -> str:
    for r in await store.list_entities_by_type(
        tenant_id=_T, entity_type=NodeCategory.IDENTITY.value
    ):
        if r.external_id == external_id:
            return r.entity_id
    raise AssertionError(f"no identity node {external_id}")


@pytest.mark.asyncio
async def test_azure_identity_spine_is_productive() -> None:
    assignments = _assignments()
    blob_uri = azure_blob_uri("acct", "pii")
    async with in_memory_semantic_store() as store:
        writer = IdentityKgWriter(store, _T)
        # The spine: the Azure data identity already computes, now WRITTEN to the graph.
        await writer.record_escalation_grants(escalation_grants(assignments))
        await writer.record_access(blob_read_grants(assignments))
        # data-security side: the public Azure blob exposing sensitive data (canonical key match).
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

        # (1) The Azure identity graph now EXISTS — principals are on the spine.
        idents = {
            r.external_id
            for r in await store.list_entities_by_type(
                tenant_id=_T, entity_type=NodeCategory.IDENTITY.value
            )
        }
        assert {_ATTACKER, _OWNER, _READER} <= idents, "Azure principals are now graphed"

        # (2) The SAME CAN_ESCALATE_TO edge works on Azure (attacker -> Owner).
        escal = await store.get_relationships_from(
            tenant_id=_T,
            src_entity_id=await _id_of(store, _ATTACKER),
            edge_types=(EdgeType.CAN_ESCALATE_TO.value,),
        )
        assert escal and escal[0].dst_entity_id == await _id_of(store, _OWNER)
        assert escal[0].properties.get("method") == "self_grant_admin"

        # (3) An Azure access→data attack path EMERGES — the spine is productive.
        paths = await AttackPathRanker(KgQuery(store, _T)).find_all()
        fine = [p for p in paths if p.path_type == "fine_grained_data"]
        assert fine, (
            "the blob-data principal's access to the public Azure blob is now an attack path"
        )
        assert any(blob_uri in p.entities or data in p.entities for p in fine)
