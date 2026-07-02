"""NEX-104 e2e — multi-cloud-posture now makes Azure/GCP public resources attack-path SOURCES.

Before this, multi-cloud-posture wrote only AFFECTS → Azure/GCP public resources never became sources,
so multi-cloud attack paths could not form (the parity gap at the graph level). Proves an Azure blob /
GCS bucket marked exposed by multi-cloud-posture is now a `public_resource` source that reaches data.
"""

import pytest
from charter.canonical import azure_blob_uri, gcs_uri
from charter.memory.graph_types import EdgeType, NodeCategory
from meta_harness.attack_paths import AttackPathRanker
from meta_harness.kg_query import KgQuery
from meta_harness.path_taxonomy import match_source
from multi_cloud_posture.tools.kg_writer import KnowledgeGraphWriter as McpKgWriter

from fleet_testkit import in_memory_semantic_store

_T = "tenant-mcp"


async def _data_on(store, resource_key):
    d = await store.upsert_entity(
        tenant_id=_T,
        entity_type=NodeCategory.DATA_CLASSIFICATION.value,
        external_id=f"{resource_key}:sec",
        properties={"data_type": "private_key"},  # a SECRET type
    )
    # the exposed resource node already exists (record_exposed_resources); attach EXPOSES_DATA
    for r in await store.list_entities_by_type(
        tenant_id=_T, entity_type=NodeCategory.CLOUD_RESOURCE.value
    ):
        if r.external_id == resource_key:
            await store.add_relationship(
                tenant_id=_T,
                src_entity_id=r.entity_id,
                dst_entity_id=d,
                relationship_type=EdgeType.EXPOSES_DATA.value,
                properties={},
            )
            return


@pytest.mark.parametrize("resource_key", [azure_blob_uri("acct", "pii"), gcs_uri("crown")])
@pytest.mark.asyncio
async def test_multicloud_public_resource_is_a_source(resource_key) -> None:
    async with in_memory_semantic_store() as store:
        # multi-cloud-posture flags the Azure/GCP resource as publicly exposed → source-marked
        await McpKgWriter(store, _T).record_exposed_resources([resource_key])
        await _data_on(store, resource_key)

        # (1) NEX-104 core: the Azure/GCP resource is now a `public_resource` SOURCE (was inert)
        node = next(
            r
            for r in await store.list_entities_by_type(
                tenant_id=_T, entity_type=NodeCategory.CLOUD_RESOURCE.value
            )
            if r.external_id == resource_key
        )
        assert match_source(NodeCategory.CLOUD_RESOURCE.value, node.properties) == "public_resource"

        # (2) and a real exposure path forms for it (named public-data archetype)
        paths = await AttackPathRanker(KgQuery(store, _T)).find_all()
        assert any(node.entity_id in p.entities for p in paths), (
            f"an attack path must form for the exposed multi-cloud resource {resource_key}"
        )
