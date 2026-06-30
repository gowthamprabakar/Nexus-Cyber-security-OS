"""W6 e2e — a public workload's embedded credential's blast radius emerges.

A public ECS service embeds a long-lived AWS key belonging to an over-permissioned user. Drives the
REAL cloud-posture detector + writer (STORES_SECRET) and identity (OWNED_BY owner + access), proving:
``public workload --STORES_SECRET--> secret --OWNED_BY--> identity --HAS_ACCESS_TO--> data``.
"""

import pytest
from charter.memory.graph_types import EdgeType, NodeCategory
from cloud_posture.tools.kg_writer import KnowledgeGraphWriter as CloudKgWriter
from cloud_posture.tools.stored_secrets import stored_secret_grants
from identity.kg_writer import KnowledgeGraphWriter as IdentityKgWriter
from meta_harness.path_engine import find_candidate_paths

from fleet_testkit import in_memory_semantic_store

_T = "tenant-stored"
_SVC = "arn:aws:ecs:us-east-1:111:service/web"
_KEY = "AKIA" + "EXAMPLE0STORED99"
_USER = "arn:aws:iam::111:user/ci"
_BUCKET = "arn:aws:s3:::crown"


@pytest.mark.asyncio
async def test_stored_credential_blast_radius_emerges() -> None:
    grants = stored_secret_grants([(_SVC, [f"AWS_ACCESS_KEY_ID={_KEY}"])])
    async with in_memory_semantic_store() as store:
        cloud = CloudKgWriter(store, _T)
        # the public workload + the STORES_SECRET edge
        await store.upsert_entity(
            tenant_id=_T,
            entity_type=NodeCategory.CLOUD_RESOURCE.value,
            external_id=_SVC,
            properties={"is_public": True},
        )
        await cloud.record_stored_secrets(grants)
        # identity: that key is owned by ci, who can read the crown bucket
        ident = IdentityKgWriter(store, _T)
        await ident.record_credential_ownership([(_USER, _KEY)])  # writes OWNS + OWNED_BY
        await ident.record_access([(_USER, _BUCKET)])
        bucket = await store.upsert_entity(
            tenant_id=_T,
            entity_type=NodeCategory.CLOUD_RESOURCE.value,
            external_id=_BUCKET,
            properties={},
        )
        data = await store.upsert_entity(
            tenant_id=_T,
            entity_type=NodeCategory.DATA_CLASSIFICATION.value,
            external_id=f"{_BUCKET}/pii",
            properties={"data_type": "ssn"},
        )
        await store.add_relationship(
            tenant_id=_T,
            src_entity_id=bucket,
            dst_entity_id=data,
            relationship_type=EdgeType.EXPOSES_DATA.value,
            properties={},
        )

        cands = await find_candidate_paths(store, _T)
        stored = [c for c in cands if "STORES_SECRET" in c.path.edge_signature]
        assert stored, "a public workload's embedded credential reaching data must surface"
        assert stored[0].path.edge_signature == (
            "STORES_SECRET",
            "OWNED_BY",
            "HAS_ACCESS_TO",
            "EXPOSES_DATA",
        )
        assert stored[0].path.sink_marker == "sensitive_data"
