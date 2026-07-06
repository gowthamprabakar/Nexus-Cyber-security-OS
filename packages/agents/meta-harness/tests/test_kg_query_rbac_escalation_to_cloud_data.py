"""Unit tests for find_rbac_escalation_to_cloud_data — cluster-admin SA + IRSA→cloud-data combo.

Three properties proven:
1. A SA that BINDS an is_admin role AND has IRSA_MAPPING→role→data fires with the right ids.
2. A SA that is admin-only (no IRSA→data) does NOT fire.
3. A SA with IRSA→data but NOT is_admin does NOT fire (the intersection is real).
"""

from __future__ import annotations

import pytest
from charter.memory.graph_types import EdgeType, NodeCategory
from fleet_testkit import in_memory_semantic_store
from meta_harness.kg_query import KgQuery, RbacEscalationToCloudData

_T = "tenant-rbac-cloud"

_K8S = NodeCategory.K8S_OBJECT.value
_ID = NodeCategory.IDENTITY.value
_CR = NodeCategory.CLOUD_RESOURCE.value
_DC = NodeCategory.DATA_CLASSIFICATION.value


async def _seed_full_combo(store) -> dict[str, str]:  # type: ignore[type-arg]
    """SA that BINDS is_admin role AND has IRSA_MAPPING → cloud role → resource → data."""
    ids: dict[str, str] = {}
    # Service account
    ids["sa"] = await store.upsert_entity(
        tenant_id=_T,
        entity_type=_K8S,
        external_id="sa:default/deployer",
        properties={"kind": "service-account", "name": "deployer"},
    )
    # Admin role (RBAC K8S_OBJECT)
    ids["admin_role"] = await store.upsert_entity(
        tenant_id=_T,
        entity_type=_K8S,
        external_id="clusterrole:cluster-admin",
        properties={"kind": "clusterrole", "name": "cluster-admin", "is_admin": True},
    )
    # Cloud IAM role (IDENTITY, via IRSA_MAPPING)
    ids["cloud_role"] = await store.upsert_entity(
        tenant_id=_T,
        entity_type=_ID,
        external_id="arn:aws:iam::123:role/pod-role",
        properties={"name": "pod-role"},
    )
    # Cloud resource
    ids["bucket"] = await store.upsert_entity(
        tenant_id=_T,
        entity_type=_CR,
        external_id="arn:aws:s3:::pii-bucket",
        properties={"is_public": True},
    )
    # Data classification
    ids["dc"] = await store.upsert_entity(
        tenant_id=_T,
        entity_type=_DC,
        external_id="dc:pii",
        properties={"data_type": "pii"},
    )
    # Edges
    await store.add_relationship(
        tenant_id=_T,
        src_entity_id=ids["sa"],
        dst_entity_id=ids["admin_role"],
        relationship_type=EdgeType.BINDS.value,
        properties={},
    )
    await store.add_relationship(
        tenant_id=_T,
        src_entity_id=ids["sa"],
        dst_entity_id=ids["cloud_role"],
        relationship_type=EdgeType.IRSA_MAPPING.value,
        properties={},
    )
    await store.add_relationship(
        tenant_id=_T,
        src_entity_id=ids["cloud_role"],
        dst_entity_id=ids["bucket"],
        relationship_type=EdgeType.HAS_ACCESS_TO.value,
        properties={},
    )
    await store.add_relationship(
        tenant_id=_T,
        src_entity_id=ids["bucket"],
        dst_entity_id=ids["dc"],
        relationship_type=EdgeType.EXPOSES_DATA.value,
        properties={},
    )
    return ids


@pytest.mark.asyncio
async def test_full_combo_fires() -> None:
    """SA with BOTH admin binding AND IRSA→data fires the detector with the right ids."""
    async with in_memory_semantic_store() as store:
        ids = await _seed_full_combo(store)
        hits = await KgQuery(store, _T).find_rbac_escalation_to_cloud_data()
        assert len(hits) == 1
        h = hits[0]
        assert isinstance(h, RbacEscalationToCloudData)
        assert h.subject_id == ids["sa"]
        assert h.admin_role_id == ids["admin_role"]
        assert h.cloud_role_id == ids["cloud_role"]
        assert h.resource_id == ids["bucket"]
        assert h.data_classification_id == ids["dc"]
        assert h.data_type == "pii"
        assert h.role_name == "cluster-admin"


@pytest.mark.asyncio
async def test_admin_only_does_not_fire() -> None:
    """SA with admin binding but NO IRSA→data does NOT fire."""
    async with in_memory_semantic_store() as store:
        sa = await store.upsert_entity(
            tenant_id=_T,
            entity_type=_K8S,
            external_id="sa:default/admin-only",
            properties={"kind": "service-account", "name": "admin-only"},
        )
        admin_role = await store.upsert_entity(
            tenant_id=_T,
            entity_type=_K8S,
            external_id="clusterrole:admin-only-role",
            properties={"kind": "clusterrole", "name": "admin-only-role", "is_admin": True},
        )
        await store.add_relationship(
            tenant_id=_T,
            src_entity_id=sa,
            dst_entity_id=admin_role,
            relationship_type=EdgeType.BINDS.value,
            properties={},
        )
        hits = await KgQuery(store, _T).find_rbac_escalation_to_cloud_data()
        assert hits == []


@pytest.mark.asyncio
async def test_irsa_data_only_does_not_fire() -> None:
    """SA with IRSA→data but is_admin=False on the bound role does NOT fire."""
    async with in_memory_semantic_store() as store:
        sa = await store.upsert_entity(
            tenant_id=_T,
            entity_type=_K8S,
            external_id="sa:default/irsa-only",
            properties={"kind": "service-account", "name": "irsa-only"},
        )
        # Non-admin role binding (is_admin absent / False)
        role = await store.upsert_entity(
            tenant_id=_T,
            entity_type=_K8S,
            external_id="clusterrole:reader",
            properties={"kind": "clusterrole", "name": "reader", "is_admin": False},
        )
        cloud_role = await store.upsert_entity(
            tenant_id=_T,
            entity_type=_ID,
            external_id="arn:aws:iam::123:role/irsa-role",
            properties={"name": "irsa-role"},
        )
        bucket = await store.upsert_entity(
            tenant_id=_T,
            entity_type=_CR,
            external_id="arn:aws:s3:::data-bucket",
            properties={"is_public": True},
        )
        dc = await store.upsert_entity(
            tenant_id=_T,
            entity_type=_DC,
            external_id="dc:pii2",
            properties={"data_type": "ssn"},
        )
        await store.add_relationship(
            tenant_id=_T,
            src_entity_id=sa,
            dst_entity_id=role,
            relationship_type=EdgeType.BINDS.value,
            properties={},
        )
        await store.add_relationship(
            tenant_id=_T,
            src_entity_id=sa,
            dst_entity_id=cloud_role,
            relationship_type=EdgeType.IRSA_MAPPING.value,
            properties={},
        )
        await store.add_relationship(
            tenant_id=_T,
            src_entity_id=cloud_role,
            dst_entity_id=bucket,
            relationship_type=EdgeType.HAS_ACCESS_TO.value,
            properties={},
        )
        await store.add_relationship(
            tenant_id=_T,
            src_entity_id=bucket,
            dst_entity_id=dc,
            relationship_type=EdgeType.EXPOSES_DATA.value,
            properties={},
        )
        hits = await KgQuery(store, _T).find_rbac_escalation_to_cloud_data()
        assert hits == []
