"""Unit tests — find_imds_credential_theft detector (Cycle 5 Task 1).

Graph pattern:
  CLOUD_RESOURCE{kind=ec2-instance, is_public=True, imdsv1_enabled=True}
    --ASSUMES--> IDENTITY(role)
    --HAS_ACCESS_TO--> CLOUD_RESOURCE(bucket)
    --EXPOSES_DATA--> DATA_CLASSIFICATION

The DISCRIMINATOR is imdsv1_enabled:
- Positive: public + IMDSv1 + role reaches data → fires
- Negative 1 (IMDSv2): public + IMDSv2 (imdsv1_enabled=False) → dark
- Negative 2 (private): NOT public + IMDSv1 → dark
"""

from __future__ import annotations

import pytest
from charter.memory.graph_types import EdgeType, NodeCategory
from fleet_testkit import in_memory_semantic_store
from meta_harness.kg_query import ImdsCredentialTheft, KgQuery

_TENANT = "t-imds-cred"

_CR = NodeCategory.CLOUD_RESOURCE.value
_IDENTITY = NodeCategory.IDENTITY.value
_DC = NodeCategory.DATA_CLASSIFICATION.value

_INSTANCE_ARN = "arn:aws:ec2:us-east-1:123456789012:instance/i-imds"
_ROLE_ARN = "arn:aws:iam::123456789012:role/imds-role"
_BUCKET_ARN = "arn:aws:s3:::imds-pii-bucket"
_DC_EXT_ID = f"{_BUCKET_ARN}:pii"


async def _seed_scene(
    store,  # type: ignore[type-arg]
    *,
    is_public: bool,
    imdsv1_enabled: bool,
    tenant: str = _TENANT,
) -> tuple[str, str, str, str]:
    """Seed full IMDS cred-theft scene; return (inst_id, role_id, bucket_id, dc_id)."""
    inst_id = await store.upsert_entity(
        tenant_id=tenant,
        entity_type=_CR,
        external_id=_INSTANCE_ARN,
        properties={
            "kind": "ec2-instance",
            "is_public": is_public,
            "imdsv1_enabled": imdsv1_enabled,
        },
    )
    role_id = await store.upsert_entity(
        tenant_id=tenant,
        entity_type=_IDENTITY,
        external_id=_ROLE_ARN,
        properties={},
    )
    bucket_id = await store.upsert_entity(
        tenant_id=tenant,
        entity_type=_CR,
        external_id=_BUCKET_ARN,
        properties={"kind": "s3-bucket", "is_public": True},
    )
    dc_id = await store.upsert_entity(
        tenant_id=tenant,
        entity_type=_DC,
        external_id=_DC_EXT_ID,
        properties={"data_type": "pii"},
    )
    await store.add_relationship(
        tenant_id=tenant,
        src_entity_id=inst_id,
        dst_entity_id=role_id,
        relationship_type=EdgeType.ASSUMES.value,
        properties={},
    )
    await store.add_relationship(
        tenant_id=tenant,
        src_entity_id=role_id,
        dst_entity_id=bucket_id,
        relationship_type=EdgeType.HAS_ACCESS_TO.value,
        properties={},
    )
    await store.add_relationship(
        tenant_id=tenant,
        src_entity_id=bucket_id,
        dst_entity_id=dc_id,
        relationship_type=EdgeType.EXPOSES_DATA.value,
        properties={},
    )
    return inst_id, role_id, bucket_id, dc_id


@pytest.mark.asyncio
async def test_imds_credential_theft_positive() -> None:
    """Public + IMDSv1 + role reaches data → one ImdsCredentialTheft hit."""
    async with in_memory_semantic_store() as store:
        inst_id, role_id, bucket_id, dc_id = await _seed_scene(
            store, is_public=True, imdsv1_enabled=True
        )
        hits = await KgQuery(store, _TENANT).find_imds_credential_theft()

    assert len(hits) == 1, f"expected 1 hit, got {len(hits)}: {hits}"
    h = hits[0]
    assert isinstance(h, ImdsCredentialTheft)
    assert h.instance_id == inst_id, f"instance_id mismatch: {h.instance_id!r} != {inst_id!r}"
    assert h.role_id == role_id, f"role_id mismatch: {h.role_id!r} != {role_id!r}"
    assert h.resource_id == bucket_id, f"resource_id mismatch: {h.resource_id!r} != {bucket_id!r}"
    assert h.data_classification_id == dc_id, (
        f"dc_id mismatch: {h.data_classification_id!r} != {dc_id!r}"
    )
    assert h.data_type == "pii", f"data_type mismatch: {h.data_type!r}"


@pytest.mark.asyncio
async def test_imds_credential_theft_imdsv2_stays_dark() -> None:
    """IMDSv2-only (imdsv1_enabled=False) → no hit even though public + role reaches data."""
    async with in_memory_semantic_store() as store:
        await _seed_scene(store, is_public=True, imdsv1_enabled=False, tenant="t-imds-safe")
        hits = await KgQuery(store, "t-imds-safe").find_imds_credential_theft()

    assert hits == [], f"expected no hits for IMDSv2 instance; got {hits}"


@pytest.mark.asyncio
async def test_imds_credential_theft_private_instance_stays_dark() -> None:
    """Private instance (is_public=False) → no hit even with IMDSv1 enabled."""
    async with in_memory_semantic_store() as store:
        await _seed_scene(store, is_public=False, imdsv1_enabled=True, tenant="t-imds-private")
        hits = await KgQuery(store, "t-imds-private").find_imds_credential_theft()

    assert hits == [], f"expected no hits for private instance; got {hits}"
