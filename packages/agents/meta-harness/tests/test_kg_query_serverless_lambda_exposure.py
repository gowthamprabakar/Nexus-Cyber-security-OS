"""Unit tests — find_serverless_lambda_exposure detector (Cycle 6).

Graph pattern:
  CLOUD_RESOURCE{kind=lambda-function, is_public=True}
    --ASSUMES--> IDENTITY(role)
    --HAS_ACCESS_TO--> CLOUD_RESOURCE(bucket)
    --EXPOSES_DATA--> DATA_CLASSIFICATION

The DISCRIMINATOR is kind=lambda-function:
- Positive: public lambda + role reaches data → fires
- Negative 1 (private lambda): NOT public + same edges → dark
- Negative 2 (ec2 kind gate): ec2-instance (not lambda) with same edges → dark
"""

from __future__ import annotations

import pytest
from charter.memory.graph_types import EdgeType, NodeCategory
from fleet_testkit import in_memory_semantic_store
from meta_harness.kg_query import KgQuery, ServerlessLambdaExposure

_TENANT = "t-lambda-exposure"

_CR = NodeCategory.CLOUD_RESOURCE.value
_IDENTITY = NodeCategory.IDENTITY.value
_DC = NodeCategory.DATA_CLASSIFICATION.value

_LAMBDA_ARN = "arn:aws:lambda:us-east-1:123456789012:function/public-fn"
_ROLE_ARN = "arn:aws:iam::123456789012:role/lambda-exec-role"
_BUCKET_ARN = "arn:aws:s3:::lambda-pii-bucket"
_DC_EXT_ID = f"{_BUCKET_ARN}:pii"


async def _seed_scene(
    store,  # type: ignore[type-arg]
    *,
    fn_kind: str,
    is_public: bool,
    tenant: str = _TENANT,
) -> tuple[str, str, str, str]:
    """Seed full Lambda exposure scene; return (fn_id, role_id, bucket_id, dc_id)."""
    fn_id = await store.upsert_entity(
        tenant_id=tenant,
        entity_type=_CR,
        external_id=_LAMBDA_ARN,
        properties={"kind": fn_kind, "is_public": is_public},
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
        src_entity_id=fn_id,
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
    return fn_id, role_id, bucket_id, dc_id


@pytest.mark.asyncio
async def test_serverless_lambda_exposure_positive() -> None:
    """Public lambda-function + role reaches data → one ServerlessLambdaExposure hit."""
    async with in_memory_semantic_store() as store:
        fn_id, role_id, bucket_id, dc_id = await _seed_scene(
            store, fn_kind="lambda-function", is_public=True
        )
        hits = await KgQuery(store, _TENANT).find_serverless_lambda_exposure()

    assert len(hits) == 1, f"expected 1 hit, got {len(hits)}: {hits}"
    h = hits[0]
    assert isinstance(h, ServerlessLambdaExposure)
    assert h.function_id == fn_id, f"function_id mismatch: {h.function_id!r} != {fn_id!r}"
    assert h.role_id == role_id, f"role_id mismatch: {h.role_id!r} != {role_id!r}"
    assert h.resource_id == bucket_id, f"resource_id mismatch: {h.resource_id!r} != {bucket_id!r}"
    assert h.data_classification_id == dc_id, (
        f"dc_id mismatch: {h.data_classification_id!r} != {dc_id!r}"
    )
    assert h.data_type == "pii", f"data_type mismatch: {h.data_type!r}"


@pytest.mark.asyncio
async def test_serverless_lambda_exposure_private_lambda_stays_dark() -> None:
    """Private lambda (is_public=False) → no hit even with role reaching data."""
    async with in_memory_semantic_store() as store:
        await _seed_scene(
            store, fn_kind="lambda-function", is_public=False, tenant="t-lambda-private"
        )
        hits = await KgQuery(store, "t-lambda-private").find_serverless_lambda_exposure()

    assert hits == [], f"expected no hits for private lambda; got {hits}"


@pytest.mark.asyncio
async def test_serverless_lambda_exposure_ec2_kind_gate_stays_dark() -> None:
    """EC2 instance with same edges (public + ASSUMES → role → data) must NOT fire.

    This is the kind-gate proof: the detector is for lambda-function ONLY.
    An ec2-instance node with is_public=True and the full ASSUMES chain must stay dark.
    """
    async with in_memory_semantic_store() as store:
        await _seed_scene(store, fn_kind="ec2-instance", is_public=True, tenant="t-ec2-gate")
        hits = await KgQuery(store, "t-ec2-gate").find_serverless_lambda_exposure()

    assert hits == [], (
        f"expected no hits for ec2-instance kind (kind gate proof); got {hits}. "
        "The detector must check kind='lambda-function' to stay dark for non-Lambda nodes."
    )
