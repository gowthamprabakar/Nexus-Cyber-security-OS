"""Unit tests for find_exposed_kms_key_over_data — public KMS key + EXPOSES_DATA intersection.

Three properties proven:
1. A kms-key with is_public=True AND an EXPOSES_DATA edge fires with right ids + data_type.
2. A kms-key with is_public=True but NO EXPOSES_DATA edge returns [] (bare exposed key only).
3. A kms-key with is_public=False (private) WITH EXPOSES_DATA returns [] (both legs required).
"""

from __future__ import annotations

import pytest
from charter.memory.graph_types import EdgeType, NodeCategory
from fleet_testkit import in_memory_semantic_store
from meta_harness.kg_query import ExposedKmsKeyOverData, KgQuery

_T = "tenant-exposed-kms-over-data"
_CR = NodeCategory.CLOUD_RESOURCE.value
_DC = NodeCategory.DATA_CLASSIFICATION.value

_KEY_ARN = "arn:aws:kms:us-east-1:123456789012:key/test-key-1"
_DATA_EXT_ID = f"{_KEY_ARN}:protected"
_DATA_TYPE = "ssn"


async def _seed_kms_key(
    store,  # type: ignore[type-arg]
    *,
    tenant: str = _T,
    key_arn: str = _KEY_ARN,
    is_public: bool,
    add_exposes_data: bool,
    data_type: str = _DATA_TYPE,
) -> tuple[str, str]:
    """Seed a kms-key node and optionally an EXPOSES_DATA edge to a DATA_CLASSIFICATION.

    Returns (key_entity_id, dc_entity_id).  dc_entity_id is empty string when
    add_exposes_data=False (no DATA_CLASSIFICATION node created).
    """
    key_id = await store.upsert_entity(
        tenant_id=tenant,
        entity_type=_CR,
        external_id=key_arn,
        properties={"kind": "kms-key", "is_public": is_public},
    )
    if not add_exposes_data:
        return key_id, ""

    dc_id = await store.upsert_entity(
        tenant_id=tenant,
        entity_type=_DC,
        external_id=f"{key_arn}:protected",
        properties={"data_type": data_type},
    )
    await store.add_relationship(
        tenant_id=tenant,
        src_entity_id=key_id,
        dst_entity_id=dc_id,
        relationship_type=EdgeType.EXPOSES_DATA.value,
        properties={},
    )
    return key_id, dc_id


# ---------------------------------------------------------------------------
# Test 1: intersection fires correctly
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_detects_public_kms_key_with_exposed_data() -> None:
    """A kms-key with is_public=True AND EXPOSES_DATA --> DATA_CLASSIFICATION fires 1 hit."""
    async with in_memory_semantic_store() as store:
        key_id, dc_id = await _seed_kms_key(
            store,
            is_public=True,
            add_exposes_data=True,
        )
        hits = await KgQuery(store, _T).find_exposed_kms_key_over_data()

        assert len(hits) == 1, f"expected 1 hit, got {len(hits)}: {hits}"
        hit = hits[0]
        assert isinstance(hit, ExposedKmsKeyOverData)
        assert hit.resource_id == key_id, (
            f"resource_id mismatch: got {hit.resource_id!r}, want {key_id!r}"
        )
        assert hit.data_classification_id == dc_id, (
            f"data_classification_id mismatch: got {hit.data_classification_id!r}, want {dc_id!r}"
        )
        assert hit.data_type == _DATA_TYPE, (
            f"data_type mismatch: got {hit.data_type!r}, want {_DATA_TYPE!r}"
        )


# ---------------------------------------------------------------------------
# Test 2: public key with NO EXPOSES_DATA edge returns [] (bare exposed key only)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_public_kms_key_without_exposes_data_is_dark() -> None:
    """A kms-key with is_public=True but no EXPOSES_DATA edge must return [] from
    find_exposed_kms_key_over_data.  It IS a bare exposed key (path #21) but NOT
    the deeper intersection combo (path P4b) — both legs are required."""
    async with in_memory_semantic_store() as store:
        await _seed_kms_key(
            store,
            is_public=True,
            add_exposes_data=False,
        )
        hits = await KgQuery(store, _T).find_exposed_kms_key_over_data()
        assert hits == [], f"expected [] for public kms-key with no EXPOSES_DATA edge; got {hits}"


# ---------------------------------------------------------------------------
# Test 3: private key with EXPOSES_DATA returns [] (is_public=False → leg A fails)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_private_kms_key_with_exposes_data_is_dark() -> None:
    """A kms-key with is_public=False (private) AND EXPOSES_DATA must return [].

    The protected-data leg alone is not sufficient — the key policy must ALSO be
    internet-open (is_public=True) for the P4b combo to fire."""
    async with in_memory_semantic_store() as store:
        await _seed_kms_key(
            store,
            is_public=False,
            add_exposes_data=True,
        )
        hits = await KgQuery(store, _T).find_exposed_kms_key_over_data()
        assert hits == [], f"expected [] for private kms-key with EXPOSES_DATA edge; got {hits}"
