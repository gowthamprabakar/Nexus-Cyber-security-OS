"""Path #21 — exposed KMS key policy (internet-open), REAL e2e.

Drives cloud-posture's REAL KMS reader against moto: a key with a wildcard-principal Allow in its
key policy surfaces the exposed_kms_key path; a default (root-only) policy stays dark.
"""

import pytest
from meta_harness.attack_paths import AttackPathRanker
from meta_harness.kg_query import KgQuery

from fleet_testkit import in_memory_semantic_store
from fleet_testkit.moto_aws import drive_kms_keys, moto_kms_client, setup_kms_key

_TENANT = "tenant-kms"


@pytest.mark.asyncio
async def test_public_kms_key_lights_up() -> None:
    async with in_memory_semantic_store() as store:
        with moto_kms_client() as kms:
            setup_kms_key(kms, public=True)
            keys = await drive_kms_keys(store, tenant_id=_TENANT, kms_client=kms)
        assert keys and keys[0].is_public, "the KMS key policy was read as internet-open"

        paths = await AttackPathRanker(KgQuery(store, _TENANT)).find_all()
        kp = [p for p in paths if p.path_type == "exposed_kms_key"]
        assert len(kp) == 1
        assert kp[0].severity == 72


@pytest.mark.asyncio
async def test_default_policy_kms_key_is_dark() -> None:
    async with in_memory_semantic_store() as store:
        with moto_kms_client() as kms:
            setup_kms_key(kms, public=False)  # default root-only policy
            await drive_kms_keys(store, tenant_id=_TENANT, kms_client=kms)
        paths = await AttackPathRanker(KgQuery(store, _TENANT)).find_all()
        assert not [p for p in paths if p.path_type == "exposed_kms_key"]
