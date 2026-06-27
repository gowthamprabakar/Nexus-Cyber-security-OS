"""Path #19 — exposed managed database (publicly-accessible RDS), REAL e2e.

Drives cloud-posture's REAL RDS reader against a moto RDS instance: a ``PubliclyAccessible`` DB
surfaces the exposed_database path; a private one stays dark.
"""

import pytest
from meta_harness.attack_paths import AttackPathRanker
from meta_harness.kg_query import KgQuery

from fleet_testkit import in_memory_semantic_store
from fleet_testkit.moto_aws import drive_rds_instances, moto_rds_client, setup_rds_instance

_TENANT = "tenant-rds"


@pytest.mark.asyncio
async def test_public_rds_instance_lights_up() -> None:
    async with in_memory_semantic_store() as store:
        with moto_rds_client() as rds:
            setup_rds_instance(rds, name="prod-db", public=True, engine="postgres")
            instances = await drive_rds_instances(store, tenant_id=_TENANT, rds_client=rds)
        assert instances and instances[0].is_public, "the RDS instance was read as public"

        paths = await AttackPathRanker(KgQuery(store, _TENANT)).find_all()
        db = [p for p in paths if p.path_type == "exposed_database"]
        assert len(db) == 1, "a publicly-accessible managed database surfaces one path"
        assert db[0].severity == 84
        assert "postgres" in db[0].evidence


@pytest.mark.asyncio
async def test_private_rds_instance_is_dark() -> None:
    async with in_memory_semantic_store() as store:
        with moto_rds_client() as rds:
            setup_rds_instance(rds, name="internal-db", public=False)
            await drive_rds_instances(store, tenant_id=_TENANT, rds_client=rds)
        paths = await AttackPathRanker(KgQuery(store, _TENANT)).find_all()
        assert not [p for p in paths if p.path_type == "exposed_database"]
