"""Path #20 — K8s RBAC privilege escalation, REAL e2e.

Drives k8s-posture's REAL RBAC inventory parser + writer against a canned cluster reader: a
ServiceAccount bound to a cluster-admin ClusterRole (wildcard verbs on wildcard resources)
surfaces the rbac_privilege_escalation path; a read-only role stays dark.
"""

import pytest
from meta_harness.attack_paths import AttackPathRanker
from meta_harness.kg_query import KgQuery

from fleet_testkit import in_memory_semantic_store
from fleet_testkit.k8s_workloads import cluster_admin_rbac_reader, drive_cluster_inventory

_TENANT = "tenant-rbac"


@pytest.mark.asyncio
async def test_cluster_admin_bound_sa_lights_up() -> None:
    async with in_memory_semantic_store() as store:
        await drive_cluster_inventory(
            store,
            tenant_id=_TENANT,
            cluster_id="prod",
            reader=cluster_admin_rbac_reader(admin=True),
        )
        paths = await AttackPathRanker(KgQuery(store, _TENANT)).find_all()
        rp = [p for p in paths if p.path_type == "rbac_privilege_escalation"]
        assert len(rp) == 1
        assert rp[0].severity == 76
        assert "cluster-admin" in rp[0].title


@pytest.mark.asyncio
async def test_scoped_role_is_dark() -> None:
    async with in_memory_semantic_store() as store:
        await drive_cluster_inventory(
            store,
            tenant_id=_TENANT,
            cluster_id="prod",
            reader=cluster_admin_rbac_reader(admin=False),  # read-only pods role
        )
        paths = await AttackPathRanker(KgQuery(store, _TENANT)).find_all()
        assert not [p for p in paths if p.path_type == "rbac_privilege_escalation"]
