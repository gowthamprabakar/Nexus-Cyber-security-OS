"""Multi-cloud DB + VM attack-path e2e — Azure SQL/VM + GCP Cloud SQL/Compute Engine (B-2).

Proves ``find_exposed_database`` fires on Azure SQL Database and GCP Cloud SQL, and
``find_internet_exposed_host_vulnerable`` fires on Azure VMs and GCP Compute Engine instances,
with NO detector change — both detectors are cloud-agnostic:

- ``find_exposed_database`` filters on ``CLOUD_RESOURCE{kind="rds-instance", is_public=True}``
- ``find_internet_exposed_host_vulnerable`` filters on ``CLOUD_RESOURCE{is_public=True}`` +
  a DIRECT ``VULNERABLE_TO`` edge; it does NOT check ``kind``

This test drives the NEW ``record_sql_instances`` / ``record_vm_instances`` writers (B-2) to
stamp the spine nodes. Hermetic: in-memory store only, no SDK calls.
"""

import pytest
from charter.memory.graph_types import EdgeType, NodeCategory
from meta_harness.kg_query import KgQuery
from multi_cloud_posture.tools.kg_writer import KnowledgeGraphWriter as MultiCloudKgWriter
from multi_cloud_posture.tools.kg_writer import SqlInstanceRecord, VmInstanceRecord

from fleet_testkit import in_memory_semantic_store

_TENANT_AZ_DB = "tenant-b2-azure-db"
_TENANT_GCP_DB = "tenant-b2-gcp-db"
_TENANT_AZ_VM = "tenant-b2-azure-vm"
_TENANT_GCP_VM = "tenant-b2-gcp-vm"
_TENANT_DARK = "tenant-b2-dark"

# Azure SQL resource ids
_AZ_SQL_ID = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Sql/servers/db1"
_AZ_SQL_ENGINE = "sqlserver"

# GCP Cloud SQL resource names
_GCP_SQL_ID = "projects/p/instances/db"
_GCP_SQL_ENGINE = "mysql"

# Azure VM resource ids
_AZ_VM_ID = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm1"
_AZ_CVE_ID = "CVE-2024-AZ-001"

# GCP Compute Engine resource names
_GCP_VM_ID = "projects/p/zones/us-central1-a/instances/vm"
_GCP_CVE_ID = "CVE-2024-GCP-001"


# ---------------------------------------------------------------------------
# find_exposed_database — Azure SQL
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_azure_sql_exposed_database_fires() -> None:
    """find_exposed_database returns a hit for an Azure SQL Database with is_public=True."""
    async with in_memory_semantic_store() as store:
        await MultiCloudKgWriter(store, _TENANT_AZ_DB).record_sql_instances(
            [SqlInstanceRecord(instance_id=_AZ_SQL_ID, is_public=True, engine=_AZ_SQL_ENGINE)]
        )

        hits = await KgQuery(store, _TENANT_AZ_DB).find_exposed_database()
        assert hits, "Azure SQL exposed_database path must fire"
        # Resolve internal entity_ids back to external_ids to confirm canonical id was stored
        db_entities = [
            await store.get_entity(tenant_id=_TENANT_AZ_DB, entity_id=h.resource_id) for h in hits
        ]
        external_ids = {e.external_id for e in db_entities if e is not None}
        assert _AZ_SQL_ID in external_ids, (
            f"Azure SQL resource id must be the spine node external_id; got {external_ids}"
        )
        assert any(h.engine == _AZ_SQL_ENGINE for h in hits), f"engine must be '{_AZ_SQL_ENGINE}'"


# ---------------------------------------------------------------------------
# find_exposed_database — GCP Cloud SQL
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_gcp_cloud_sql_exposed_database_fires() -> None:
    """find_exposed_database returns a hit for a GCP Cloud SQL instance with is_public=True."""
    async with in_memory_semantic_store() as store:
        await MultiCloudKgWriter(store, _TENANT_GCP_DB).record_sql_instances(
            [SqlInstanceRecord(instance_id=_GCP_SQL_ID, is_public=True, engine=_GCP_SQL_ENGINE)]
        )

        hits = await KgQuery(store, _TENANT_GCP_DB).find_exposed_database()
        assert hits, "GCP Cloud SQL exposed_database path must fire"
        db_entities = [
            await store.get_entity(tenant_id=_TENANT_GCP_DB, entity_id=h.resource_id) for h in hits
        ]
        external_ids = {e.external_id for e in db_entities if e is not None}
        assert _GCP_SQL_ID in external_ids, (
            f"GCP Cloud SQL resource name must be the spine node external_id; got {external_ids}"
        )
        assert any(h.engine == _GCP_SQL_ENGINE for h in hits), f"engine must be '{_GCP_SQL_ENGINE}'"


# ---------------------------------------------------------------------------
# find_exposed_database — darkness case (is_public=False)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_private_sql_instance_is_dark() -> None:
    """A private SQL instance (is_public=False) must NOT appear in find_exposed_database."""
    async with in_memory_semantic_store() as store:
        await MultiCloudKgWriter(store, _TENANT_DARK).record_sql_instances(
            [
                SqlInstanceRecord(instance_id=_AZ_SQL_ID, is_public=False, engine=_AZ_SQL_ENGINE),
                SqlInstanceRecord(instance_id=_GCP_SQL_ID, is_public=False, engine=_GCP_SQL_ENGINE),
            ]
        )
        hits = await KgQuery(store, _TENANT_DARK).find_exposed_database()
        assert hits == [], (
            f"private SQL instances must not appear in find_exposed_database; got {hits}"
        )


# ---------------------------------------------------------------------------
# find_internet_exposed_host_vulnerable — Azure VM
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_azure_vm_host_vuln_fires() -> None:
    """find_internet_exposed_host_vulnerable fires for a public Azure VM with a VULNERABLE_TO CVE."""
    async with in_memory_semantic_store() as store:
        # Stamp the Azure VM spine node via multi-cloud-posture writer
        await MultiCloudKgWriter(store, _TENANT_AZ_VM).record_vm_instances(
            [VmInstanceRecord(instance_id=_AZ_VM_ID, is_public=True)]
        )
        # Retrieve the internal entity_id for the VM node so we can add the edge
        vm_node_id = await store.upsert_entity(
            tenant_id=_TENANT_AZ_VM,
            entity_type=NodeCategory.CLOUD_RESOURCE.value,
            external_id=_AZ_VM_ID,
            properties={"kind": "vm-instance", "is_public": True},
        )
        # Plant the CVE_FINDING node
        cve_node_id = await store.upsert_entity(
            tenant_id=_TENANT_AZ_VM,
            entity_type=NodeCategory.CVE_FINDING.value,
            external_id=_AZ_CVE_ID,
            properties={"severity": "CRITICAL"},
        )
        # Add the direct VULNERABLE_TO edge from the VM to the CVE
        await store.add_relationship(
            tenant_id=_TENANT_AZ_VM,
            src_entity_id=vm_node_id,
            dst_entity_id=cve_node_id,
            relationship_type=EdgeType.VULNERABLE_TO.value,
            properties={},
        )

        hits = await KgQuery(store, _TENANT_AZ_VM).find_internet_exposed_host_vulnerable()
        assert hits, "Azure VM host-vuln path must fire"
        # Confirm the host_id resolves back to the Azure VM resource id
        vm_entities = [
            await store.get_entity(tenant_id=_TENANT_AZ_VM, entity_id=h.host_id) for h in hits
        ]
        external_ids = {e.external_id for e in vm_entities if e is not None}
        assert _AZ_VM_ID in external_ids, (
            f"Azure VM resource id must be the spine node external_id; got {external_ids}"
        )
        assert any(h.cve_id == _AZ_CVE_ID for h in hits), f"CVE external_id must be '{_AZ_CVE_ID}'"


# ---------------------------------------------------------------------------
# find_internet_exposed_host_vulnerable — GCP Compute Engine
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_gcp_compute_host_vuln_fires() -> None:
    """find_internet_exposed_host_vulnerable fires for a public GCP VM with a VULNERABLE_TO CVE."""
    async with in_memory_semantic_store() as store:
        # Stamp the GCP Compute Engine spine node via multi-cloud-posture writer
        await MultiCloudKgWriter(store, _TENANT_GCP_VM).record_vm_instances(
            [VmInstanceRecord(instance_id=_GCP_VM_ID, is_public=True)]
        )
        # Retrieve/ensure the internal entity_id
        vm_node_id = await store.upsert_entity(
            tenant_id=_TENANT_GCP_VM,
            entity_type=NodeCategory.CLOUD_RESOURCE.value,
            external_id=_GCP_VM_ID,
            properties={"kind": "vm-instance", "is_public": True},
        )
        # Plant the CVE_FINDING node
        cve_node_id = await store.upsert_entity(
            tenant_id=_TENANT_GCP_VM,
            entity_type=NodeCategory.CVE_FINDING.value,
            external_id=_GCP_CVE_ID,
            properties={"severity": "HIGH"},
        )
        # Add the direct VULNERABLE_TO edge
        await store.add_relationship(
            tenant_id=_TENANT_GCP_VM,
            src_entity_id=vm_node_id,
            dst_entity_id=cve_node_id,
            relationship_type=EdgeType.VULNERABLE_TO.value,
            properties={},
        )

        hits = await KgQuery(store, _TENANT_GCP_VM).find_internet_exposed_host_vulnerable()
        assert hits, "GCP Compute Engine host-vuln path must fire"
        vm_entities = [
            await store.get_entity(tenant_id=_TENANT_GCP_VM, entity_id=h.host_id) for h in hits
        ]
        external_ids = {e.external_id for e in vm_entities if e is not None}
        assert _GCP_VM_ID in external_ids, (
            f"GCP Compute Engine resource name must be the spine node external_id; got {external_ids}"
        )
        assert any(h.cve_id == _GCP_CVE_ID for h in hits), (
            f"CVE external_id must be '{_GCP_CVE_ID}'"
        )
