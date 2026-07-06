"""Full-parity e2e: data_security.run() Blob/GCS record_data_sources writes BOTH edges natively.

Cycle 4 P2 proof — the SINK side of the native fine-grained path is now written by a real
data-security agent (NOT hand-seeded) via the ScanSources.ds_gcs_inventory and
ScanSources.ds_azure_blob_inventory seams.

Three pieces cooperate in ONE shared SemanticStore per test:
  1. scan_run data-security feeder: ds_gcs_inventory (or ds_azure_blob_inventory) +
     ds_blob_gcs_classifier_hits → data_security.run() calls record_data_sources →
     CLOUD_RESOURCE(gcs_uri / azure_blob_uri, is_public=True) --EXPOSES_DATA-->
     DATA_CLASSIFICATION(ssn)
  2. scan_run identity feeder: gcp_iam_bindings (or azure_role_assignments) →
     identity.run() calls storage_read_grants / blob_read_grants → record_access →
     IDENTITY --HAS_ACCESS_TO--> CLOUD_RESOURCE(gcs_uri / azure_blob_uri)
  3. analyze → find_fine_grained_data_exposure → confirmed path_type "fine_grained_data"

Join keys:
  GCP:   gcs_uri("gcp-pii-p2") shared between ds_gcs_inventory canonical_key
         and the GCP IAM grant's storage_read_grants resource side.
  Azure: azure_blob_uri("p2store", "p2-container") shared between
         ds_azure_blob_inventory canonical_key and blob_read_grants resource side.

Both edges are written by REAL agents — not hand-seeded — proving end-to-end parity.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
import pytest_asyncio
from charter.canonical import azure_blob_uri, gcs_uri
from charter.memory.models import Base
from charter.memory.semantic import SemanticStore
from data_security.schemas import ClassifierLabel
from data_security.tools.azure_blob_inventory import AzureBlobContainer
from data_security.tools.gcs_inventory import GcsBucket
from identity.tools.azure_rbac import AzureRoleAssignment
from identity.tools.gcp_iam import GcpIamBinding
from nexus_runtime.scan_pipeline import ScanSources, scan_run
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

_NOW = datetime(2026, 7, 6, tzinfo=UTC)

# ---------------------------------------------------------------------------
# GCP constants
# ---------------------------------------------------------------------------

_TENANT_GCP = "tenant-p2-gcp-e2e"
_GCP_BUCKET = "gcp-pii-p2"
_GCS_URI = gcs_uri(_GCP_BUCKET)
_GCP_SA = "serviceAccount:p2-reader@my-project.iam.gserviceaccount.com"

# ---------------------------------------------------------------------------
# Azure constants
# ---------------------------------------------------------------------------

_TENANT_AZ = "tenant-p2-azure-e2e"
_AZ_ACCOUNT = "p2store"
_AZ_CONTAINER = "p2-container"
_AZURE_BLOB = azure_blob_uri(_AZ_ACCOUNT, _AZ_CONTAINER)
_AZURE_MI = "mi-p2-reader-obj-id"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def gcp_session_factory() -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield async_sessionmaker(engine, expire_on_commit=False)
    await engine.dispose()


@pytest_asyncio.fixture
async def azure_session_factory() -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield async_sessionmaker(engine, expire_on_commit=False)
    await engine.dispose()


# ---------------------------------------------------------------------------
# GCP full-parity e2e
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_scan_run_gcp_full_parity_both_edges_real(
    tmp_path: Path,
    gcp_session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Full-parity proof: BOTH edges written by real agents — NOT hand-seeded.

    data-security feeder writes:
      CLOUD_RESOURCE(gs://gcp-pii-p2) --EXPOSES_DATA--> DATA_CLASSIFICATION(ssn)
    identity feeder writes:
      IDENTITY(GCP-SA) --HAS_ACCESS_TO--> CLOUD_RESOURCE(gs://gcp-pii-p2)
    analyze → find_fine_grained_data_exposure → fine_grained_data confirmed.

    Join key: gcs_uri("gcp-pii-p2") == "gs://gcp-pii-p2" shared between
    ds_gcs_inventory canonical_key and GcpIamBinding.bucket.
    """
    gcs_bucket = GcsBucket(
        project="my-project",
        name=_GCP_BUCKET,
        location="us-central1",
        iam_members=("allUsers",),  # is_public=True — EXPOSES_DATA will be written
        encrypted=True,
    )
    bindings = (
        GcpIamBinding(
            bucket=_GCP_BUCKET,
            role="roles/storage.objectViewer",
            members=(_GCP_SA,),
        ),
    )

    sources = ScanSources(
        # P2: data-security writes CLOUD_RESOURCE + EXPOSES_DATA → DATA_CLASSIFICATION
        ds_gcs_inventory=(gcs_bucket,),
        ds_blob_gcs_classifier_hits={_GCP_BUCKET: (ClassifierLabel.SSN,)},
        # P1: identity writes HAS_ACCESS_TO
        gcp_iam_bindings=bindings,
    )

    res = await scan_run(
        session_factory=gcp_session_factory,
        tenant=_TENANT_GCP,
        sources=sources,
        workspace_root=tmp_path / "ws_gcp",
    )

    failed = [f for f in res.feeders if not f.ok]
    assert not failed, f"feeder(s) failed: {failed}"

    feeder_names = {f.agent for f in res.feeders}
    assert "data-security" in feeder_names, (
        f"data-security feeder did not run — check activation condition; feeders={feeder_names}"
    )
    assert "identity" in feeder_names, f"identity feeder did not run; feeders={feeder_names}"

    path_types = [p.path_type for p in res.confirmed]
    assert "fine_grained_data" in path_types, (
        f"expected fine_grained_data confirmed path (both edges written by real agents); "
        f"got path_types={path_types}. "
        f"Join key: GCP-SA={_GCP_SA!r} bucket={_GCP_BUCKET!r} gcs_uri={_GCS_URI!r}. "
        f"data-security wrote CLOUD_RESOURCE({_GCS_URI!r}) --EXPOSES_DATA--> DATA_CLASSIFICATION; "
        f"identity wrote IDENTITY({_GCP_SA!r}) --HAS_ACCESS_TO--> CLOUD_RESOURCE({_GCS_URI!r})."
    )

    # Verify the store has BOTH edges (belt + suspenders).
    store = SemanticStore(gcp_session_factory)
    resources = await store.list_entities_by_type(
        tenant_id=_TENANT_GCP, entity_type="cloud_resource"
    )
    gcs_nodes = [r for r in resources if r.external_id == _GCS_URI]
    assert len(gcs_nodes) == 1, (
        f"expected one CLOUD_RESOURCE node keyed by {_GCS_URI!r}; got {[r.external_id for r in resources]}"
    )
    assert gcs_nodes[0].properties["is_public"] is True


# ---------------------------------------------------------------------------
# Azure full-parity e2e
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_scan_run_azure_full_parity_both_edges_real(
    tmp_path: Path,
    azure_session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Full-parity proof: BOTH edges written by real agents for Azure-MI → Blob path.

    data-security feeder writes:
      CLOUD_RESOURCE(azure://p2store/p2-container) --EXPOSES_DATA--> DATA_CLASSIFICATION(ssn)
    identity feeder writes:
      IDENTITY(Azure-MI) --HAS_ACCESS_TO--> CLOUD_RESOURCE(azure://p2store/p2-container)
    analyze → find_fine_grained_data_exposure → fine_grained_data confirmed.

    Join key: azure_blob_uri("p2store", "p2-container") shared between
    ds_azure_blob_inventory canonical_key and AzureRoleAssignment scope.
    """
    blob_container = AzureBlobContainer(
        storage_account=_AZ_ACCOUNT,
        container=_AZ_CONTAINER,
        region="eastus",
        public_access="container",  # is_public=True — EXPOSES_DATA will be written
        encrypted=True,
    )
    # AzureRoleAssignment scope encodes the container path that blob_read_grants parses.
    assignments = (
        AzureRoleAssignment(
            principal_id=_AZURE_MI,
            role_name="Storage Blob Data Reader",
            scope=(
                f"/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Storage"
                f"/storageAccounts/{_AZ_ACCOUNT}/blobServices/default/containers/{_AZ_CONTAINER}"
            ),
        ),
    )
    # DataSource.identifier for Azure = "{account}/{container}"
    az_identifier = f"{_AZ_ACCOUNT}/{_AZ_CONTAINER}"

    sources = ScanSources(
        # P2: data-security writes CLOUD_RESOURCE + EXPOSES_DATA → DATA_CLASSIFICATION
        ds_azure_blob_inventory=(blob_container,),
        ds_blob_gcs_classifier_hits={az_identifier: (ClassifierLabel.SSN,)},
        # P1b: identity writes HAS_ACCESS_TO
        azure_role_assignments=assignments,
    )

    res = await scan_run(
        session_factory=azure_session_factory,
        tenant=_TENANT_AZ,
        sources=sources,
        workspace_root=tmp_path / "ws_azure",
    )

    failed = [f for f in res.feeders if not f.ok]
    assert not failed, f"feeder(s) failed: {failed}"

    feeder_names = {f.agent for f in res.feeders}
    assert "data-security" in feeder_names, (
        f"data-security feeder did not run; feeders={feeder_names}"
    )
    assert "identity" in feeder_names, f"identity feeder did not run; feeders={feeder_names}"

    path_types = [p.path_type for p in res.confirmed]
    assert "fine_grained_data" in path_types, (
        f"expected fine_grained_data confirmed path (both edges written by real agents); "
        f"got path_types={path_types}. "
        f"Join key: MI={_AZURE_MI!r} container={_AZ_CONTAINER!r} azure_blob_uri={_AZURE_BLOB!r}. "
        f"data-security wrote CLOUD_RESOURCE({_AZURE_BLOB!r}) --EXPOSES_DATA--> DATA_CLASSIFICATION; "
        f"identity wrote IDENTITY({_AZURE_MI!r}) --HAS_ACCESS_TO--> CLOUD_RESOURCE({_AZURE_BLOB!r})."
    )

    # Verify the store has the CLOUD_RESOURCE node from the real data-security feeder.
    store = SemanticStore(azure_session_factory)
    resources = await store.list_entities_by_type(
        tenant_id=_TENANT_AZ, entity_type="cloud_resource"
    )
    blob_nodes = [r for r in resources if r.external_id == _AZURE_BLOB]
    assert len(blob_nodes) == 1, (
        f"expected one CLOUD_RESOURCE node keyed by {_AZURE_BLOB!r}; got {[r.external_id for r in resources]}"
    )
    assert blob_nodes[0].properties["is_public"] is True
    assert blob_nodes[0].properties["resource_type"] == "azure-storage"
