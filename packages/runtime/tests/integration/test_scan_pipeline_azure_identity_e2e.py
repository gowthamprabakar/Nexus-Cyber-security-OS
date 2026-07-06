"""End-to-end: Azure-MI identity seam through scan_run yields a fine_grained_data path.

Cycle 4 P1b proof (task-2-report — Azure identity seam, gap #13 parity).

Three pieces cooperate in ONE shared SemanticStore:
  1. Pre-seed: data_security KnowledgeGraphWriter.record_data_sources writes
     CLOUD_RESOURCE(azure_blob_uri, is_public=True) --EXPOSES_DATA--> DATA_CLASSIFICATION(ssn)
  2. scan_run identity feeder: azure_role_assignments (Azure-MI with Storage Blob Data Reader on
     pii-container) causes identity.run() to call blob_read_grants → record_access →
     IDENTITY(Azure-MI) --HAS_ACCESS_TO--> CLOUD_RESOURCE(azure_blob_uri)
  3. analyze → find_fine_grained_data_exposure → confirmed path_type "fine_grained_data"

Join key: azure_blob_uri("mystorage", "pii-container") shared between the Azure RBAC grant
resource side (blob_read_grants) and the data node written by record_data_sources.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
import pytest_asyncio
from charter.canonical import azure_blob_uri
from charter.memory.models import Base
from charter.memory.semantic import SemanticStore
from data_security.kg_writer import KnowledgeGraphWriter as DsKgWriter
from data_security.schemas import ClassifierLabel
from data_security.tools.data_source import DataCloud, DataSource
from identity.tools.azure_rbac import AzureRoleAssignment
from nexus_runtime.scan_pipeline import ScanSources, scan_run
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

_NOW = datetime(2026, 7, 6, tzinfo=UTC)
_TENANT = "tenant-azure-identity-e2e"

_STORAGE_ACCOUNT = "azpiistore"
_CONTAINER = "pii-data"
_AZURE_BLOB = azure_blob_uri(_STORAGE_ACCOUNT, _CONTAINER)
_AZURE_MI_ID = "mi-reader-obj-id-12345"


@pytest_asyncio.fixture
async def session_factory() -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield async_sessionmaker(engine, expire_on_commit=False)
    await engine.dispose()


def _azure_blob_data_source(
    storage_account: str, container: str, *, is_public: bool = True
) -> DataSource:
    """A public Azure Blob container DataSource — mirrors the GCS fixture used in test_scan_pipeline_gcp_identity_e2e.

    Azure DataSource.identifier must be "{storage_account}/{container}" so that
    canonical_key correctly computes azure_blob_uri(account, container).
    """
    return DataSource(
        cloud=DataCloud.AZURE,
        identifier=f"{storage_account}/{container}",
        region="eastus",
        is_public=is_public,
        is_encrypted=True,
    )


async def _seed_azure_blob_data(
    session_factory: async_sessionmaker[AsyncSession],
    tenant: str,
    storage_account: str,
    container: str,
) -> None:
    """Pre-seed CLOUD_RESOURCE(azure_blob_uri) --EXPOSES_DATA--> DATA_CLASSIFICATION(ssn).

    Simulates what data_security.run() will do when the Azure Blob data-side path is wired (P2).
    For this e2e we hand-seed it so the join key is available when identity writes HAS_ACCESS_TO.
    classifier_hits_by_identifier is keyed by DataSource.identifier (not canonical_key).
    """
    identifier = f"{storage_account}/{container}"
    store = SemanticStore(session_factory)
    writer = DsKgWriter(store, tenant)
    source = _azure_blob_data_source(storage_account, container)
    await writer.record_data_sources(
        [source],
        {identifier: [ClassifierLabel.SSN]},
    )


# ---------------------------------------------------------------------------
# Test B-1: fine_grained_data fires via Azure-MI → Blob (core P1b proof)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_scan_run_azure_mi_fine_grained_data_fires(
    tmp_path: Path,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """P1b proof: Azure-MI with Storage Blob Data Reader on a public PII container → fine_grained_data.

    1. Pre-seed CLOUD_RESOURCE(azure_blob_uri) --EXPOSES_DATA--> DATA_CLASSIFICATION(ssn)
    2. scan_run azure_role_assignments (Azure-MI → Storage Blob Data Reader → pii-data container)
    3. identity writes HAS_ACCESS_TO(Azure-MI, azure_blob_uri)
    4. analyze → find_fine_grained_data_exposure → confirmed "fine_grained_data"
    """
    # Pre-seed the Azure Blob data node (the P2 sink half of the path).
    await _seed_azure_blob_data(session_factory, _TENANT, _STORAGE_ACCOUNT, _CONTAINER)

    assignments = (
        AzureRoleAssignment(
            principal_id=_AZURE_MI_ID,
            role_name="Storage Blob Data Reader",
            scope=(
                f"/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Storage"
                f"/storageAccounts/{_STORAGE_ACCOUNT}/blobServices/default/containers/{_CONTAINER}"
            ),
        ),
    )

    sources = ScanSources(azure_role_assignments=assignments)

    res = await scan_run(
        session_factory=session_factory,
        tenant=_TENANT,
        sources=sources,
        workspace_root=tmp_path / "ws",
    )

    failed = [f for f in res.feeders if not f.ok]
    assert not failed, f"feeder(s) failed: {failed}"

    feeder_names = {f.agent for f in res.feeders}
    assert "identity" in feeder_names, f"identity feeder missing from {feeder_names}"

    path_types = [p.path_type for p in res.confirmed]
    assert "fine_grained_data" in path_types, (
        f"expected fine_grained_data confirmed path from Azure-MI with blob read grant; "
        f"got path_types={path_types}. "
        f"Join key: MI={_AZURE_MI_ID!r} container={_CONTAINER!r} azure_blob_uri={_AZURE_BLOB!r}. "
        f"Check: identity wrote IDENTITY({_AZURE_MI_ID!r}) --HAS_ACCESS_TO--> "
        f"CLOUD_RESOURCE({_AZURE_BLOB!r}); pre-seed wrote EXPOSES_DATA."
    )
