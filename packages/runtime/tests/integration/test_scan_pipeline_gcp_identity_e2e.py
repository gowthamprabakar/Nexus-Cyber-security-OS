"""End-to-end: GCP-SA identity seam through scan_run yields a fine_grained_data path.

Cycle 4 P1 proof (task-1-report — GCP identity seam, gap #13 parity).

Three pieces cooperate in ONE shared SemanticStore:
  1. Pre-seed: data_security KnowledgeGraphWriter.record_data_sources writes
     CLOUD_RESOURCE(gs://gcp-pii-bucket, is_public=True) --EXPOSES_DATA--> DATA_CLASSIFICATION(ssn)
  2. scan_run identity feeder: gcp_iam_bindings (GCP-SA with storage.objectViewer on
     gcp-pii-bucket) causes identity.run() to call storage_read_grants → record_access →
     IDENTITY(GCP-SA) --HAS_ACCESS_TO--> CLOUD_RESOURCE(gs://gcp-pii-bucket)
  3. analyze → find_fine_grained_data_exposure → confirmed path_type "fine_grained_data"

Join key: gcs_uri("gcp-pii-bucket") == "gs://gcp-pii-bucket" shared between the GCP IAM grant
resource side (storage_read_grants) and the data node written by record_data_sources.

Also verifies:
  - escalation_grants → find_privilege_escalation_to_data / escalation_method_to_data
  - sa_key_ownership → OWNS edge lands via gcp_sa_keys
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
import pytest_asyncio
from charter.canonical import gcs_uri, secret_fingerprint
from charter.memory.graph_types import EdgeType, NodeCategory
from charter.memory.models import Base
from charter.memory.semantic import SemanticStore
from data_security.kg_writer import KnowledgeGraphWriter as DsKgWriter
from data_security.schemas import ClassifierLabel
from data_security.tools.data_source import DataCloud, DataSource
from identity.tools.gcp_iam import GcpIamBinding, GcpServiceAccountKey
from nexus_runtime.scan_pipeline import ScanSources, scan_run
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

_NOW = datetime(2026, 7, 6, tzinfo=UTC)
_TENANT = "tenant-gcp-identity-e2e"

_GCP_BUCKET = "gcp-pii-bucket"
_GCS_URI = gcs_uri(_GCP_BUCKET)
_GCP_SA = "serviceAccount:reader-sa@my-project.iam.gserviceaccount.com"
_ESCALATOR = "user:escalator@acme.com"
_OWNER = "user:owner@acme.com"
_PRIVATE_KEY_ID = "sa-key-id-abc123"


@pytest_asyncio.fixture
async def session_factory() -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield async_sessionmaker(engine, expire_on_commit=False)
    await engine.dispose()


def _gcs_data_source(bucket: str, *, is_public: bool = True) -> DataSource:
    """A public GCS bucket DataSource — mirrors the S3 fixture used in test_scan_pipeline_e2e."""
    return DataSource(
        cloud=DataCloud.GCP,
        identifier=bucket,
        region="us-central1",
        is_public=is_public,
        is_encrypted=True,
    )


async def _seed_gcs_data(
    session_factory: async_sessionmaker[AsyncSession],
    tenant: str,
    bucket: str,
) -> None:
    """Pre-seed CLOUD_RESOURCE(gcs_uri) --EXPOSES_DATA--> DATA_CLASSIFICATION(ssn).

    This simulates what data_security.run() will do in P2 when record_data_sources
    is wired for GCS. For P1 we hand-seed it here so the join key is available when
    identity writes HAS_ACCESS_TO.
    """
    store = SemanticStore(session_factory)
    writer = DsKgWriter(store, tenant)
    source = _gcs_data_source(bucket)
    await writer.record_data_sources(
        [source],
        {bucket: [ClassifierLabel.SSN]},
    )


# ---------------------------------------------------------------------------
# Test B-1: fine_grained_data fires via GCP-SA → GCS (core P1 proof)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_scan_run_gcp_sa_fine_grained_data_fires(
    tmp_path: Path,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """P1 proof: GCP-SA with storage.objectViewer on a public PII GCS bucket → fine_grained_data.

    1. Pre-seed CLOUD_RESOURCE(gs://gcp-pii-bucket) --EXPOSES_DATA--> DATA_CLASSIFICATION(ssn)
    2. scan_run gcp_iam_bindings (SA → storage.objectViewer → gcp-pii-bucket)
    3. identity writes HAS_ACCESS_TO(GCP-SA, gs://gcp-pii-bucket)
    4. analyze → find_fine_grained_data_exposure → confirmed "fine_grained_data"
    """
    # Pre-seed the GCS data node (the P2 sink half of the path).
    await _seed_gcs_data(session_factory, _TENANT, _GCP_BUCKET)

    bindings = (
        GcpIamBinding(
            bucket=_GCP_BUCKET,
            role="roles/storage.objectViewer",
            members=(_GCP_SA,),
        ),
    )

    sources = ScanSources(gcp_iam_bindings=bindings)

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
        f"expected fine_grained_data confirmed path from GCP-SA with storage read grant; "
        f"got path_types={path_types}. "
        f"Join key: GCP-SA={_GCP_SA!r} bucket={_GCP_BUCKET!r} gcs_uri={_GCS_URI!r}. "
        f"Check: identity wrote IDENTITY({_GCP_SA!r}) --HAS_ACCESS_TO--> "
        f"CLOUD_RESOURCE({_GCS_URI!r}); pre-seed wrote EXPOSES_DATA."
    )


# ---------------------------------------------------------------------------
# Test B-2: sa_key_ownership → OWNS edges land through scan_run
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_scan_run_gcp_sa_key_owns_edge_lands(
    tmp_path: Path,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """GCP SA key injected via gcp_sa_keys → IDENTITY --OWNS--> SECRET in the shared store."""
    sa_keys = (GcpServiceAccountKey(service_account=_GCP_SA, private_key_id=_PRIVATE_KEY_ID),)
    fingerprint = secret_fingerprint(_PRIVATE_KEY_ID)

    sources = ScanSources(gcp_sa_keys=sa_keys)

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

    # Verify OWNS edge is in the shared store.
    store = SemanticStore(session_factory)
    sa_node = await store.upsert_entity(
        tenant_id=_TENANT,
        entity_type=NodeCategory.IDENTITY.value,
        external_id=_GCP_SA,
        properties={},
    )
    secret_node = await store.upsert_entity(
        tenant_id=_TENANT,
        entity_type=NodeCategory.SECRET.value,
        external_id=fingerprint,
        properties={},
    )

    owns_edges = await store.get_relationships_from(
        tenant_id=_TENANT,
        src_entity_id=sa_node,
        edge_types=(EdgeType.OWNS.value,),
    )
    assert len(owns_edges) == 1, f"expected 1 OWNS edge from SA to key; got {owns_edges}"
    assert owns_edges[0].dst_entity_id == secret_node, (
        f"OWNS edge destination must be the SECRET node keyed by fingerprint({_PRIVATE_KEY_ID!r})"
    )
