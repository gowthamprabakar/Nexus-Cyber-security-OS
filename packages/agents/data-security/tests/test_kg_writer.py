"""Tests for the data-security knowledge-graph writer (v0.4 Stage 1.5/D.5).

End-to-end through ``agent.run()`` against a real in-memory ``SemanticStore``: the
typed BucketInventory + classifier hits land as storage + DATA_CLASSIFICATION nodes
(CONTAINS / EXPOSES_DATA edges), labels only. Opt-in: default (no store) writes nothing.

Cycle 4 P2 addition: run() with azure_blob_inventory / gcs_inventory → EXPOSES_DATA
edges land from the CLOUD_RESOURCE(azure_blob_uri / gcs_uri) node to DATA_CLASSIFICATION.
"""

from __future__ import annotations

import base64
import json
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import pytest_asyncio
from charter.canonical import azure_blob_uri, gcs_uri
from charter.contract import BudgetSpec, ExecutionContract
from charter.memory.models import Base
from charter.memory.semantic import SemanticStore
from data_security.agent import run
from data_security.tools.azure_blob_inventory import AzureBlobContainer
from data_security.tools.gcs_inventory import GcsBucket
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

pytestmark = pytest.mark.asyncio

_TENANT = "cust_test"
_SSN = "123-45-6789"


def _contract(workspace: Path) -> ExecutionContract:
    persistent = workspace / "_p"
    persistent.mkdir(exist_ok=True)
    return ExecutionContract(
        schema_version="0.1",
        delegation_id="01J0000000000000000000DSEC",
        source_agent="supervisor",
        target_agent="data_security",
        customer_id=_TENANT,
        task="Data security scan",
        required_outputs=["findings.json", "report.md"],
        budget=BudgetSpec(
            llm_calls=5, tokens=10_000, wall_clock_sec=60.0, cloud_api_calls=10, mb_written=10
        ),
        permitted_tools=["read_s3_inventory", "read_s3_objects", "read_f3_findings"],
        completion_condition="findings.json AND report.md exist",
        escalation_rules=[],
        workspace=str(workspace),
        persistent_root=str(persistent),
        created_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )


def _public_bucket(name: str = "alpha") -> dict:
    return {
        "name": name,
        "region": "us-east-1",
        "account_id": "123456789012",
        "acl": {"grants_all_users": ["READ"], "grants_authenticated_users": []},
        "public_access_block": {
            "block_public_acls": False,
            "ignore_public_acls": False,
            "block_public_policy": False,
            "restrict_public_buckets": False,
        },
        "encryption": {"algorithm": "NONE", "kms_master_key_id": None},
        "policy_json": None,
        "tags": {},
    }


def _write(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data), encoding="utf-8")


@pytest_asyncio.fixture
async def store() -> AsyncIterator[SemanticStore]:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory: async_sessionmaker[AsyncSession] = async_sessionmaker(engine, expire_on_commit=False)
    yield SemanticStore(factory)
    await engine.dispose()


async def test_run_with_store_writes_storage_and_classification(
    tmp_path: Path, store: SemanticStore
) -> None:
    inv = tmp_path / "inv.json"
    obj = tmp_path / "obj.json"
    _write(inv, {"buckets": [_public_bucket("alpha")]})
    _write(
        obj,
        {
            "objects": [
                {
                    "bucket": "alpha",
                    "key": "data.csv",
                    "content_sample_b64": base64.b64encode(f"name,ssn\nbob,{_SSN}".encode()).decode(
                        "ascii"
                    ),
                }
            ]
        },
    )
    await run(_contract(tmp_path), s3_inventory_feed=inv, s3_objects_feed=obj, semantic_store=store)

    storage = await store.list_entities_by_type(tenant_id=_TENANT, entity_type="cloud_resource")
    assert len(storage) == 1
    assert (
        storage[0].external_id == "arn:aws:s3:::alpha"
    )  # canonical ARN key (was bucket.name — bug)
    assert storage[0].properties["is_public"] is True
    assert storage[0].properties["is_encrypted"] is False
    assert storage[0].properties["source"] == "alpha"  # human-readable name preserved as property

    classifications = await store.list_entities_by_type(
        tenant_id=_TENANT, entity_type="data_classification"
    )
    assert any(c.properties["data_type"] == "ssn" for c in classifications)
    # CONTAINS: storage → classification is traversable; raw SSN never persisted.
    neighbors = await store.neighbors(tenant_id=_TENANT, entity_id=storage[0].entity_id, depth=1)
    assert any(n.entity_type == "data_classification" for n in neighbors)
    all_props = json.dumps([c.properties for c in classifications])
    assert _SSN not in all_props


async def test_run_without_store_writes_nothing(tmp_path: Path, store: SemanticStore) -> None:
    inv = tmp_path / "inv.json"
    _write(inv, {"buckets": [_public_bucket("alpha")]})
    await run(_contract(tmp_path), s3_inventory_feed=inv)
    assert await store.list_entities_by_type(tenant_id=_TENANT, entity_type="cloud_resource") == []


# ---------------------------------------------------------------------------
# Cycle 4 P2 — Blob/GCS record_data_sources wired into run()
# ---------------------------------------------------------------------------


async def test_run_with_blob_inventory_writes_exposes_data(
    tmp_path: Path, store: SemanticStore
) -> None:
    """run() with azure_blob_inventory writes CLOUD_RESOURCE(azure_blob_uri) --EXPOSES_DATA-->
    DATA_CLASSIFICATION when the container is public.

    Mirrors test_run_with_store_writes_storage_and_classification but via the Azure Blob path.
    No S3 inventory is injected to prove the Blob path activates independently.

    NOTE: no object samples are available in this path (azure_blob_objects_feed is a v0.5
    deliverable), so CONTAINS/EXPOSES_DATA only land when a public container is present.
    The CLOUD_RESOURCE node is written regardless; EXPOSES_DATA requires is_public=True.
    """
    _ACCOUNT = "mystorage"
    _CONTAINER = "pii-data"
    container = AzureBlobContainer(
        storage_account=_ACCOUNT,
        container=_CONTAINER,
        region="eastus",
        public_access="container",  # is_public=True
        encrypted=True,
    )
    expected_uri = azure_blob_uri(_ACCOUNT, _CONTAINER)

    await run(
        _contract(tmp_path),
        azure_blob_inventory=[container],
        semantic_store=store,
    )

    storage = await store.list_entities_by_type(tenant_id=_TENANT, entity_type="cloud_resource")
    assert len(storage) == 1, (
        f"expected 1 CLOUD_RESOURCE node; got {[s.external_id for s in storage]}"
    )
    assert storage[0].external_id == expected_uri, (
        f"CLOUD_RESOURCE node must be keyed by azure_blob_uri; "
        f"got {storage[0].external_id!r}, want {expected_uri!r}"
    )
    assert storage[0].properties["is_public"] is True
    assert storage[0].properties["resource_type"] == "azure-storage"


async def test_run_with_gcs_inventory_writes_exposes_data(
    tmp_path: Path, store: SemanticStore
) -> None:
    """run() with gcs_inventory writes CLOUD_RESOURCE(gcs_uri) --EXPOSES_DATA-->
    DATA_CLASSIFICATION when the bucket is public (allUsers iam_member).

    Mirrors the Azure test above for the GCP path.
    """
    _PROJECT = "my-project"
    _BUCKET = "gcp-pii-bucket"
    bucket = GcsBucket(
        project=_PROJECT,
        name=_BUCKET,
        location="us-central1",
        iam_members=("allUsers",),  # is_public=True
        encrypted=True,
    )
    expected_uri = gcs_uri(_BUCKET)

    await run(
        _contract(tmp_path),
        gcs_inventory=[bucket],
        semantic_store=store,
    )

    storage = await store.list_entities_by_type(tenant_id=_TENANT, entity_type="cloud_resource")
    assert len(storage) == 1, (
        f"expected 1 CLOUD_RESOURCE node; got {[s.external_id for s in storage]}"
    )
    assert storage[0].external_id == expected_uri, (
        f"CLOUD_RESOURCE node must be keyed by gcs_uri; "
        f"got {storage[0].external_id!r}, want {expected_uri!r}"
    )
    assert storage[0].properties["is_public"] is True
    assert storage[0].properties["resource_type"] == "gcp-storage"


async def test_run_blob_gcs_none_does_not_write_extra_nodes(
    tmp_path: Path, store: SemanticStore
) -> None:
    """S3-only path unchanged: azure_blob_inventory=None + gcs_inventory=None → no extra nodes."""
    inv = tmp_path / "inv.json"
    _write(inv, {"buckets": [_public_bucket("alpha")]})
    await run(_contract(tmp_path), s3_inventory_feed=inv, semantic_store=store)
    storage = await store.list_entities_by_type(tenant_id=_TENANT, entity_type="cloud_resource")
    # Only the S3 bucket node should be present
    assert len(storage) == 1
    assert storage[0].external_id == "arn:aws:s3:::alpha"
