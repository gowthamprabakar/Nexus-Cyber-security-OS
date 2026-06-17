"""Tests for the data-security knowledge-graph writer (v0.4 Stage 1.5/D.5).

End-to-end through ``agent.run()`` against a real in-memory ``SemanticStore``: the
typed BucketInventory + classifier hits land as storage + DATA_CLASSIFICATION nodes
(CONTAINS / EXPOSES_DATA edges), labels only. Opt-in: default (no store) writes nothing.
"""

from __future__ import annotations

import base64
import json
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import pytest_asyncio
from charter.contract import BudgetSpec, ExecutionContract
from charter.memory.models import Base
from charter.memory.semantic import SemanticStore
from data_security.agent import run
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
    assert storage[0].external_id == "alpha"
    assert storage[0].properties["is_public"] is True
    assert storage[0].properties["is_encrypted"] is False

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
