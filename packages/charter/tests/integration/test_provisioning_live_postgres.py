"""Gated (NEXUS_LIVE_POSTGRES=1): the production factory builds a working,
migrated, RLS-capable store against real Postgres. CI skips this."""

from __future__ import annotations

import os
from collections.abc import AsyncIterator

import pytest
import pytest_asyncio
from charter.memory.provisioning import build_session_factory
from charter.memory.semantic import SemanticStore
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

_LIVE = os.environ.get("NEXUS_LIVE_POSTGRES") == "1"

_DEFAULT_ADMIN_URL = "postgresql+asyncpg://nexus:nexus_dev@localhost:5432/postgres"
_DEFAULT_TARGET_URL = "postgresql+asyncpg://nexus:nexus_dev@localhost:5432/nexus_provisioning_test"

_TARGET_URL = os.environ.get("NEXUS_LIVE_POSTGRES_URL", _DEFAULT_TARGET_URL)
_ADMIN_URL = os.environ.get("NEXUS_LIVE_POSTGRES_ADMIN_URL", _DEFAULT_ADMIN_URL)

pytestmark = pytest.mark.skipif(not _LIVE, reason="set NEXUS_LIVE_POSTGRES=1 + reachable Postgres")


@pytest_asyncio.fixture
async def postgres_dsn() -> AsyncIterator[str]:
    """Drop + recreate the test database for a clean slate per test."""
    target_db = _TARGET_URL.rsplit("/", 1)[-1]
    admin_engine = create_async_engine(_ADMIN_URL, isolation_level="AUTOCOMMIT")
    try:
        async with admin_engine.connect() as conn:
            await conn.execute(text(f"DROP DATABASE IF EXISTS {target_db}"))
            await conn.execute(text(f"CREATE DATABASE {target_db}"))
    finally:
        await admin_engine.dispose()

    yield _TARGET_URL


@pytest.mark.asyncio
async def test_build_session_factory_round_trips(postgres_dsn: str) -> None:
    factory = await build_session_factory(postgres_dsn, migrate=True)
    store = SemanticStore(factory)
    eid = await store.upsert_entity(
        tenant_id="t1",
        entity_type="cloud_resource",
        external_id="arn:aws:s3:::b",
        properties={},
    )
    rows = await store.list_entities_by_type(tenant_id="t1", entity_type="cloud_resource")
    assert any(r.entity_id == eid for r in rows)
