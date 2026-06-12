"""curiosity v0.2 Task 6 — live SemanticStore aggregate reads (Q2/H5).

Exercises read_sibling_state against a REAL in-memory F.5 SemanticStore (not an AsyncMock):
seeds aws_account_region + finding_aggregate rows across multiple source agents for two tenants,
then asserts (a) the per-region + per-source aggregate comes through live and (b) the read is
strictly tenant-scoped — tenant A never sees tenant B's rows (H5; cross-tenant aggregation
forbidden, always).
"""

from __future__ import annotations

from collections.abc import AsyncIterator

import pytest
import pytest_asyncio
from charter.memory.models import Base
from charter.memory.semantic import SemanticStore
from curiosity.tools.sibling_state_reader import read_sibling_state
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

pytestmark = pytest.mark.asyncio

_TENANT_A = "01HV0T0000000000000000TENA"
_TENANT_B = "01HV0T0000000000000000TENB"


@pytest_asyncio.fixture
async def store() -> AsyncIterator[SemanticStore]:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory: async_sessionmaker[AsyncSession] = async_sessionmaker(engine, expire_on_commit=False)
    yield SemanticStore(factory)
    await engine.dispose()


async def _seed_tenant(store: SemanticStore, tenant: str, *, region: str, assets: int) -> None:
    await store.upsert_entity(
        tenant_id=tenant,
        entity_type="aws_account_region",
        external_id=region,
        properties={"asset_count": assets},
    )
    for source in ("cloud_posture", "compliance", "investigation"):
        await store.upsert_entity(
            tenant_id=tenant,
            entity_type="finding_aggregate",
            external_id=f"{region}:{source}",
            properties={
                "region": region,
                "days_since_last_finding": 2,
                "last_finding_severity": "high",
                "source_agent": source,
            },
        )


async def test_live_read_aggregates_per_source(store: SemanticStore) -> None:
    await _seed_tenant(store, _TENANT_A, region="eu-west-1", assets=42)
    state = await read_sibling_state(store, customer_id=_TENANT_A)

    assert state.total_assets == 42
    assert len(state.regions) == 1
    assert state.regions[0].region == "eu-west-1"
    # Q2/WI-X1: per-source breakdown comes through live, across 3 of the 14 sources.
    assert state.per_source_findings == {
        "cloud_posture": 1,
        "compliance": 1,
        "investigation": 1,
    }


async def test_live_read_is_tenant_scoped(store: SemanticStore) -> None:
    await _seed_tenant(store, _TENANT_A, region="eu-west-1", assets=42)
    await _seed_tenant(store, _TENANT_B, region="us-east-1", assets=999)

    state_a = await read_sibling_state(store, customer_id=_TENANT_A)
    # H5: tenant A sees ONLY its own region + assets; tenant B's 999 never leaks.
    assert state_a.total_assets == 42
    assert {r.region for r in state_a.regions} == {"eu-west-1"}


async def test_empty_tenant_rejected_before_db(store: SemanticStore) -> None:
    with pytest.raises(ValueError, match="customer_id"):
        await read_sibling_state(store, customer_id="")
