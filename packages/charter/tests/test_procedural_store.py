"""Tests for `charter.memory.procedural.ProceduralStore` (F.5 Task 5).

Production contract:

1. `publish_version` is the single ingress for new playbook revisions.
   Inserts a row with `active=True` and the next monotonically
   increasing version for that `(tenant_id, path)`. Deactivates the
   prior active row in the same transaction.
2. `get_active(tenant, path)` returns the unique active row or `None`
   if no row was ever published for that path. Type is `PlaybookRow`,
   not the ORM model, so callers stay decoupled.
3. `list_subtree(tenant, prefix)` returns every active playbook whose
   LTREE path is a descendant of `prefix` (and `prefix` itself).
   On aiosqlite, the LTREE column is `String(512)`; the store falls
   back to a prefix `LIKE` match that satisfies the same semantics.
4. **Exactly one active row per (tenant, path) at any time** — the
   invariant agents rely on when reading "the current playbook".
5. Tenant isolation on every query.
6. Older versions are retained (not deleted) for audit / rollback.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

import pytest
import pytest_asyncio
from charter.memory.models import Base
from charter.memory.procedural import ProceduralStore
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine


@pytest_asyncio.fixture
async def session_factory() -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield async_sessionmaker(engine, expire_on_commit=False)
    await engine.dispose()


@pytest_asyncio.fixture
async def store(session_factory: async_sessionmaker[AsyncSession]) -> ProceduralStore:
    return ProceduralStore(session_factory)


_TENANT = "01HV0T0000000000000000TEN1"
_OTHER = "01HV0T0000000000000000TEN2"


# ---------------------------- publish + get_active -----------------------


@pytest.mark.asyncio
async def test_publish_version_returns_version_one_on_first_publish(
    store: ProceduralStore,
) -> None:
    version = await store.publish_version(
        tenant_id=_TENANT,
        path="remediation.s3.public_bucket",
        body={"steps": ["disable-acl"]},
    )
    assert version == 1


@pytest.mark.asyncio
async def test_publish_version_auto_increments(store: ProceduralStore) -> None:
    path = "remediation.s3.public_bucket"
    for expected in (1, 2, 3):
        version = await store.publish_version(tenant_id=_TENANT, path=path, body={"v": expected})
        assert version == expected


@pytest.mark.asyncio
async def test_get_active_returns_latest_published(store: ProceduralStore) -> None:
    path = "remediation.s3.public_bucket"
    await store.publish_version(tenant_id=_TENANT, path=path, body={"v": 1})
    await store.publish_version(tenant_id=_TENANT, path=path, body={"v": 2})

    row = await store.get_active(tenant_id=_TENANT, path=path)
    assert row is not None
    assert row.version == 2
    assert row.body == {"v": 2}
    assert row.active is True


@pytest.mark.asyncio
async def test_get_active_returns_none_when_path_never_published(
    store: ProceduralStore,
) -> None:
    row = await store.get_active(tenant_id=_TENANT, path="never.published")
    assert row is None


# ---------------------------- exactly-one-active invariant ---------------


@pytest.mark.asyncio
async def test_only_one_active_row_after_multiple_publishes(
    store: ProceduralStore,
) -> None:
    path = "remediation.s3.public_bucket"
    for _ in range(4):
        await store.publish_version(tenant_id=_TENANT, path=path, body={})

    history = await store.list_versions(tenant_id=_TENANT, path=path)
    assert len(history) == 4
    actives = [r for r in history if r.active]
    assert len(actives) == 1
    assert actives[0].version == 4


@pytest.mark.asyncio
async def test_list_versions_returns_all_versions_descending(
    store: ProceduralStore,
) -> None:
    path = "remediation.s3.public_bucket"
    for _ in range(3):
        await store.publish_version(tenant_id=_TENANT, path=path, body={})

    rows = await store.list_versions(tenant_id=_TENANT, path=path)
    assert [r.version for r in rows] == [3, 2, 1]


# ---------------------------- list_subtree (LTREE) -----------------------


@pytest.mark.asyncio
async def test_list_subtree_returns_active_descendants(
    store: ProceduralStore,
) -> None:
    await store.publish_version(tenant_id=_TENANT, path="remediation.s3.public_bucket", body={})
    await store.publish_version(tenant_id=_TENANT, path="remediation.s3.lifecycle", body={})
    await store.publish_version(tenant_id=_TENANT, path="remediation.iam.role", body={})

    rows = await store.list_subtree(tenant_id=_TENANT, prefix="remediation.s3")
    paths = sorted(r.path for r in rows)
    assert paths == ["remediation.s3.lifecycle", "remediation.s3.public_bucket"]


@pytest.mark.asyncio
async def test_list_subtree_includes_exact_match(store: ProceduralStore) -> None:
    await store.publish_version(tenant_id=_TENANT, path="remediation.s3", body={})
    await store.publish_version(tenant_id=_TENANT, path="remediation.s3.public_bucket", body={})
    rows = await store.list_subtree(tenant_id=_TENANT, prefix="remediation.s3")
    assert {r.path for r in rows} == {"remediation.s3", "remediation.s3.public_bucket"}


@pytest.mark.asyncio
async def test_list_subtree_excludes_inactive_versions(store: ProceduralStore) -> None:
    path = "remediation.s3.public_bucket"
    await store.publish_version(tenant_id=_TENANT, path=path, body={"v": 1})
    await store.publish_version(tenant_id=_TENANT, path=path, body={"v": 2})

    rows = await store.list_subtree(tenant_id=_TENANT, prefix="remediation.s3")
    assert len(rows) == 1
    assert rows[0].version == 2


# ---------------------------- tenant isolation ---------------------------


@pytest.mark.asyncio
async def test_publish_is_tenant_scoped(store: ProceduralStore) -> None:
    path = "remediation.s3.public_bucket"
    v1 = await store.publish_version(tenant_id=_TENANT, path=path, body={})
    v_other = await store.publish_version(tenant_id=_OTHER, path=path, body={})
    # Versions are per-tenant — both start at 1, independently.
    assert v1 == 1
    assert v_other == 1


@pytest.mark.asyncio
async def test_get_active_is_tenant_scoped(store: ProceduralStore) -> None:
    path = "remediation.s3.public_bucket"
    await store.publish_version(tenant_id=_TENANT, path=path, body={"owner": _TENANT})
    await store.publish_version(tenant_id=_OTHER, path=path, body={"owner": _OTHER})

    a = await store.get_active(tenant_id=_TENANT, path=path)
    b = await store.get_active(tenant_id=_OTHER, path=path)
    assert a is not None and a.body == {"owner": _TENANT}
    assert b is not None and b.body == {"owner": _OTHER}


@pytest.mark.asyncio
async def test_list_subtree_is_tenant_scoped(store: ProceduralStore) -> None:
    await store.publish_version(tenant_id=_TENANT, path="remediation.s3.public_bucket", body={})
    await store.publish_version(tenant_id=_OTHER, path="remediation.s3.public_bucket", body={})

    rows = await store.list_subtree(tenant_id=_TENANT, prefix="remediation.s3")
    assert len(rows) == 1
    assert all(r.tenant_id == _TENANT for r in rows)
