"""Tests for `control_plane.tenants.resolver.TenantResolver`.

Uses an in-memory aiosqlite database (no Postgres required). The
schema is created via `Base.metadata.create_all`, mirroring the
canonical migration shape from Task 2 closely enough for resolver
behavior — there is a separate alembic test for migration fidelity.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime

import pytest
import pytest_asyncio
from control_plane.auth.jwt_verifier import VerifiedToken
from control_plane.tenants.models import Base, Role, TenantRow, UserRow
from control_plane.tenants.resolver import (
    TenantNotFoundError,
    TenantResolver,
    TenantSuspendedError,
)
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from ulid import ULID

TENANT_ID = str(ULID())
SUSPENDED_TENANT_ID = str(ULID())


@pytest_asyncio.fixture
async def session_factory() -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)

    async with factory() as session:
        session.add(
            TenantRow(
                tenant_id=TENANT_ID,
                name="Acme",
                created_at=datetime.now(UTC),
            )
        )
        session.add(
            TenantRow(
                tenant_id=SUSPENDED_TENANT_ID,
                name="Suspended Co",
                created_at=datetime.now(UTC),
                suspended_at=datetime.now(UTC),
            )
        )
        await session.commit()

    yield factory
    await engine.dispose()


def _token(
    sub: str = "auth0|abc",
    *,
    tenant_id: str = TENANT_ID,
    roles: tuple[str, ...] = ("operator",),
) -> VerifiedToken:
    return VerifiedToken(
        sub=sub,
        tenant_id=tenant_id,
        roles=roles,
        expires_at=datetime.now(UTC),
        amr=("pwd",),
    )


# ---------------------------- happy paths --------------------------------


@pytest.mark.asyncio
async def test_first_login_provisions_new_user(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    resolver = TenantResolver(session_factory)
    identity = await resolver.resolve(_token(), email="alice@example.com")

    assert identity.tenant_id == TENANT_ID
    assert identity.is_first_login is True
    assert identity.role == Role.OPERATOR
    assert len(identity.user_id) == 26  # ULID

    async with session_factory() as session:
        row = await session.get(UserRow, identity.user_id)
    assert row is not None
    assert row.email == "alice@example.com"
    assert row.auth0_sub == "auth0|abc"


@pytest.mark.asyncio
async def test_existing_user_resolves_without_provisioning(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    resolver = TenantResolver(session_factory)
    first = await resolver.resolve(_token(), email="alice@example.com")
    second = await resolver.resolve(_token(), email="alice@example.com")

    assert second.is_first_login is False
    assert second.user_id == first.user_id


@pytest.mark.asyncio
async def test_existing_user_last_login_updated(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    resolver = TenantResolver(session_factory)
    first = await resolver.resolve(_token(), email="alice@example.com")
    async with session_factory() as session:
        row = await session.get(UserRow, first.user_id)
        assert row is not None
        first_login_at = row.last_login_at

    await resolver.resolve(_token(), email="alice@example.com")

    async with session_factory() as session:
        row = await session.get(UserRow, first.user_id)
        assert row is not None
        assert row.last_login_at is not None
        assert first_login_at is not None
        assert row.last_login_at >= first_login_at


@pytest.mark.asyncio
async def test_role_resolved_from_token_when_known(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    resolver = TenantResolver(session_factory)
    identity = await resolver.resolve(_token(roles=("admin",)), email="alice@example.com")
    assert identity.role == Role.ADMIN


@pytest.mark.asyncio
async def test_unknown_role_falls_back_to_default(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    resolver = TenantResolver(session_factory)
    identity = await resolver.resolve(
        _token(roles=("nonsense-role",)),
        email="alice@example.com",
        default_role=Role.AUDITOR,
    )
    assert identity.role == Role.AUDITOR


# ---------------------------- rejection paths ----------------------------


@pytest.mark.asyncio
async def test_unknown_tenant_raises_tenant_not_found(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    resolver = TenantResolver(session_factory)
    with pytest.raises(TenantNotFoundError):
        await resolver.resolve(
            _token(tenant_id=str(ULID())),
            email="alice@example.com",
        )


@pytest.mark.asyncio
async def test_suspended_tenant_raises_tenant_suspended(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    resolver = TenantResolver(session_factory)
    with pytest.raises(TenantSuspendedError):
        await resolver.resolve(
            _token(tenant_id=SUSPENDED_TENANT_ID),
            email="alice@example.com",
        )


@pytest.mark.asyncio
async def test_two_users_in_same_tenant(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    resolver = TenantResolver(session_factory)
    alice = await resolver.resolve(_token(sub="auth0|alice"), email="alice@example.com")
    bob = await resolver.resolve(_token(sub="auth0|bob"), email="bob@example.com")

    assert alice.tenant_id == bob.tenant_id == TENANT_ID
    assert alice.user_id != bob.user_id
