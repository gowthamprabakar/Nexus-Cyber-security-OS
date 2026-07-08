"""Shared dependencies and envelope models for the Nexus Read API."""

from __future__ import annotations

import os
from datetime import UTC, datetime
from typing import Any

from charter.memory.semantic import SemanticStore
from fastapi import Header
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

# ---------------------------------------------------------------------------
# Envelope / response models
# ---------------------------------------------------------------------------


class Meta(BaseModel):
    offset: int | None
    total: int | None
    tenant: str
    generated_at: str


class Envelope(BaseModel):
    data: Any
    meta: Meta


def make_envelope(
    *,
    data: Any,
    offset: int | None,
    total: int | None,
    tenant: str,
) -> Envelope:
    return Envelope(
        data=data,
        meta=Meta(
            offset=offset,
            total=total,
            tenant=tenant,
            generated_at=datetime.now(tz=UTC).isoformat(),
        ),
    )


# ---------------------------------------------------------------------------
# SemanticStore dependency (overridable via app.dependency_overrides)
# ---------------------------------------------------------------------------

_store: SemanticStore | None = None


def _build_store() -> SemanticStore:
    dsn = os.environ.get("NEXUS_DB_DSN", "sqlite+aiosqlite:///:memory:")
    factory: async_sessionmaker[AsyncSession] = async_sessionmaker(
        create_async_engine(dsn), expire_on_commit=False
    )
    return SemanticStore(factory)


def get_store() -> SemanticStore:
    """Return the application SemanticStore.

    In production: reads NEXUS_DB_DSN from the environment.
    In tests: override via ``app.dependency_overrides[get_store]``.
    """
    global _store
    if _store is None:
        _store = _build_store()
    return _store


# ---------------------------------------------------------------------------
# Auth stubs (real IdP wired later; callers don't change)
# ---------------------------------------------------------------------------


async def require_tenant(
    x_tenant_id: str = Header(default="dev"),
) -> str:
    """STUB: return the tenant id from the X-Tenant-Id header, defaulting to 'dev'."""
    return x_tenant_id


def require_entitlement(resource: str, action: str) -> Any:
    """STUB: allow-all entitlement check (swapped for real IdP later)."""

    async def _check() -> None:
        return None

    return _check
