"""Shared dependencies and envelope models for the Nexus Read API."""

from __future__ import annotations

import os
from datetime import UTC, datetime
from typing import Any

from audit.store import AuditStore
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

_session_factory_singleton: async_sessionmaker[AsyncSession] | None = None
_store: SemanticStore | None = None
_audit_store: AuditStore | None = None


def _session_factory() -> async_sessionmaker[AsyncSession]:
    # Fail fast: an unset DSN used to default to in-memory sqlite, which has no
    # schema and is per-connection — it would serve empty results forever while
    # looking healthy. Tests never hit this path (they override the store deps).
    # One engine/factory backs both the graph store and the audit store.
    global _session_factory_singleton
    if _session_factory_singleton is None:
        dsn = os.environ.get("NEXUS_DB_DSN")
        if not dsn:
            raise RuntimeError(
                "NEXUS_DB_DSN is not set. The read API needs a DSN pointing at the "
                "populated knowledge-graph database (e.g. postgresql+asyncpg://...)."
            )
        _session_factory_singleton = async_sessionmaker(
            create_async_engine(dsn), expire_on_commit=False
        )
    return _session_factory_singleton


def get_store() -> SemanticStore:
    """Return the application SemanticStore.

    In production: reads NEXUS_DB_DSN from the environment.
    In tests: override via ``app.dependency_overrides[get_store]``.
    """
    global _store
    if _store is None:
        _store = SemanticStore(_session_factory())
    return _store


def get_audit_store() -> AuditStore:
    """Return the application AuditStore.

    Audit events (OCSF 6003) live in the ``audit_events`` table — a separate
    store from the entity graph, backed by the same DSN/session factory.
    In tests: override via ``app.dependency_overrides[get_audit_store]``.
    """
    global _audit_store
    if _audit_store is None:
        _audit_store = AuditStore(_session_factory())
    return _audit_store


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
