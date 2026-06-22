"""Production SemanticStore/AuditStore session-factory provisioning (Postgres).

Lifts the proven live-test pattern into a reusable production builder: run alembic
migrations (sync psycopg2 URL), then return an async session factory. The only store
factory previously in the repo was the in-memory test one -- this is its production
counterpart. SemanticStore(factory) + AuditStore(factory) are built by the caller.
"""

from __future__ import annotations

from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

_CHARTER_ROOT = Path(__file__).resolve().parents[3]  # packages/charter


def _alembic_url(dsn: str) -> str:
    """Alembic runs sync -- swap the asyncpg driver for psycopg2."""
    return dsn.replace("+asyncpg", "+psycopg2")


def run_migrations(dsn: str) -> None:
    """Apply ``alembic upgrade head`` against the given Postgres DSN."""
    cfg = Config(str(_CHARTER_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(_CHARTER_ROOT / "alembic"))
    cfg.set_main_option("sqlalchemy.url", _alembic_url(dsn))
    command.upgrade(cfg, "head")


async def build_session_factory(
    dsn: str, *, migrate: bool = False
) -> async_sessionmaker[AsyncSession]:
    """Build a production async session factory from a Postgres DSN.

    When ``migrate`` is True, applies ``alembic upgrade head`` first (use for a
    fresh DB / first boot; production normally migrates out-of-band and passes False).
    """
    if migrate:
        run_migrations(dsn)
    return async_sessionmaker(create_async_engine(dsn), expire_on_commit=False)
