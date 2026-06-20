"""In-memory ``SemanticStore`` for fleet-test L1 (the substrate's documented test backend)."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from charter.memory.models import Base
from charter.memory.semantic import SemanticStore
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine


@asynccontextmanager
async def in_memory_semantic_store() -> AsyncIterator[SemanticStore]:
    """Yield a fresh sqlite/aiosqlite-backed ``SemanticStore``, schema created from the
    model metadata, disposed on exit.

    In-memory is the substrate's documented test backend (ADR-009/ADR-019) — the same
    aiosqlite path every charter unit test uses; not mock theater (swiss-bar #2). L5/L6
    swap in real Postgres; L1 stays in-memory (Q1).
    """
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        factory: async_sessionmaker[AsyncSession] = async_sessionmaker(
            engine, expire_on_commit=False
        )
        yield SemanticStore(factory)
    finally:
        await engine.dispose()
