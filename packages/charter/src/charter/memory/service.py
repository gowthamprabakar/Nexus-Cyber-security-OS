"""`MemoryService` — single DI seam for agent-side memory access (F.5 Task 9).

The four shipped agents (F.3 / D.1 / D.2 / D.3) and every agent that
follows talks to memory through this facade rather than wiring up the
three stores by hand. Responsibilities:

- **Bundle the three stores** behind stable `episodic` / `procedural`
  / `semantic` properties. Each store is constructed once at service
  init and reused.
- **Embedder injection.** `MemoryService.append_event` runs the
  embedder before delegating, so agents don't have to remember to
  embed before writing. A caller-supplied `embedding=` still wins.
- **Audit-log threading.** The facade's `audit_log` argument is
  forwarded into every store, so a single configuration choice at
  the service level decides whether all four write paths emit
  chained audit entries.
- **Tenant-scoped sessions.** `session(tenant_id=...)` is an async
  context manager that yields an `AsyncSession`. On Postgres it
  issues `SET LOCAL app.tenant_id = '<tid>'` inside the same
  transaction so the RLS policies from Task 7 fire. On aiosqlite
  it skips the SET LOCAL silently — the variable isn't recognised
  there.

The facade keeps the session-variable management and the embedder
inside one object; agent code stays terse:

    async with memory.session(tenant_id=ctx.tenant_id):
        episode_id = await memory.append_event(
            tenant_id=ctx.tenant_id,
            correlation_id=ctx.correlation_id,
            agent_id="cloud_posture",
            action="finding.created",
            payload={"finding_id": fid},
        )
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from charter.audit import AuditLog
from charter.memory.embedding import Embedding
from charter.memory.episodic import EpisodicStore
from charter.memory.procedural import ProceduralStore
from charter.memory.semantic import SemanticStore


class MemoryService:
    """Single async DI seam for the three memory engines."""

    def __init__(
        self,
        *,
        session_factory: async_sessionmaker[AsyncSession],
        embedder: Embedding,
        audit_log: AuditLog | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._embedder = embedder
        self._audit_log = audit_log
        self._episodic = EpisodicStore(session_factory, audit_log=audit_log)
        self._procedural = ProceduralStore(session_factory, audit_log=audit_log)
        self._semantic = SemanticStore(session_factory, audit_log=audit_log)

    @property
    def episodic(self) -> EpisodicStore:
        return self._episodic

    @property
    def procedural(self) -> ProceduralStore:
        return self._procedural

    @property
    def semantic(self) -> SemanticStore:
        return self._semantic

    @asynccontextmanager
    async def session(self, *, tenant_id: str) -> AsyncIterator[AsyncSession]:
        """Yield an `AsyncSession` with `app.tenant_id` set.

        On Postgres the `SET LOCAL` populates the session variable
        the RLS policies (Task 7) read. The setting is scoped to the
        transaction, so closing the session unbinds it automatically.

        On non-Postgres dialects the SET LOCAL is silently skipped.
        """
        async with self._session_factory.begin() as session:
            dialect = session.bind.dialect.name if session.bind else ""
            if dialect == "postgresql":
                await session.execute(
                    text("SET LOCAL app.tenant_id = :tid").bindparams(tid=tenant_id)
                )
            yield session

    async def append_event(
        self,
        *,
        tenant_id: str,
        correlation_id: str,
        agent_id: str,
        action: str,
        payload: dict[str, Any],
        embedding: list[float] | None = None,
    ) -> int:
        """Convenience writer that embeds the payload before delegating.

        Computes the embedding from `payload["text"]` (or the JSON
        rendering of the payload if no `text` field is present) so
        agents don't have to plumb an embedder around. A caller-
        supplied `embedding=` short-circuits the embedder and is
        passed through verbatim.
        """
        if embedding is None:
            text_to_embed = _text_from_payload(payload)
            embedding = self._embedder.embed(text_to_embed)

        return await self._episodic.append_event(
            tenant_id=tenant_id,
            correlation_id=correlation_id,
            agent_id=agent_id,
            action=action,
            payload=payload,
            embedding=embedding,
        )


def _text_from_payload(payload: dict[str, Any]) -> str:
    """Pull the text to embed out of a payload.

    Convention: payloads carry the human-readable summary under
    `text`. If absent, fall back to a stable JSON rendering so
    embeddings remain deterministic over the same payload shape.
    """
    if "text" in payload and isinstance(payload["text"], str):
        return payload["text"]
    import json

    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


__all__ = ["MemoryService"]
