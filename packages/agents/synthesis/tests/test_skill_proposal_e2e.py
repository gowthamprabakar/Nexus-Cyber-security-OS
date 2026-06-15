"""Hermes Phase 1 end-to-end verification (Track C C-3 PR1) — D.13 synthesis.

The per-agent ``test_skill_proposal`` unit tests assert the *call shape* against an
``AsyncMock`` store. This test closes the remaining gap: it drives
``_propose_skill_candidate`` against a **real** ``SemanticStore`` (in-memory
aiosqlite) and proves the proposed ``skill_candidate`` actually persists and is
retrievable by the cross-session query path the meta-harness consumes — i.e. the
full C-2 loop (audit → ``detect_skill_trigger`` → ``upsert_skill_candidate`` →
queryable KG row) works against the production store, not just a mock.

Idempotency (re-proposing the same workflow merges, never duplicates) is the
cross-session-reuse contract the SemanticStore guarantees on
``(tenant_id, entity_type, external_id)``.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from pathlib import Path

import pytest
import pytest_asyncio
from charter.memory.models import Base
from charter.memory.semantic import SemanticStore
from nexus_runtime.hermes import SKILL_CANDIDATE_ENTITY_TYPE
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from synthesis.agent import _propose_skill_candidate

pytestmark = pytest.mark.asyncio

_AGENT_ID = "synthesis"
_TENANT = "01HV0T0000000000000000TEN1"


@pytest_asyncio.fixture
async def store() -> AsyncIterator[SemanticStore]:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory: async_sessionmaker[AsyncSession] = async_sessionmaker(engine, expire_on_commit=False)
    yield SemanticStore(factory)
    await engine.dispose()


def _write_llm_audit(path: Path, *, n_llm: int) -> None:
    lines = [
        json.dumps(
            {
                "action": f"{_AGENT_ID}.llm.call_completed",
                "payload": {"llm_call_count": 1},
                "entry_hash": f"h{i}",
            }
        )
        for i in range(n_llm)
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


async def test_proposal_persists_into_real_semantic_store(
    tmp_path: Path, store: SemanticStore
) -> None:
    audit = tmp_path / "audit.jsonl"
    _write_llm_audit(audit, n_llm=5)

    await _propose_skill_candidate(
        audit_path=audit,
        semantic_store=store,
        agent_id=_AGENT_ID,
        run_id="run-1",
        tenant_id=_TENANT,
    )

    rows = await store.list_entities_by_type(
        tenant_id=_TENANT, entity_type=SKILL_CANDIDATE_ENTITY_TYPE
    )
    assert len(rows) == 1
    row = rows[0]
    assert row.external_id.startswith(f"{_AGENT_ID}:")
    assert row.properties["agent_id"] == _AGENT_ID
    assert row.properties["run_id"] == "run-1"
    assert row.properties["tool_sequence_hash"]


async def test_reproposing_same_workflow_is_idempotent(
    tmp_path: Path, store: SemanticStore
) -> None:
    audit = tmp_path / "audit.jsonl"
    _write_llm_audit(audit, n_llm=6)

    # Same workflow proposed twice (e.g. two runs of the same LLM pipeline) →
    # the (tenant, entity_type, external_id) key merges, never duplicates.
    for run_id in ("run-1", "run-2"):
        await _propose_skill_candidate(
            audit_path=audit,
            semantic_store=store,
            agent_id=_AGENT_ID,
            run_id=run_id,
            tenant_id=_TENANT,
        )

    rows = await store.list_entities_by_type(
        tenant_id=_TENANT, entity_type=SKILL_CANDIDATE_ENTITY_TYPE
    )
    assert len(rows) == 1


async def test_no_persistence_below_threshold(tmp_path: Path, store: SemanticStore) -> None:
    audit = tmp_path / "audit.jsonl"
    _write_llm_audit(audit, n_llm=4)

    await _propose_skill_candidate(
        audit_path=audit,
        semantic_store=store,
        agent_id=_AGENT_ID,
        run_id="run-1",
        tenant_id=_TENANT,
    )

    rows = await store.list_entities_by_type(
        tenant_id=_TENANT, entity_type=SKILL_CANDIDATE_ENTITY_TYPE
    )
    assert rows == []
