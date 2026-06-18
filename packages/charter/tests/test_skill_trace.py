"""Tests for the skill-trace store (T2, ADR-021) — real in-memory SemanticStore."""

from __future__ import annotations

from collections.abc import AsyncIterator

import pytest
import pytest_asyncio
from charter.memory.models import Base
from charter.memory.semantic import SemanticStore
from charter.memory.skill_trace import SkillTraceStore
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

pytestmark = pytest.mark.asyncio

_TENANT = "cust_test"


@pytest_asyncio.fixture
async def store() -> AsyncIterator[SemanticStore]:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory: async_sessionmaker[AsyncSession] = async_sessionmaker(engine, expire_on_commit=False)
    yield SemanticStore(factory)
    await engine.dispose()


async def test_record_then_list_multi_example(store: SemanticStore) -> None:
    sts = SkillTraceStore(store, _TENANT)
    assert sts.enabled is True
    for i in range(3):
        await sts.record_trace(
            agent_id="synthesis",
            skill_id=f"skill-{i}",
            category="narrate",
            trace=f"tool-a -> tool-b ({i})",
            audit_hashes=(f"h{i}",),
            effectiveness_score=0.5 + i * 0.1,
        )
    examples = await sts.list_traces(agent_id="synthesis")
    assert len(examples) == 3  # the multi-example trainset source (un-starves GEPA)
    assert {e.skill_id for e in examples} == {"skill-0", "skill-1", "skill-2"}
    one = next(e for e in examples if e.skill_id == "skill-1")
    assert one.trace == "tool-a -> tool-b (1)"
    assert one.effectiveness_score == pytest.approx(0.6)
    assert one.audit_hashes == ("h1",)


async def test_idempotent_on_agent_skill(store: SemanticStore) -> None:
    sts = SkillTraceStore(store, _TENANT)
    await sts.record_trace(agent_id="d7", skill_id="s1", category="c", trace="t1")
    await sts.record_trace(agent_id="d7", skill_id="s1", category="c", trace="t1-updated")
    examples = await sts.list_traces(agent_id="d7")
    assert len(examples) == 1  # same (agent, skill) → one row


async def test_category_filter_and_agent_scope(store: SemanticStore) -> None:
    sts = SkillTraceStore(store, _TENANT)
    await sts.record_trace(agent_id="d7", skill_id="a", category="narrate", trace="t")
    await sts.record_trace(agent_id="d7", skill_id="b", category="hypothesize", trace="t")
    await sts.record_trace(agent_id="d12", skill_id="c", category="narrate", trace="t")
    assert {e.skill_id for e in await sts.list_traces(agent_id="d7")} == {"a", "b"}
    narrate = await sts.list_traces(agent_id="d7", category="narrate")
    assert {e.skill_id for e in narrate} == {"a"}


async def test_tenant_isolation(store: SemanticStore) -> None:
    a = SkillTraceStore(store, "cust_a")
    b = SkillTraceStore(store, "cust_b")
    await a.record_trace(agent_id="d7", skill_id="s", category="c", trace="t")
    assert len(await a.list_traces(agent_id="d7")) == 1
    assert await b.list_traces(agent_id="d7") == []  # no cross-tenant leak


async def test_inert_when_no_store() -> None:
    sts = SkillTraceStore(None, _TENANT)
    assert sts.enabled is False
    assert await sts.record_trace(agent_id="d7", skill_id="s", category="c", trace="t") is None
    assert await sts.list_traces(agent_id="d7") == []


async def test_empty_trace_not_recorded(store: SemanticStore) -> None:
    sts = SkillTraceStore(store, _TENANT)
    assert await sts.record_trace(agent_id="d7", skill_id="s", category="c", trace="") is None
    assert await sts.list_traces(agent_id="d7") == []
