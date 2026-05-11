"""Tests for charter-audit instrumentation on every memory write (F.5 Task 8).

Every store-side write must emit a hash-chained `AuditLog.append` entry
with the canonical action name. The chain must verify via
`charter.verifier.verify_audit_log` after the writes.

Canonical action names (locked here):

- `episode_appended`     — `EpisodicStore.append_event`
- `playbook_published`   — `ProceduralStore.publish_version`
- `entity_upserted`      — `SemanticStore.upsert_entity`
- `relationship_added`   — `SemanticStore.add_relationship`

Each entry carries the same tenant_id, the natural / synthetic
identifier for the row that just landed, plus the action-specific
payload (e.g. correlation_id + agent_id for episodes; path + version
for playbooks).
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path

import pytest
import pytest_asyncio
from charter.audit import AuditLog
from charter.memory.episodic import EpisodicStore
from charter.memory.models import Base
from charter.memory.procedural import ProceduralStore
from charter.memory.semantic import SemanticStore
from charter.verifier import verify_audit_log
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine


@pytest_asyncio.fixture
async def session_factory() -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield async_sessionmaker(engine, expire_on_commit=False)
    await engine.dispose()


@pytest.fixture
def audit_log(tmp_path: Path) -> AuditLog:
    return AuditLog(
        path=tmp_path / "audit.jsonl",
        agent="memory",
        run_id="01HV0T0000000000000000RUN1",
    )


_TENANT = "01HV0T0000000000000000TEN1"


def _read_audit_lines(log: AuditLog) -> list[dict[str, object]]:
    import json

    return [json.loads(line) for line in log.path.read_text().splitlines() if line.strip()]


# ---------------------------- episodic -----------------------------------


@pytest.mark.asyncio
async def test_episodic_append_event_emits_audit_entry(
    session_factory: async_sessionmaker[AsyncSession],
    audit_log: AuditLog,
) -> None:
    store = EpisodicStore(session_factory, audit_log=audit_log)
    episode_id = await store.append_event(
        tenant_id=_TENANT,
        correlation_id="corr-1",
        agent_id="cloud_posture",
        action="finding.created",
        payload={"finding_id": "F-1"},
    )

    entries = _read_audit_lines(audit_log)
    assert len(entries) == 1
    e = entries[0]
    assert e["action"] == "episode_appended"
    payload = e["payload"]
    assert payload["tenant_id"] == _TENANT
    assert payload["episode_id"] == episode_id
    assert payload["correlation_id"] == "corr-1"
    assert payload["agent_id"] == "cloud_posture"


@pytest.mark.asyncio
async def test_episodic_store_without_audit_log_is_silent(
    session_factory: async_sessionmaker[AsyncSession],
    tmp_path: Path,
) -> None:
    """Audit is opt-in — passing no AuditLog must not raise."""
    store = EpisodicStore(session_factory)
    eid = await store.append_event(
        tenant_id=_TENANT,
        correlation_id="c",
        agent_id="a",
        action="x",
        payload={},
    )
    assert eid > 0


# ---------------------------- procedural ---------------------------------


@pytest.mark.asyncio
async def test_procedural_publish_emits_audit_entry(
    session_factory: async_sessionmaker[AsyncSession],
    audit_log: AuditLog,
) -> None:
    store = ProceduralStore(session_factory, audit_log=audit_log)
    version = await store.publish_version(
        tenant_id=_TENANT,
        path="remediation.s3.public_bucket",
        body={"steps": []},
    )

    entries = _read_audit_lines(audit_log)
    assert len(entries) == 1
    assert entries[0]["action"] == "playbook_published"
    payload = entries[0]["payload"]
    assert payload["tenant_id"] == _TENANT
    assert payload["path"] == "remediation.s3.public_bucket"
    assert payload["version"] == version


# ---------------------------- semantic -----------------------------------


@pytest.mark.asyncio
async def test_semantic_upsert_emits_audit_entry(
    session_factory: async_sessionmaker[AsyncSession],
    audit_log: AuditLog,
) -> None:
    store = SemanticStore(session_factory, audit_log=audit_log)
    entity_id = await store.upsert_entity(
        tenant_id=_TENANT, entity_type="host", external_id="i-abc"
    )

    entries = _read_audit_lines(audit_log)
    assert len(entries) == 1
    assert entries[0]["action"] == "entity_upserted"
    payload = entries[0]["payload"]
    assert payload["tenant_id"] == _TENANT
    assert payload["entity_id"] == entity_id
    assert payload["entity_type"] == "host"
    assert payload["external_id"] == "i-abc"


@pytest.mark.asyncio
async def test_semantic_add_relationship_emits_audit_entry(
    session_factory: async_sessionmaker[AsyncSession],
    audit_log: AuditLog,
) -> None:
    store = SemanticStore(session_factory, audit_log=audit_log)
    a = await store.upsert_entity(tenant_id=_TENANT, entity_type="host", external_id="a")
    b = await store.upsert_entity(tenant_id=_TENANT, entity_type="finding", external_id="F-1")
    rid = await store.add_relationship(
        tenant_id=_TENANT,
        src_entity_id=a,
        dst_entity_id=b,
        relationship_type="HAS_FINDING",
    )

    entries = _read_audit_lines(audit_log)
    # Two upserts + one relationship = 3 entries.
    assert len(entries) == 3
    last = entries[-1]
    assert last["action"] == "relationship_added"
    payload = last["payload"]
    assert payload["tenant_id"] == _TENANT
    assert payload["relationship_id"] == rid
    assert payload["src_entity_id"] == a
    assert payload["dst_entity_id"] == b
    assert payload["relationship_type"] == "HAS_FINDING"


# ---------------------------- chain verifies end-to-end ------------------


@pytest.mark.asyncio
async def test_audit_chain_verifies_after_mixed_writes(
    session_factory: async_sessionmaker[AsyncSession],
    audit_log: AuditLog,
) -> None:
    """A mixed write sequence across all three engines must leave the
    hash chain valid per `verify_audit_log`.
    """
    episodic = EpisodicStore(session_factory, audit_log=audit_log)
    procedural = ProceduralStore(session_factory, audit_log=audit_log)
    semantic = SemanticStore(session_factory, audit_log=audit_log)

    await episodic.append_event(
        tenant_id=_TENANT,
        correlation_id="c-1",
        agent_id="a",
        action="x",
        payload={"n": 1},
    )
    await procedural.publish_version(tenant_id=_TENANT, path="rem.x", body={"v": 1})
    e1 = await semantic.upsert_entity(tenant_id=_TENANT, entity_type="host", external_id="x")
    e2 = await semantic.upsert_entity(tenant_id=_TENANT, entity_type="finding", external_id="F-1")
    await semantic.add_relationship(
        tenant_id=_TENANT,
        src_entity_id=e1,
        dst_entity_id=e2,
        relationship_type="LINKS",
    )
    await episodic.append_event(
        tenant_id=_TENANT,
        correlation_id="c-2",
        agent_id="a",
        action="y",
        payload={"n": 2},
    )

    result = verify_audit_log(audit_log.path)
    assert result.valid
    assert result.entries_checked == 6
    assert result.broken_at is None


# ---------------------------- action-name discipline ---------------------


def test_audit_action_names_are_canonical() -> None:
    """Lock the four action names into module-level constants so renames
    are an explicit (test-breaking) change rather than a silent drift.
    """
    from charter.memory.audit import (
        ACTION_ENTITY_UPSERTED,
        ACTION_EPISODE_APPENDED,
        ACTION_PLAYBOOK_PUBLISHED,
        ACTION_RELATIONSHIP_ADDED,
    )

    assert ACTION_EPISODE_APPENDED == "episode_appended"
    assert ACTION_PLAYBOOK_PUBLISHED == "playbook_published"
    assert ACTION_ENTITY_UPSERTED == "entity_upserted"
    assert ACTION_RELATIONSHIP_ADDED == "relationship_added"
