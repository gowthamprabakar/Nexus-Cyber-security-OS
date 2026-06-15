"""Tests for the injected skill-candidate persistence helper (Track C C-2 PR1).

The helper takes the SemanticStore as an injected dependency, so a tiny in-memory
fake suffices — keeping the test (and ``nexus_runtime``) free of any charter import.
"""

from __future__ import annotations

from typing import Any

import pytest
from nexus_runtime.hermes import SKILL_CANDIDATE_ENTITY_TYPE, upsert_skill_candidate

pytestmark = pytest.mark.asyncio


class _FakeStore:
    """Minimal stand-in matching SemanticStore.upsert_entity semantics."""

    def __init__(self) -> None:
        self.rows: dict[tuple[str, str, str], dict[str, Any]] = {}
        self.calls: list[dict[str, Any]] = []

    async def upsert_entity(
        self,
        *,
        tenant_id: str,
        entity_type: str,
        external_id: str,
        properties: dict[str, Any] | None = None,
    ) -> str:
        key = (tenant_id, entity_type, external_id)
        self.calls.append(
            {
                "tenant_id": tenant_id,
                "entity_type": entity_type,
                "external_id": external_id,
                "properties": properties,
            }
        )
        if key in self.rows:
            self.rows[key].update(properties or {})
            return f"id-{external_id}"
        self.rows[key] = dict(properties or {})
        return f"id-{external_id}"


async def test_upsert_uses_skill_candidate_entity_type() -> None:
    store = _FakeStore()
    entity_id = await upsert_skill_candidate(
        store,  # type: ignore[arg-type]
        tenant_id="tenant-1",
        skill_id="skill-abc",
        properties={"tool_sequence_hash": "deadbeef"},
    )
    assert entity_id == "id-skill-abc"
    assert store.calls[0]["entity_type"] == SKILL_CANDIDATE_ENTITY_TYPE
    assert store.calls[0]["external_id"] == "skill-abc"
    assert store.calls[0]["tenant_id"] == "tenant-1"


async def test_upsert_is_idempotent_by_key() -> None:
    store = _FakeStore()
    await upsert_skill_candidate(
        store,  # type: ignore[arg-type]
        tenant_id="t",
        skill_id="s",
        properties={"a": 1},
    )
    await upsert_skill_candidate(
        store,  # type: ignore[arg-type]
        tenant_id="t",
        skill_id="s",
        properties={"b": 2},
    )
    assert store.rows[("t", SKILL_CANDIDATE_ENTITY_TYPE, "s")] == {"a": 1, "b": 2}
