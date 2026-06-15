"""Hermes Phase 1 (C-2 PR4) — D.12 curiosity skill-candidate proposal.

Unit-tests the agent-local ``_propose_skill_candidate`` wiring: a run with enough
LLM stages proposes a ``skill_candidate`` into the SemanticStore (proposer-only,
C2-C); a run below the activity threshold proposes nothing.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock

import pytest
from charter.memory.semantic import SemanticStore
from curiosity.agent import _propose_skill_candidate

pytestmark = pytest.mark.asyncio


def _write_llm_audit(path: Path, *, n_llm: int) -> None:
    lines = [
        json.dumps(
            {
                "action": "curiosity.llm.call_completed",
                "payload": {"llm_call_count": 1},
                "entry_hash": f"h{i}",
            }
        )
        for i in range(n_llm)
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


async def test_proposes_candidate_on_five_llm_stages(tmp_path: Path) -> None:
    audit = tmp_path / "audit.jsonl"
    _write_llm_audit(audit, n_llm=5)
    store = AsyncMock(spec=SemanticStore)
    store.upsert_entity.return_value = "entity-id"

    await _propose_skill_candidate(
        audit_path=audit,
        semantic_store=store,
        agent_id="curiosity",
        run_id="run-1",
        tenant_id="tenant-1",
    )

    store.upsert_entity.assert_awaited_once()
    kwargs = store.upsert_entity.await_args.kwargs
    assert kwargs["entity_type"] == "skill_candidate"
    assert kwargs["tenant_id"] == "tenant-1"
    assert kwargs["external_id"].startswith("curiosity:")


async def test_no_candidate_below_threshold(tmp_path: Path) -> None:
    audit = tmp_path / "audit.jsonl"
    _write_llm_audit(audit, n_llm=4)
    store = AsyncMock(spec=SemanticStore)

    await _propose_skill_candidate(
        audit_path=audit,
        semantic_store=store,
        agent_id="curiosity",
        run_id="run-1",
        tenant_id="tenant-1",
    )

    store.upsert_entity.assert_not_awaited()
