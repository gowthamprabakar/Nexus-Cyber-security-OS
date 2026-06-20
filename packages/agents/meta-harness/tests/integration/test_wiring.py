"""Fleet Test Level 1 — meta-harness (A.4) wiring smoke.

Tier B (orchestration / fleet-evaluation). A.4 is the odd one out: it HAS a kg_writer (it
upserts `agent_scorecard` / `ab_comparison_result` entities) but emits NO findings.json OCSF,
and its run() signature is its own — `run(*, customer_id, run_id, workspace_root,
semantic_store, llm_provider, cases_resolver, ...)` — not the shared `(contract, *, ...)` shape.

L1 is SMOKE, not capability — proves plumbing only (run completes, the scorecard entity lands
in the graph, tenant-scoped). Scorecard accuracy / regression-flag policy is L2.

Tier-B assertion subset (every omission documented, swiss-bar #5/#12):
  * ASSERTS: run completes (MetaHarnessReport), the kg_writer wrote an `agent_scorecard` entity
    for the tenant, and tenant isolation (a second tenant's run writes a disjoint scorecard
    entity set — no cross-tenant leak).
  * USES store.list_entities_by_type("agent_scorecard") directly, NOT the shared
    assert_entity_written(category=NodeCategory.*): A.4's kg_writer upserts a CUSTOM string
    entity_type ("agent_scorecard"), not a charter NodeCategory enum member, so the shared
    category-typed helper does not apply. We assert the raw entity_type directly. Documented.
  * OMITS the shared assert_ocsf_valid / findings.json assertions: A.4 emits no OCSF and writes
    no findings.json (its artifact is meta_harness_report.md + graph entities). Documented;
    asserting an OCSF finding would be a fake-green.
  * OMITS assert_audit_chain: A.4 writes a workspace audit.jsonl ONLY on the Stage-6/7 skill-
    lifecycle DSPy path, which is gated behind a non-None llm_provider (+ NEXUS_DSPY_PRODUCTION).
    The default L1 smoke path (no llm_provider) produces NO workspace audit.jsonl, so there is
    no chain to verify. Driving the DSPy path just to manufacture an audit chain would change
    what we're smoke-testing. Documented deviation, not a skipped check.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
import pytest_asyncio
from charter.memory.models import Base
from charter.memory.semantic import SemanticStore
from eval_framework.cases import EvalCase
from meta_harness.agent import run
from meta_harness.eval import batch as batch_module
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

_SCORECARD_ENTITY_TYPE = "agent_scorecard"  # A.4 kg_writer's custom entity_type string


@pytest_asyncio.fixture
async def semantic_store() -> AsyncIterator[SemanticStore]:
    """A real aiosqlite-backed SemanticStore (the substrate's documented test backend).

    We use the concrete store (not a mock) so the scorecard write + tenant-scoped read are
    exercised end-to-end through the real upsert/list path (swiss-bar #2).
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


@dataclass
class _FakeEntryPoint:
    name: str
    group: str
    _target: object

    def load(self) -> object:
        return self._target


def _make_runner_class(agent_name: str) -> type:
    class _Runner:
        @property
        def agent_name(self) -> str:
            return agent_name

        async def run(
            self,
            case: EvalCase,
            *,
            workspace: Path,
            llm_provider: Any | None = None,
        ) -> tuple[bool, str | None, dict[str, Any], Path | None]:
            del workspace, llm_provider, case
            return True, None, {}, None

    return _Runner


def _write_case(cases_dir: Path, case_id: str) -> Path:
    cases_dir.mkdir(parents=True, exist_ok=True)
    (cases_dir / f"{case_id}.yaml").write_text(
        f"case_id: {case_id}\ndescription: test\nfixture: {{}}\nexpected: {{}}\n",
        encoding="utf-8",
    )
    return cases_dir


def _register_fake_runner(monkeypatch: pytest.MonkeyPatch, agent_name: str) -> None:
    """Patch the eval-runner entry-point discovery to expose one deterministic fake runner."""

    def fake_entry_points(*, group: str) -> list[_FakeEntryPoint]:
        assert group == "nexus_eval_runners"
        return [
            _FakeEntryPoint(
                name=agent_name, group="nexus_eval_runners", _target=_make_runner_class(agent_name)
            )
        ]

    monkeypatch.setattr(batch_module, "entry_points", fake_entry_points)


@pytest.mark.asyncio
async def test_wiring_meta_harness(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, semantic_store: SemanticStore
) -> None:
    """Tier B orchestration: run completes · kg_writer wrote an agent_scorecard entity ·
    tenant isolation. (No OCSF / no audit chain on the default path — see module docstring.)"""
    _register_fake_runner(monkeypatch, "cloud_posture")
    cases = _write_case(tmp_path / "cases", "c1")

    # tenant A
    ws_a = tmp_path / "a"
    ws_a.mkdir(parents=True, exist_ok=True)
    report_a = await run(
        customer_id="tenant_a",
        run_id="r1",
        workspace_root=ws_a,
        semantic_store=semantic_store,
        cases_resolver=lambda _aid: cases,
    )

    # run-completes.
    assert report_a.customer_id == "tenant_a"
    assert report_a.total_agents_evaluated == 1

    # kg_writer wrote the scorecard entity (custom string entity_type, queried directly).
    rows_a = await semantic_store.list_entities_by_type(
        tenant_id="tenant_a", entity_type=_SCORECARD_ENTITY_TYPE
    )
    assert rows_a, "A.4 kg_writer did not write an agent_scorecard entity for tenant_a"
    assert all(r.tenant_id == "tenant_a" for r in rows_a)
    # external_id convention is "<customer>:<run>:<agent>" — proves the write is fully scoped.
    assert any(r.external_id == "tenant_a:r1:cloud_posture" for r in rows_a), (
        f"scorecard external_id mismatch: {[r.external_id for r in rows_a]}"
    )

    # A.4 emits no findings.json (no OCSF) — confirm the artifact is the markdown report instead.
    assert (ws_a / "meta_harness_report.md").is_file()
    assert not (ws_a / "findings.json").exists()

    # tenant isolation: a second tenant's run writes a disjoint scorecard entity set.
    ws_b = tmp_path / "b"
    ws_b.mkdir(parents=True, exist_ok=True)
    await run(
        customer_id="tenant_b",
        run_id="r1",
        workspace_root=ws_b,
        semantic_store=semantic_store,
        cases_resolver=lambda _aid: cases,
    )
    rows_b = await semantic_store.list_entities_by_type(
        tenant_id="tenant_b", entity_type=_SCORECARD_ENTITY_TYPE
    )
    assert rows_b, "A.4 kg_writer did not write an agent_scorecard entity for tenant_b"
    ids_a = {r.entity_id for r in rows_a}
    ids_b = {r.entity_id for r in rows_b}
    assert ids_a and ids_b and not (ids_a & ids_b), (
        f"cross-tenant scorecard entity leak between tenant_a and tenant_b: {ids_a & ids_b}"
    )
    # tenant_a's scoped read never returns tenant_b's scorecards.
    assert all("tenant_b" not in r.external_id for r in rows_a)
