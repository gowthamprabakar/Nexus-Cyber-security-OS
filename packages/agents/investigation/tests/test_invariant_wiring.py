"""Phase C SS5 — D.7 investigation's six invariants are load-bearing in run().

Cycle 14 defined six code-level invariants (3 inherited from D.13 + 3 Orchestrator-Workers)
but the audit found none called from run(). This spy proves a real run invokes all six:
assert_worker_bounded (spawn), assert_bounded_retry (post-synthesis), and the four per-hypothesis
guards (no_speculation / evidence_chain / findings_cited / categorical_only).
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import investigation.agent as agent_mod
import pytest
import pytest_asyncio
from audit.schemas import AuditEvent
from audit.store import AuditStore
from charter.contract import BudgetSpec, ExecutionContract
from charter.memory.models import Base
from charter.memory.semantic import SemanticStore
from investigation.agent import run as investigation_run
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

_TENANT_A = "01HV0T0000000000000000TENA"


@pytest_asyncio.fixture
async def session_factory() -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield async_sessionmaker(engine, expire_on_commit=False)
    await engine.dispose()


@pytest_asyncio.fixture
async def audit_store(session_factory: async_sessionmaker[AsyncSession]) -> AuditStore:
    return AuditStore(session_factory)


@pytest_asyncio.fixture
async def semantic_store(session_factory: async_sessionmaker[AsyncSession]) -> SemanticStore:
    return SemanticStore(session_factory)


def _contract(workspace_root: Path) -> ExecutionContract:
    return ExecutionContract(
        schema_version="0.1",
        delegation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
        source_agent="supervisor",
        target_agent="investigation",
        customer_id=_TENANT_A,
        task="Investigate the incident",
        required_outputs=[
            "incident_report.json",
            "timeline.json",
            "hypotheses.md",
            "containment_plan.yaml",
        ],
        budget=BudgetSpec(
            llm_calls=30, tokens=60000, wall_clock_sec=600.0, cloud_api_calls=10, mb_written=10
        ),
        permitted_tools=[
            "audit_trail_query",
            "memory_neighbors_walk",
            "find_related_findings",
            "extract_iocs",
            "map_to_mitre",
            "reconstruct_timeline",
            "synthesize_hypotheses",
        ],
        completion_condition="incident_report.json exists",
        escalation_rules=[],
        workspace=str(workspace_root / "ws"),
        persistent_root=str(workspace_root / "p"),
        created_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(hours=1),
    )


def _audit_event(*, seed: int) -> AuditEvent:
    return AuditEvent(
        tenant_id=_TENANT_A,
        correlation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
        agent_id="cloud_posture",
        action="finding.created",
        payload={"seed": seed},
        previous_hash=f"{seed:064x}",
        entry_hash=f"{seed + 1:064x}",
        emitted_at=datetime(2026, 5, 12, tzinfo=UTC),
        source=f"jsonl:fixture/{seed}",
    )


def _write_sibling_findings(workspace: Path) -> None:
    workspace.mkdir(parents=True, exist_ok=True)
    report = {
        "agent": "cloud_posture",
        "agent_version": "0.1.0",
        "customer_id": _TENANT_A,
        "run_id": "sibling-run",
        "findings": [
            {
                "class_uid": 2003,
                "class_name": "Compliance Finding",
                "finding_info": {"uid": "F-1", "title": "Public bucket"},
                "time": int(datetime(2026, 5, 12, tzinfo=UTC).timestamp() * 1000),
            }
        ],
    }
    (workspace / "findings.json").write_text(json.dumps(report), encoding="utf-8")


@pytest.mark.asyncio
async def test_run_invokes_all_six_invariants(
    tmp_path: Path,
    audit_store: AuditStore,
    semantic_store: SemanticStore,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    await audit_store.ingest(tenant_id=_TENANT_A, events=(_audit_event(seed=1),))
    sibling_ws = tmp_path / "siblings" / "cloud_posture" / "r1"
    _write_sibling_findings(sibling_ws)

    seen: list[str] = []
    for name in (
        "assert_worker_bounded",
        "assert_bounded_retry",
        "assert_no_speculation",
        "assert_evidence_chain",
        "assert_findings_cited",
        "assert_categorical_only",
    ):
        real = getattr(agent_mod, name)

        def _spy(*args: object, _name: str = name, _real: object = real, **kwargs: object) -> None:
            seen.append(_name)
            _real(*args, **kwargs)  # type: ignore[operator]

        monkeypatch.setattr(agent_mod, name, _spy)

    await investigation_run(
        _contract(tmp_path),
        llm_provider=None,  # deterministic fallback → 1 hypothesis from F-1
        audit_store=audit_store,
        semantic_store=semantic_store,
        sibling_workspaces=(sibling_ws,),
    )

    # Spawn + post-synthesis guards always fire; the per-hypothesis guards fire on the survivor.
    assert {"assert_worker_bounded", "assert_bounded_retry"} <= set(seen)
    assert {
        "assert_no_speculation",
        "assert_evidence_chain",
        "assert_findings_cited",
        "assert_categorical_only",
    } <= set(seen)
