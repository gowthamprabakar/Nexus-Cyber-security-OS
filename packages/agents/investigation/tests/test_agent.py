"""Tests for `investigation.agent.run` (D.7 Task 12).

The 6-stage Orchestrator-Workers pipeline:

    SCOPE → SPAWN → SYNTHESIZE → VALIDATE → PLAN → HANDOFF

Production contract:

- `run(contract, *, llm_provider, audit_store, semantic_store,
  sibling_workspaces, since, until)` returns an `IncidentReport`.
- Writes four artifacts to the contract workspace:
  - `incident_report.json` — OCSF 2005 wire shape
  - `timeline.json` — sorted Timeline
  - `hypotheses.md` — operator-readable hypothesis tracking
  - `containment_plan.yaml` — Stage 5 output
- SPAWN stage runs up to 4 sub-investigations in parallel under the
  SubAgentOrchestrator (allowlist-enforced).
- SYNTHESIZE uses `synthesize_hypotheses` (load-bearing LLM). VALIDATE
  drops unresolved hypotheses.
- PLAN emits per-class_uid containment templates.
- HANDOFF is the final write + return.
- No `wall_clock_sec` always-on relaxation (D.7 is NOT in the v1.3
  allowlist).
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import pytest_asyncio
import yaml
from audit.schemas import AuditEvent
from audit.store import AuditStore
from charter.contract import BudgetSpec, ExecutionContract
from charter.memory import SemanticStore
from charter.memory.models import Base
from investigation.agent import run as investigation_run
from investigation.schemas import IncidentReport
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine


@pytest_asyncio.fixture
async def session_factory() -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield async_sessionmaker(engine, expire_on_commit=False)
    await engine.dispose()


@pytest_asyncio.fixture
async def audit_store(
    session_factory: async_sessionmaker[AsyncSession],
) -> AuditStore:
    return AuditStore(session_factory)


@pytest_asyncio.fixture
async def semantic_store(
    session_factory: async_sessionmaker[AsyncSession],
) -> SemanticStore:
    return SemanticStore(session_factory)


_TENANT_A = "01HV0T0000000000000000TENA"


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
            llm_calls=30,
            tokens=60000,
            wall_clock_sec=600.0,
            cloud_api_calls=10,
            mb_written=10,
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
    h_prev = f"{seed:064x}"
    h_entry = f"{seed + 1:064x}"
    return AuditEvent(
        tenant_id=_TENANT_A,
        correlation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
        agent_id="cloud_posture",
        action="finding.created",
        payload={"seed": seed},
        previous_hash=h_prev,
        entry_hash=h_entry,
        emitted_at=datetime(2026, 5, 12, tzinfo=UTC),
        source=f"jsonl:fixture/{seed}",
    )


def _write_sibling_findings(workspace: Path, *, agent: str, findings: list[dict]) -> None:
    workspace.mkdir(parents=True, exist_ok=True)
    report = {
        "agent": agent,
        "agent_version": "0.1.0",
        "customer_id": _TENANT_A,
        "run_id": "sibling-run",
        "findings": findings,
    }
    (workspace / "findings.json").write_text(json.dumps(report), encoding="utf-8")


# ---------------------------- happy path -------------------------------


@pytest.mark.asyncio
async def test_run_with_no_sources_emits_empty_incident_report(
    tmp_path: Path,
    audit_store: AuditStore,
    semantic_store: SemanticStore,
) -> None:
    """Zero audit events + zero siblings + no LLM → empty report with
    fallback hypotheses (zero, since no findings → nothing to enumerate)."""
    contract = _contract(tmp_path)
    report = await investigation_run(
        contract,
        llm_provider=None,
        audit_store=audit_store,
        semantic_store=semantic_store,
        sibling_workspaces=(),
        since=None,
        until=None,
    )
    assert isinstance(report, IncidentReport)
    assert report.hypotheses == ()
    assert report.timeline.events == ()
    # Workspace artifacts emitted (required_outputs).
    assert (Path(contract.workspace) / "incident_report.json").is_file()
    assert (Path(contract.workspace) / "timeline.json").is_file()
    assert (Path(contract.workspace) / "hypotheses.md").is_file()
    assert (Path(contract.workspace) / "containment_plan.yaml").is_file()


@pytest.mark.asyncio
async def test_run_ingests_audit_events_and_sibling_findings(
    tmp_path: Path,
    audit_store: AuditStore,
    semantic_store: SemanticStore,
) -> None:
    """Seed audit + sibling findings → timeline merges them; fallback
    hypotheses enumerate one per finding."""
    await audit_store.ingest(
        tenant_id=_TENANT_A, events=(_audit_event(seed=1), _audit_event(seed=3))
    )
    sibling_ws = tmp_path / "siblings" / "cloud_posture" / "r1"
    _write_sibling_findings(
        sibling_ws,
        agent="cloud_posture",
        findings=[
            {
                "class_uid": 2003,
                "class_name": "Compliance Finding",
                "finding_info": {"uid": "F-1", "title": "Public bucket"},
                "time": int(datetime(2026, 5, 12, tzinfo=UTC).timestamp() * 1000),
            },
        ],
    )

    contract = _contract(tmp_path)
    report = await investigation_run(
        contract,
        llm_provider=None,
        audit_store=audit_store,
        semantic_store=semantic_store,
        sibling_workspaces=(sibling_ws,),
        since=None,
        until=None,
    )
    # 2 audit events + 1 finding = 3 timeline events.
    assert len(report.timeline.events) == 3
    # 1 finding → 1 fallback hypothesis.
    assert len(report.hypotheses) == 1
    assert "Public bucket" in report.hypotheses[0].statement


# ---------------------------- 4 artifacts -----------------------------


@pytest.mark.asyncio
async def test_run_writes_incident_report_json_as_ocsf_envelope(
    tmp_path: Path,
    audit_store: AuditStore,
    semantic_store: SemanticStore,
) -> None:
    contract = _contract(tmp_path)
    await investigation_run(
        contract,
        llm_provider=None,
        audit_store=audit_store,
        semantic_store=semantic_store,
        sibling_workspaces=(),
        since=None,
        until=None,
    )
    payload = json.loads((Path(contract.workspace) / "incident_report.json").read_text())
    assert payload["class_uid"] == 2005
    assert payload["class_name"] == "Incident Finding"


@pytest.mark.asyncio
async def test_run_writes_timeline_json_sorted_by_emitted_at(
    tmp_path: Path,
    audit_store: AuditStore,
    semantic_store: SemanticStore,
) -> None:
    await audit_store.ingest(
        tenant_id=_TENANT_A, events=(_audit_event(seed=1), _audit_event(seed=3))
    )
    contract = _contract(tmp_path)
    await investigation_run(
        contract,
        llm_provider=None,
        audit_store=audit_store,
        semantic_store=semantic_store,
        sibling_workspaces=(),
        since=None,
        until=None,
    )
    timeline = json.loads((Path(contract.workspace) / "timeline.json").read_text())
    # Two audit events emitted; the JSON wraps Timeline.events.
    assert "events" in timeline
    assert len(timeline["events"]) == 2


@pytest.mark.asyncio
async def test_run_writes_hypotheses_markdown(
    tmp_path: Path,
    audit_store: AuditStore,
    semantic_store: SemanticStore,
) -> None:
    sibling_ws = tmp_path / "siblings" / "cloud_posture" / "r1"
    _write_sibling_findings(
        sibling_ws,
        agent="cloud_posture",
        findings=[
            {
                "class_uid": 2003,
                "class_name": "Compliance Finding",
                "finding_info": {"uid": "F-1", "title": "Public bucket"},
                "time": int(datetime(2026, 5, 12, tzinfo=UTC).timestamp() * 1000),
            },
        ],
    )

    contract = _contract(tmp_path)
    await investigation_run(
        contract,
        llm_provider=None,
        audit_store=audit_store,
        semantic_store=semantic_store,
        sibling_workspaces=(sibling_ws,),
        since=None,
        until=None,
    )
    markdown = (Path(contract.workspace) / "hypotheses.md").read_text()
    assert "# Hypotheses" in markdown
    assert "Public bucket" in markdown
    # LLM-unavailable banner present (D.7 NLAH example 02).
    assert "without LLM synthesis" in markdown


@pytest.mark.asyncio
async def test_run_writes_containment_plan_yaml_with_class_specific_template(
    tmp_path: Path,
    audit_store: AuditStore,
    semantic_store: SemanticStore,
) -> None:
    sibling_ws = tmp_path / "siblings" / "cloud_posture" / "r1"
    _write_sibling_findings(
        sibling_ws,
        agent="cloud_posture",
        findings=[
            {
                "class_uid": 2003,
                "class_name": "Compliance Finding",
                "finding_info": {"uid": "F-1", "title": "Public bucket"},
                "time": int(datetime(2026, 5, 12, tzinfo=UTC).timestamp() * 1000),
            },
        ],
    )

    contract = _contract(tmp_path)
    await investigation_run(
        contract,
        llm_provider=None,
        audit_store=audit_store,
        semantic_store=semantic_store,
        sibling_workspaces=(sibling_ws,),
        since=None,
        until=None,
    )
    plan = yaml.safe_load((Path(contract.workspace) / "containment_plan.yaml").read_text())
    # The plan has at least one step per finding.
    assert "steps" in plan
    assert len(plan["steps"]) >= 1
    # Class 2003 template mentions remediation playbook.
    assert any("remediation" in str(step).lower() for step in plan["steps"])


# ---------------------------- VALIDATE stage --------------------------


@pytest.mark.asyncio
async def test_run_returns_report_with_validated_hypotheses_only(
    tmp_path: Path,
    audit_store: AuditStore,
    semantic_store: SemanticStore,
) -> None:
    """Fallback hypotheses always validate (their evidence_refs point at
    their source finding). This pins that the validator doesn't drop
    them spuriously.
    """
    sibling_ws = tmp_path / "siblings" / "cloud_posture" / "r1"
    _write_sibling_findings(
        sibling_ws,
        agent="cloud_posture",
        findings=[
            {
                "class_uid": 2003,
                "class_name": "x",
                "finding_info": {"uid": "F-1", "title": "T1"},
                "time": int(datetime(2026, 5, 12, tzinfo=UTC).timestamp() * 1000),
            },
            {
                "class_uid": 2003,
                "class_name": "x",
                "finding_info": {"uid": "F-2", "title": "T2"},
                "time": int(datetime(2026, 5, 12, tzinfo=UTC).timestamp() * 1000),
            },
        ],
    )
    contract = _contract(tmp_path)
    report = await investigation_run(
        contract,
        llm_provider=None,
        audit_store=audit_store,
        semantic_store=semantic_store,
        sibling_workspaces=(sibling_ws,),
        since=None,
        until=None,
    )
    assert len(report.hypotheses) == 2


# ---------------------------- contract pass-through -------------------


@pytest.mark.asyncio
async def test_run_uses_contract_customer_id_as_tenant(
    tmp_path: Path,
    audit_store: AuditStore,
    semantic_store: SemanticStore,
) -> None:
    contract = _contract(tmp_path)
    report = await investigation_run(
        contract,
        llm_provider=None,
        audit_store=audit_store,
        semantic_store=semantic_store,
        sibling_workspaces=(),
        since=None,
        until=None,
    )
    assert report.tenant_id == _TENANT_A
    assert report.correlation_id == contract.delegation_id


@pytest.mark.asyncio
async def test_run_emits_unique_incident_id(
    tmp_path: Path,
    audit_store: AuditStore,
    semantic_store: SemanticStore,
) -> None:
    contract = _contract(tmp_path)
    report_a = await investigation_run(
        contract,
        llm_provider=None,
        audit_store=audit_store,
        semantic_store=semantic_store,
        sibling_workspaces=(),
        since=None,
        until=None,
    )
    # Reset workspace for the second call.
    import shutil

    shutil.rmtree(Path(contract.workspace))
    shutil.rmtree(Path(contract.persistent_root), ignore_errors=True)
    report_b = await investigation_run(
        contract,
        llm_provider=None,
        audit_store=audit_store,
        semantic_store=semantic_store,
        sibling_workspaces=(),
        since=None,
        until=None,
    )
    assert report_a.incident_id != report_b.incident_id
