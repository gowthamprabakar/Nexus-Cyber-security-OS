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


# ============================================================================
# F.7 v0.2 Task 3 — bus_emit wiring tests
#
# These tests run agent.run() with publish_events_to_bus toggled on/off
# and a mocked JetStreamClient injected at the bus_emit module level.
# The load-bearing test is `test_run_continues_when_bus_publish_fails`
# which proves D.7's "filesystem artifacts are the contract" guarantee
# survives a broken bus — the user's non-negotiable requirement #3 from
# the Task 3 brief.
#
# Watch-item HELD: these tests do NOT modify packages/shared/. They
# monkeypatch shared.fabric.JetStreamClient at the consumption boundary
# (the bus_emit module's import) — substrate code is untouched.
# ============================================================================


def _read_audit_actions(workspace: Path) -> list[str]:
    """Read every action from the workspace's audit.jsonl in order."""
    audit_path = workspace / "audit.jsonl"
    if not audit_path.exists():
        return []
    return [json.loads(line)["action"] for line in audit_path.read_text().splitlines() if line]


def _make_jetstream_client_factory(
    *,
    publish_side_effect: object | None = None,
) -> type:
    """Build a fake JetStreamClient class that the BusEmitter can construct.

    The returned class has the minimal async surface BusEmitter calls:
    `connect`, `publish`, `close`. When `publish_side_effect` is an
    Exception (or list), publish raises it; otherwise it returns a
    PubAck-shaped namespace.
    """
    from unittest.mock import AsyncMock, MagicMock

    class _FakeJetStreamClient:
        def __init__(self, *args: object, **kwargs: object) -> None:
            self.connect = AsyncMock()
            self.close = AsyncMock()
            if publish_side_effect is not None:
                self.publish = AsyncMock(side_effect=publish_side_effect)
            else:
                self.publish = AsyncMock(return_value=MagicMock(stream="events", seq=1))

    return _FakeJetStreamClient


@pytest.mark.asyncio
async def test_run_with_flag_off_does_not_construct_bus_emitter(
    tmp_path: Path,
    audit_store: AuditStore,
    semantic_store: SemanticStore,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Flag-off code path: no BusEmitter is constructed, no NATS calls.
    Proves back-compat — D.7's behaviour is byte-identical to pre-v0.2.
    """
    import investigation.agent as agent_mod

    construction_count = {"n": 0}

    class _ShouldNotBeConstructed:
        def __init__(self, *args: object, **kwargs: object) -> None:
            construction_count["n"] += 1
            raise AssertionError("BusEmitter should not be constructed when flag is off")

    monkeypatch.setattr(agent_mod, "BusEmitter", _ShouldNotBeConstructed)

    contract = _contract(tmp_path)
    report = await investigation_run(
        contract,
        llm_provider=None,
        audit_store=audit_store,
        semantic_store=semantic_store,
        sibling_workspaces=(),
        since=None,
        until=None,
        publish_events_to_bus=False,
    )
    assert isinstance(report, IncidentReport)
    assert construction_count["n"] == 0
    # And no bus_publish.* audit entries.
    actions = _read_audit_actions(Path(contract.workspace))
    bus_actions = [a for a in actions if a.startswith("investigation.bus_publish.")]
    assert bus_actions == []


@pytest.mark.asyncio
async def test_run_with_flag_on_emits_started_and_completed_to_audit_chain(
    tmp_path: Path,
    audit_store: AuditStore,
    semantic_store: SemanticStore,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Happy path: working bus + flag on → two emits (started, completed),
    each landing 2 audit entries (attempt + success) = 4 bus_publish.*
    actions on the chain. The 4 filesystem artifacts are also written.
    """
    import investigation.bus_emit as bus_emit_mod

    fake_client_cls = _make_jetstream_client_factory()
    monkeypatch.setattr(bus_emit_mod, "JetStreamClient", fake_client_cls)

    contract = _contract(tmp_path)
    report = await investigation_run(
        contract,
        llm_provider=None,
        audit_store=audit_store,
        semantic_store=semantic_store,
        sibling_workspaces=(),
        since=None,
        until=None,
        publish_events_to_bus=True,
    )
    assert isinstance(report, IncidentReport)

    # 4 filesystem artifacts written.
    ws = Path(contract.workspace)
    assert (ws / "incident_report.json").is_file()
    assert (ws / "timeline.json").is_file()
    assert (ws / "hypotheses.md").is_file()
    assert (ws / "containment_plan.yaml").is_file()

    # 4 bus_publish entries on the chain: attempt+success for started,
    # then attempt+success for completed.
    actions = _read_audit_actions(ws)
    bus_actions = [a for a in actions if a.startswith("investigation.bus_publish.")]
    assert bus_actions == [
        "investigation.bus_publish.attempt",
        "investigation.bus_publish.success",
        "investigation.bus_publish.attempt",
        "investigation.bus_publish.success",
    ]


@pytest.mark.asyncio
async def test_run_continues_when_bus_publish_fails(
    tmp_path: Path,
    audit_store: AuditStore,
    semantic_store: SemanticStore,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """**LOAD-BEARING NON-FATAL PROOF** (user's Task-3 requirement #3).

    A broken bus (every publish raises FabricConnectionError) MUST NOT
    break D.7. The investigation runs to completion. All 4 filesystem
    artifacts are written. The audit chain records `bus_publish.failure`
    entries instead of `bus_publish.success`. D.7's "filesystem artifacts
    are the contract" guarantee is preserved.
    """
    import investigation.bus_emit as bus_emit_mod
    from shared.fabric import FabricConnectionError

    fake_client_cls = _make_jetstream_client_factory(
        publish_side_effect=FabricConnectionError("broker unreachable"),
    )
    monkeypatch.setattr(bus_emit_mod, "JetStreamClient", fake_client_cls)

    contract = _contract(tmp_path)
    report = await investigation_run(
        contract,
        llm_provider=None,
        audit_store=audit_store,
        semantic_store=semantic_store,
        sibling_workspaces=(),
        since=None,
        until=None,
        publish_events_to_bus=True,
    )

    # 1. The investigation completed — a real IncidentReport returned.
    assert isinstance(report, IncidentReport)

    # 2. All 4 filesystem artifacts were still written (the contract).
    ws = Path(contract.workspace)
    assert (ws / "incident_report.json").is_file()
    assert (ws / "timeline.json").is_file()
    assert (ws / "hypotheses.md").is_file()
    assert (ws / "containment_plan.yaml").is_file()

    # 3. The audit chain records bus_publish.failure (not .success) for
    # both the started and completed emit attempts.
    actions = _read_audit_actions(ws)
    bus_actions = [a for a in actions if a.startswith("investigation.bus_publish.")]
    assert bus_actions == [
        "investigation.bus_publish.attempt",
        "investigation.bus_publish.failure",
        "investigation.bus_publish.attempt",
        "investigation.bus_publish.failure",
    ]
    # 4. No bus_publish.success entries — confirms the failure path was
    # taken, not silently passed through.
    assert "investigation.bus_publish.success" not in actions


@pytest.mark.asyncio
async def test_run_emits_failed_on_pipeline_exception_and_reraises(
    tmp_path: Path,
    semantic_store: SemanticStore,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When a pipeline stage raises, the agent emits `investigation.failed`
    BEFORE the exception propagates. D.7's existing failure semantics are
    preserved: the exception still bubbles out of `agent.run()`.
    """
    import investigation.agent as agent_mod
    import investigation.bus_emit as bus_emit_mod

    # Force the SPAWN stage to raise by patching `_stage_spawn` to raise
    # a synthetic exception.
    async def _explode(*args: object, **kwargs: object) -> object:
        raise RuntimeError("synthetic spawn failure for test")

    monkeypatch.setattr(agent_mod, "_stage_spawn", _explode)

    fake_client_cls = _make_jetstream_client_factory()
    monkeypatch.setattr(bus_emit_mod, "JetStreamClient", fake_client_cls)

    # Use a fresh audit_store rather than the fixture — the fixture's
    # session_factory is module-scoped and we want a clean ledger.
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    fresh_audit_store = AuditStore(async_sessionmaker(engine, expire_on_commit=False))

    contract = _contract(tmp_path)
    try:
        with pytest.raises(RuntimeError, match="synthetic spawn failure"):
            await investigation_run(
                contract,
                llm_provider=None,
                audit_store=fresh_audit_store,
                semantic_store=semantic_store,
                sibling_workspaces=(),
                since=None,
                until=None,
                publish_events_to_bus=True,
            )

        # The audit chain captures:
        # - started (attempt + success at Stage-1)
        # - failed (attempt + success in the except path)
        actions = _read_audit_actions(Path(contract.workspace))
        bus_actions = [a for a in actions if a.startswith("investigation.bus_publish.")]
        # 2 attempts (started + failed) each with a corresponding success
        # entry (because the fake client's publish returns ack rather than
        # raises in this test).
        assert bus_actions.count("investigation.bus_publish.attempt") == 2
        assert bus_actions.count("investigation.bus_publish.success") == 2
        # No filesystem artifacts are written on Stage-2 failure (the
        # pipeline doesn't reach Stage-6 _write_artifacts) — D.7's
        # existing failure semantics are preserved.
        ws = Path(contract.workspace)
        assert not (ws / "incident_report.json").is_file()
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_run_emit_failed_carries_stage_and_exception_class(
    tmp_path: Path,
    semantic_store: SemanticStore,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The `investigation.failed` event payload carries the stage name +
    the exception class so downstream consumers can route on failure mode."""
    import investigation.agent as agent_mod
    import investigation.bus_emit as bus_emit_mod

    async def _explode_in_synthesize(*args: object, **kwargs: object) -> object:
        raise ValueError("synthetic synthesize failure")

    monkeypatch.setattr(agent_mod, "synthesize_hypotheses", _explode_in_synthesize)

    captured_publishes: list[bytes] = []

    class _CapturingClient:
        def __init__(self, *args: object, **kwargs: object) -> None:
            pass

        async def connect(self) -> None:
            pass

        async def close(self) -> None:
            pass

        async def publish(
            self,
            stream: object,
            subject: str,
            payload: bytes,
            **kwargs: object,
        ) -> object:
            from unittest.mock import MagicMock

            captured_publishes.append(payload)
            return MagicMock(stream="events", seq=1)

    monkeypatch.setattr(bus_emit_mod, "JetStreamClient", _CapturingClient)

    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    fresh_audit_store = AuditStore(async_sessionmaker(engine, expire_on_commit=False))

    contract = _contract(tmp_path)
    try:
        with pytest.raises(ValueError, match="synthetic synthesize failure"):
            await investigation_run(
                contract,
                llm_provider=None,
                audit_store=fresh_audit_store,
                semantic_store=semantic_store,
                sibling_workspaces=(),
                since=None,
                until=None,
                publish_events_to_bus=True,
            )
    finally:
        await engine.dispose()

    # Two publishes: started + failed. Decode the second to confirm
    # the stage and error_class fields are populated.
    assert len(captured_publishes) == 2
    failed_event = json.loads(captured_publishes[1])
    assert failed_event["event_type"] == "failed"
    assert failed_event["stage"] == "synthesize"
    assert failed_event["error_class"] == "ValueError"


# ---------------------------- C-3: charter-gated workers ------------------
# ADR-016 / audit #316 C-3: the worker tools that read external state
# (audit store / sibling filesystem / semantic store) dispatch through the
# parent charter; extract_iocs + map_to_mitre are pure and are NOT tools.


def test_registry_registers_only_stateful_tools() -> None:
    from investigation.agent import build_registry

    tools = set(build_registry().known_tools())
    assert tools == {"audit_trail_query", "find_related_findings", "memory_neighbors_walk"}
    # Pure transforms must not be registered (ADR-016 tool-vs-helper boundary).
    assert "extract_iocs" not in tools
    assert "map_to_mitre" not in tools


def test_stateful_tool_proxies_block_direct_invocation() -> None:
    from charter import DirectInvocationBlocked
    from investigation.agent import build_registry

    reg = build_registry()
    for name in ("audit_trail_query", "find_related_findings", "memory_neighbors_walk"):
        with pytest.raises(DirectInvocationBlocked) as exc:
            reg._tools[name].proxy(sibling_workspaces=())
        assert exc.value.tool == name


@pytest.mark.asyncio
async def test_worker_tool_calls_routed_through_charter_audit(
    tmp_path: Path,
    audit_store: AuditStore,
    semantic_store: SemanticStore,
) -> None:
    """The timeline + IOC/attribution workers' tool calls appear as charter
    tool_call audit events (proof they routed through ctx.call_tool)."""
    await audit_store.ingest(tenant_id=_TENANT_A, events=(_audit_event(seed=1),))
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
    lines = [
        json.loads(x)
        for x in (Path(contract.workspace) / "audit.jsonl").read_text().splitlines()
        if x.strip()
    ]
    tools_called = {e["payload"]["tool"] for e in lines if e.get("action") == "tool_call"}
    assert "audit_trail_query" in tools_called
    assert "find_related_findings" in tools_called


@pytest.mark.asyncio
async def test_assert_complete_wired_raises_on_missing_output(
    tmp_path: Path,
    audit_store: AuditStore,
    semantic_store: SemanticStore,
) -> None:
    """assert_complete() is now wired: a required output the agent never writes
    makes the run fail rather than silently 'complete'."""
    contract = _contract(tmp_path)
    contract.required_outputs.append("never_written.json")
    with pytest.raises(RuntimeError, match=r"never_written\.json"):
        await investigation_run(
            contract,
            llm_provider=None,
            audit_store=audit_store,
            semantic_store=semantic_store,
            sibling_workspaces=(),
            since=None,
            until=None,
        )


# ============================================================================
# Toxic-combination opt-in seam (Task 2)
#
# Two tests prove the `detect_toxic_combinations` flag:
#   1. opted-in  → toxic hypothesis survives Stage 4 + OCSF class_uid == 2005
#   2. flag-off  → byte-identical to default; no toxic hypothesis leaks
# ============================================================================

from charter.memory.graph_types import EdgeType, NodeCategory  # noqa: E402


async def _tc_seed_graph(
    store: SemanticStore, tenant: str, *, principal_arn: str, bucket_arn: str
) -> None:
    """Populate the minimum graph for a public-data-exposure toxic combination."""
    role = await store.upsert_entity(
        tenant_id=tenant,
        entity_type=NodeCategory.IDENTITY.value,
        external_id=principal_arn,
        properties={},
    )
    bucket = await store.upsert_entity(
        tenant_id=tenant,
        entity_type=NodeCategory.CLOUD_RESOURCE.value,
        external_id=bucket_arn,
        properties={},
    )
    data = await store.upsert_entity(
        tenant_id=tenant,
        entity_type=NodeCategory.DATA_CLASSIFICATION.value,
        external_id=f"{bucket_arn}:ssn",
        properties={"data_type": "ssn"},
    )
    await store.add_relationship(
        tenant_id=tenant,
        src_entity_id=role,
        dst_entity_id=bucket,
        relationship_type=EdgeType.HAS_ACCESS_TO.value,
        properties={},
    )
    await store.add_relationship(
        tenant_id=tenant,
        src_entity_id=bucket,
        dst_entity_id=data,
        relationship_type=EdgeType.EXPOSES_DATA.value,
        properties={},
    )


def _tc_identity_workspace(tmp_path: Path, principal_arn: str) -> Path:
    """Create a sibling identity workspace with one overprivilege finding."""
    ws = tmp_path / "identity_ws"
    ws.mkdir()
    (ws / "findings.json").write_text(
        json.dumps(
            {
                "agent": "identity",
                "run_id": "r1",
                "findings": [
                    {
                        "class_uid": 2004,
                        "finding_info": {
                            "uid": "IDENT-OVERPRIV-app-001-x",
                            "types": ["overprivilege"],
                        },
                        "affected_principals": [
                            {"type": "Role", "name": "app", "uid": principal_arn},
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    return ws


@pytest.mark.asyncio
async def test_run_surfaces_toxic_combination_when_opted_in(
    tmp_path: Path,
    audit_store: AuditStore,
    semantic_store: SemanticStore,
) -> None:
    """Flag ON: toxic hypothesis survives Stage 4 and the report is OCSF 2005."""
    principal = "arn:aws:iam::1:role/app"
    bucket = "arn:aws:s3:::acme-pii"
    await _tc_seed_graph(semantic_store, _TENANT_A, principal_arn=principal, bucket_arn=bucket)
    ws = _tc_identity_workspace(tmp_path, principal)

    contract = _contract(tmp_path)
    report = await investigation_run(
        contract,
        llm_provider=None,
        audit_store=audit_store,
        semantic_store=semantic_store,
        sibling_workspaces=(ws,),
        since=None,
        until=None,
        detect_toxic_combinations=True,
    )

    statements = [h.statement.lower() for h in report.hypotheses]
    assert any("over-permissioned" in s for s in statements), (
        "toxic hypothesis must survive Stage 4"
    )
    ocsf = report.to_ocsf()
    assert ocsf["class_uid"] == 2005


@pytest.mark.asyncio
async def test_run_inert_when_flag_off(
    tmp_path: Path,
    audit_store: AuditStore,
    semantic_store: SemanticStore,
) -> None:
    """Flag OFF (default): no toxic hypothesis; run is byte-identical to pre-seam."""
    principal = "arn:aws:iam::1:role/app"
    bucket = "arn:aws:s3:::acme-pii"
    await _tc_seed_graph(semantic_store, _TENANT_A, principal_arn=principal, bucket_arn=bucket)
    ws = _tc_identity_workspace(tmp_path, principal)

    contract = _contract(tmp_path)
    report = await investigation_run(
        contract,
        llm_provider=None,
        audit_store=audit_store,
        semantic_store=semantic_store,
        sibling_workspaces=(ws,),
        since=None,
        until=None,
        # detect_toxic_combinations defaults to False — omit to prove the default
    )

    statements = [h.statement.lower() for h in report.hypotheses]
    assert not any("over-permissioned" in s for s in statements), "flag OFF → no toxic hypothesis"
