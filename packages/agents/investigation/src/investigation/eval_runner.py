"""`InvestigationEvalRunner` — D.7's canonical eval_framework.EvalRunner (Task 14).

Mirrors F.6's eval-runner shape — builds an `ExecutionContract` rooted
at the suite-supplied workspace, materializes the fixture into an
in-memory aiosqlite store + temp sibling workspaces, drives
`investigation.agent.run`, then compares the result against
`case.expected`.

Fixture schema (see `eval/cases/*.yaml`):

- `audit_events: list[{seed, agent_id, action, emitted_at_offset_days?}]`
  → seeded into AuditStore before the run.
- `sibling_findings: list[{agent, findings: list[<OCSF dict + time_ms_offset_from_base>]}]`
  → written as `findings.json` in temp sibling workspace dirs.
- `llm_response: str | null` → when set, wraps a `_StubLLMProvider`
  that returns the configured text. Otherwise, llm_provider=None
  (fallback path).
- `window: {since_offset_days, until_offset_days}` → optional time
  filter forwarded to `investigation.agent.run`.

`expected` shape — sparse, only the keys asserted by each case:

- `hypotheses_count: int`
- `hypothesis_id_first: str`
- `hypothesis_confidence: float`
- `hypothesis_statement_contains: str`
- `timeline_events_count: int`
- `has_iocs: bool` / `ioc_count_min: int`
- `has_mitre_techniques: bool` / `mitre_technique_id_top: str`
- `has_containment_steps: bool` / `containment_steps_count: int` /
  `containment_class_uids: list[int]`
- `ocsf_class_uid: int` — always 2005 for D.7

Registered via `pyproject.toml`'s
`[project.entry-points."nexus_eval_runners"]` so
`eval-framework run --runner investigation` resolves.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from audit.schemas import AuditEvent
from audit.store import AuditStore
from charter.contract import BudgetSpec, ExecutionContract
from charter.llm import LLMProvider, LLMResponse, TokenUsage
from charter.memory import SemanticStore
from charter.memory.models import Base
from eval_framework.cases import EvalCase
from eval_framework.runner import RunOutcome
from sqlalchemy.ext.asyncio import (
    async_sessionmaker,
    create_async_engine,
)

from investigation.agent import run as investigation_run
from investigation.schemas import IncidentReport

_TENANT_A = "01HV0EVAL00000000000INVEST"
_BASE_TIME = datetime(2026, 5, 12, tzinfo=UTC)


class InvestigationEvalRunner:
    """Reference `EvalRunner` for the Investigation Agent."""

    @property
    def agent_name(self) -> str:
        return "investigation"

    async def run(
        self,
        case: EvalCase,
        *,
        workspace: Path,
        llm_provider: LLMProvider | None = None,
    ) -> RunOutcome:
        workspace.mkdir(parents=True, exist_ok=True)
        contract = _build_contract(case, workspace)
        report = await _run_case_async(case, contract, llm_provider_override=llm_provider)

        passed, failure_reason = _evaluate(case, report, contract=contract)
        actuals: dict[str, Any] = {
            "hypotheses_count": len(report.hypotheses),
            "timeline_events_count": len(report.timeline.events),
            "has_iocs": len(report.iocs) > 0,
            "ioc_count": len(report.iocs),
            "has_mitre_techniques": len(report.mitre_techniques) > 0,
            "ocsf_class_uid": report.to_ocsf()["class_uid"],
        }
        audit_log_path = Path(contract.workspace) / "audit.jsonl"
        return (
            passed,
            failure_reason,
            actuals,
            audit_log_path if audit_log_path.exists() else None,
        )


# ---------------------------- internals ----------------------------------


def _build_contract(case: EvalCase, workspace_root: Path) -> ExecutionContract:
    return ExecutionContract(
        schema_version="0.1",
        delegation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
        source_agent="supervisor",
        target_agent="investigation",
        customer_id=_TENANT_A,
        task=case.description or case.case_id,
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


async def _run_case_async(
    case: EvalCase,
    contract: ExecutionContract,
    *,
    llm_provider_override: LLMProvider | None,
) -> IncidentReport:
    fixture = case.fixture
    tenant_id = contract.customer_id

    # In-memory aiosqlite holds the F.5 + F.6 substrate tables for this
    # case. Same Base.metadata.create_all for everything.
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)

    audit_store = AuditStore(session_factory)
    semantic_store = SemanticStore(session_factory)

    # Seed the audit store from the fixture.
    audit_event_fixtures = list(fixture.get("audit_events") or [])
    if audit_event_fixtures:
        events = tuple(
            _audit_event_from_fixture(raw, tenant_id=tenant_id) for raw in audit_event_fixtures
        )
        await audit_store.ingest(tenant_id=tenant_id, events=events)

    # Materialize sibling workspaces from the fixture.
    sibling_workspaces: list[Path] = []
    sibling_fixtures = list(fixture.get("sibling_findings") or [])
    if sibling_fixtures:
        sibling_root = Path(contract.workspace).parent / "_siblings"
        for raw in sibling_fixtures:
            agent = str(raw.get("agent", "unknown"))
            ws = sibling_root / agent / "fixture-run"
            ws.mkdir(parents=True, exist_ok=True)
            findings = [_finding_payload_from_fixture(f) for f in (raw.get("findings") or [])]
            report = {
                "agent": agent,
                "agent_version": "0.1.0",
                "customer_id": tenant_id,
                "run_id": "fixture-run",
                "findings": findings,
            }
            (ws / "findings.json").write_text(json.dumps(report), encoding="utf-8")
            sibling_workspaces.append(ws)

    # Resolve LLM provider per fixture's `llm_response` field.
    llm_provider: LLMProvider | None
    if llm_provider_override is not None:
        llm_provider = llm_provider_override
    elif fixture.get("llm_response"):
        llm_provider = _StubLLMProvider(response_text=str(fixture["llm_response"]))
    else:
        llm_provider = None

    # Resolve optional time window.
    window = fixture.get("window") or {}
    since = _offset_to_datetime(window.get("since_offset_days"))
    until = _offset_to_datetime(window.get("until_offset_days"))

    try:
        return await investigation_run(
            contract,
            audit_store=audit_store,
            semantic_store=semantic_store,
            llm_provider=llm_provider,
            sibling_workspaces=tuple(sibling_workspaces),
            since=since,
            until=until,
        )
    finally:
        await engine.dispose()


def _audit_event_from_fixture(raw: dict[str, Any], *, tenant_id: str) -> AuditEvent:
    seed = int(raw["seed"])
    h_prev = f"{seed:064x}"
    h_entry = f"{seed + 1:064x}"
    emitted = _BASE_TIME
    if raw.get("emitted_at_offset_days") is not None:
        emitted = _BASE_TIME + timedelta(days=float(raw["emitted_at_offset_days"]))
    return AuditEvent(
        tenant_id=tenant_id,
        correlation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
        agent_id=str(raw.get("agent_id", "cloud_posture")),
        action=str(raw.get("action", "x")),
        payload={"seed": seed},
        previous_hash=h_prev,
        entry_hash=h_entry,
        emitted_at=emitted,
        source=f"jsonl:fixture/{seed}",
    )


def _finding_payload_from_fixture(raw: dict[str, Any]) -> dict[str, Any]:
    """Render a fixture finding dict into the OCSF wire shape."""
    out = dict(raw)
    # Compute the OCSF `time` field from the offset.
    offset_ms = int(raw.get("time_ms_offset_from_base", 0))
    out["time"] = int(_BASE_TIME.timestamp() * 1000) + offset_ms
    out.pop("time_ms_offset_from_base", None)
    return out


def _offset_to_datetime(offset_days: float | None) -> datetime | None:
    if offset_days is None:
        return None
    return _BASE_TIME + timedelta(days=float(offset_days))


# ---------------------------- evaluation ---------------------------------


def _evaluate(
    case: EvalCase,
    report: IncidentReport,
    *,
    contract: ExecutionContract,
) -> tuple[bool, str | None]:
    """Compare report against `case.expected`. Returns (passed, reason)."""
    expected = case.expected

    # Counts.
    if (want := expected.get("hypotheses_count")) is not None:
        actual = len(report.hypotheses)
        if actual != int(want):
            return False, f"hypotheses_count expected {want}, got {actual}"

    if (want := expected.get("timeline_events_count")) is not None:
        actual = len(report.timeline.events)
        if actual != int(want):
            return False, f"timeline_events_count expected {want}, got {actual}"

    # First hypothesis details (when present).
    if (want := expected.get("hypothesis_id_first")) is not None and (
        not report.hypotheses or report.hypotheses[0].hypothesis_id != str(want)
    ):
        actual_hid = report.hypotheses[0].hypothesis_id if report.hypotheses else None
        return False, f"hypothesis_id_first expected {want}, got {actual_hid}"

    if (want := expected.get("hypothesis_confidence")) is not None and (
        not report.hypotheses or abs(report.hypotheses[0].confidence - float(want)) > 1e-6
    ):
        actual_conf = report.hypotheses[0].confidence if report.hypotheses else None
        return False, f"hypothesis_confidence expected {want}, got {actual_conf}"

    if (want := expected.get("hypothesis_statement_contains")) is not None and (
        not report.hypotheses or str(want) not in report.hypotheses[0].statement
    ):
        return False, (
            f"hypothesis_statement_contains expected {want!r}, "
            f"statement = {report.hypotheses[0].statement if report.hypotheses else None!r}"
        )

    # IOCs.
    if (want := expected.get("has_iocs")) is not None:
        actual = len(report.iocs) > 0
        if actual != bool(want):
            return False, f"has_iocs expected {want}, got {actual}"
    if (want := expected.get("ioc_count_min")) is not None and len(report.iocs) < int(want):
        return False, f"ioc_count expected >= {want}, got {len(report.iocs)}"

    # MITRE.
    if (want := expected.get("has_mitre_techniques")) is not None:
        actual = len(report.mitre_techniques) > 0
        if actual != bool(want):
            return False, f"has_mitre_techniques expected {want}, got {actual}"
    if (want := expected.get("mitre_technique_id_top")) is not None and (
        not report.mitre_techniques or report.mitre_techniques[0].technique_id != str(want)
    ):
        actual_tid = report.mitre_techniques[0].technique_id if report.mitre_techniques else None
        return False, f"mitre_technique_id_top expected {want}, got {actual_tid}"

    # Containment plan (read the YAML file in the workspace).
    if (
        expected.get("has_containment_steps") is not None
        or expected.get("containment_steps_count") is not None
        or expected.get("containment_class_uids") is not None
    ):
        plan = _load_plan_from_workspace(contract)
        steps = plan.get("steps") or []

        if (want := expected.get("has_containment_steps")) is not None:
            actual = len(steps) > 0
            if actual != bool(want):
                return False, f"has_containment_steps expected {want}, got {actual}"

        if (want := expected.get("containment_steps_count")) is not None and len(steps) != int(
            want
        ):
            return False, f"containment_steps_count expected {want}, got {len(steps)}"

        if (want := expected.get("containment_class_uids")) is not None:
            want_set = {int(c) for c in want}
            actual_set = {int(s.get("class_uid", 0)) for s in steps}
            if want_set != actual_set:
                return False, (
                    f"containment_class_uids expected {sorted(want_set)}, got {sorted(actual_set)}"
                )

    # OCSF wire shape.
    if (want := expected.get("ocsf_class_uid")) is not None:
        actual = report.to_ocsf()["class_uid"]
        if actual != int(want):
            return False, f"ocsf_class_uid expected {want}, got {actual}"

    return True, None


def _load_plan_from_workspace(contract: ExecutionContract) -> dict[str, Any]:
    import yaml

    plan_path = Path(contract.workspace) / "containment_plan.yaml"
    if not plan_path.is_file():
        return {}
    parsed = yaml.safe_load(plan_path.read_text()) or {}
    if not isinstance(parsed, dict):
        return {}
    return parsed


# ---------------------------- LLM stub ----------------------------------


class _StubLLMProvider:
    """Lightweight LLM stub for cases 007 + 008.

    Returns the configured response text verbatim. The hash-keyed
    audit_event references in case 007 are constructed to match the
    seed=1 audit event's entry_hash, which is `0000...0002` (since
    seed=1 → entry_hash = `2:064x`).
    """

    provider_id = "stub"

    def __init__(self, *, response_text: str) -> None:
        self._response_text = response_text

    @property
    def model_class(self) -> Any:
        from charter.llm import ModelTier

        return ModelTier.WORKHORSE

    async def complete(
        self,
        *,
        prompt: str,
        model_pin: str,
        max_tokens: int,
        system: str | None = None,
        temperature: float = 0.0,
        stop: list[str] | None = None,
        tools: list[Any] | None = None,
    ) -> LLMResponse:
        return LLMResponse(
            text=self._response_text,
            stop_reason="end_turn",
            usage=TokenUsage(input_tokens=1, output_tokens=1),
            model_pin=model_pin,
            provider_id=self.provider_id,
        )


__all__ = ["InvestigationEvalRunner"]
