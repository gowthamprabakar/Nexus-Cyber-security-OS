"""`AuditEvalRunner` — F.6's canonical `eval_framework.EvalRunner` (Task 14).

Mirrors D.3's [`eval_runner.py`](../../../runtime-threat/src/runtime_threat/eval_runner.py)
shape — builds an `ExecutionContract` rooted at the suite-supplied
workspace, materialises the fixture into a hash-chained jsonl file +
F.5 episodes table state, drives `audit.agent.run`, then compares the
result to `case.expected`.

Fixture schema (see `eval/cases/*.yaml`):

- `jsonl_events: list[dict]` — each dict shapes a `charter.audit.AuditEntry`.
  Required keys: `agent`, `run_id`, `action`, `payload`. Optional:
  `timestamp` (ISO-8601; defaults to a per-event monotonic timestamp
  starting at 2026-05-01T00:00:00Z).
- `memory_events: list[dict]` — each dict shapes an `EpisodeModel`
  insert. Required keys: `correlation_id`, `agent_id`, `action`,
  `payload`. Optional: `tenant_id` (defaults to the contract's
  customer_id); useful for tenant-isolation cases.
- `tampered_jsonl_index: int | None` — if set, the indexed jsonl
  event's payload is mutated AFTER its hash was computed, simulating
  tamper.
- `query: {since, until, action, agent_id, correlation_id}` — filter
  axes forwarded to `audit.agent.run`.
- `nl_query: str | None` + `llm_response: str | None` — when both
  present, the runner constructs a stub `LLMProvider` that returns
  `llm_response` for the prompt; the agent driver translates the NL
  question into typed params via `translate_nl_query`.

Comparison shape (see `eval/cases/*.yaml::expected`):

- `total: int` — must match `AuditQueryResult.total`.
- `chain_valid: bool` — must match the chain report embedded in
  `report.md` (a `False` here means the chain detected tamper).
- `count_by_action: dict[str, int]` — checked when present.

Registered via `pyproject.toml`'s
`[project.entry-points."nexus_eval_runners"]` so
`eval-framework run --runner audit` resolves it.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from charter.audit import GENESIS_HASH, _hash_entry
from charter.contract import BudgetSpec, ExecutionContract
from charter.llm import LLMProvider, LLMResponse, TokenUsage
from charter.memory.episodic import EpisodicStore
from charter.memory.models import Base
from eval_framework.cases import EvalCase
from eval_framework.runner import RunOutcome
from sqlalchemy.ext.asyncio import (
    async_sessionmaker,
    create_async_engine,
)

from audit.agent import run as audit_run
from audit.schemas import AuditQueryResult
from audit.store import AuditStore


class AuditEvalRunner:
    """Reference `EvalRunner` for the Audit Agent."""

    @property
    def agent_name(self) -> str:
        return "audit"

    async def run(
        self,
        case: EvalCase,
        *,
        workspace: Path,
        llm_provider: LLMProvider | None = None,
    ) -> RunOutcome:
        workspace.mkdir(parents=True, exist_ok=True)
        contract = _build_contract(case, workspace)
        report = await _run_case_async(case, contract, llm_provider=llm_provider)

        passed, failure_reason = _evaluate(case, report, workspace=Path(contract.workspace))
        actuals: dict[str, Any] = {
            "total": report.total,
            "chain_valid": _chain_valid_from_workspace(Path(contract.workspace)),
            "count_by_action": report.count_by_action,
            "count_by_agent": report.count_by_agent,
        }
        audit_log_path = Path(contract.workspace) / "audit.jsonl"
        return (
            passed,
            failure_reason,
            actuals,
            audit_log_path if audit_log_path.exists() else None,
        )


# ---------------------------- internals ----------------------------------


_TENANT_DEFAULT = "01HV0T0000000000000000TENA"


def _build_contract(case: EvalCase, workspace_root: Path) -> ExecutionContract:
    return ExecutionContract(
        schema_version="0.1",
        delegation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
        source_agent="supervisor",
        target_agent="audit",
        customer_id=_TENANT_DEFAULT,
        task=case.description or case.case_id,
        required_outputs=["report.md", "events.json"],
        budget=BudgetSpec(
            llm_calls=1,
            tokens=1,
            wall_clock_sec=60.0,
            cloud_api_calls=10,
            mb_written=10,
        ),
        permitted_tools=["audit_jsonl_read", "episode_audit_read"],
        completion_condition="report.md exists",
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
    llm_provider: LLMProvider | None,
) -> AuditQueryResult:
    fixture = case.fixture
    tenant_id = contract.customer_id

    # In-memory aiosqlite holds both the F.5 episodes table and F.6's
    # audit_events table for this case. Same Base.metadata, single
    # `create_all`.
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)

    # Seed F.5 episodes table per fixture's `memory_events`.
    memory_event_dicts = list(fixture.get("memory_events") or [])
    if memory_event_dicts:
        episodic = EpisodicStore(session_factory)
        for raw in memory_event_dicts:
            await episodic.append_event(
                tenant_id=str(raw.get("tenant_id", tenant_id)),
                correlation_id=str(raw["correlation_id"]),
                agent_id=str(raw["agent_id"]),
                action=str(raw["action"]),
                payload=dict(raw.get("payload") or {}),
            )

    # Materialise the jsonl chain (with optional tamper).
    sources: tuple[Path, ...] = ()
    jsonl_event_dicts = list(fixture.get("jsonl_events") or [])
    if jsonl_event_dicts:
        feed = Path(contract.workspace) / "_fixture_audit.jsonl"
        feed.parent.mkdir(parents=True, exist_ok=True)
        _write_jsonl_chain(
            feed,
            event_dicts=jsonl_event_dicts,
            tampered_index=fixture.get("tampered_jsonl_index"),
        )
        sources = (feed,)

    audit_store = AuditStore(session_factory)

    # Resolve query filters. NL-query path uses the LLM stub when both
    # `nl_query` and `llm_response` are present in the fixture.
    query_kwargs = await _resolve_query_kwargs(fixture, tenant_id=tenant_id)

    try:
        return await audit_run(
            contract,
            audit_store=audit_store,
            llm_provider=llm_provider,
            memory_session_factory=session_factory if memory_event_dicts else None,
            sources=sources,
            **query_kwargs,
        )
    finally:
        await engine.dispose()


async def _resolve_query_kwargs(fixture: dict[str, Any], *, tenant_id: str) -> dict[str, Any]:
    query = dict(fixture.get("query") or {})

    nl_query = fixture.get("nl_query")
    llm_response = fixture.get("llm_response")
    if nl_query and llm_response:
        # Stub the LLM, translate NL → params via `charter.llm_adapter`
        # consumption (F.6 Task 11), then merge the translated args
        # into the query filters. This exercises the full NL pipeline.
        from audit.query_translator import translate_nl_query

        provider = _StubLLMProvider(response_text=str(llm_response))
        args = await translate_nl_query(nl=str(nl_query), tenant_id=tenant_id, provider=provider)
        if args.action is not None:
            query["action"] = args.action
        if args.agent_id is not None:
            query["agent_id"] = args.agent_id
        if args.correlation_id is not None:
            query["correlation_id"] = args.correlation_id
        if args.since is not None:
            query["since"] = args.since
        if args.until is not None:
            query["until"] = args.until

    return {
        "since": _parse_dt(query.get("since")),
        "until": _parse_dt(query.get("until")),
        "action": query.get("action"),
        "agent_id": query.get("agent_id"),
        "correlation_id": query.get("correlation_id"),
    }


def _parse_dt(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    if isinstance(value, str):
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    return None


def _write_jsonl_chain(
    path: Path,
    *,
    event_dicts: list[dict[str, Any]],
    tampered_index: int | None,
) -> None:
    """Build a hash-chained jsonl. If `tampered_index` is set, mutate
    that entry's payload *after* its hash was computed so the chain
    verifier surfaces a break.
    """
    base_ts = datetime(2026, 5, 1, tzinfo=UTC)
    previous = GENESIS_HASH
    lines: list[str] = []
    for i, raw in enumerate(event_dicts):
        ts_raw = raw.get("timestamp")
        if ts_raw is None:
            ts = (base_ts + timedelta(seconds=i)).isoformat().replace("+00:00", "Z")
        else:
            ts = str(ts_raw)
        agent = str(raw["agent"])
        run_id = str(raw["run_id"])
        action = str(raw["action"])
        payload = dict(raw.get("payload") or {})

        entry_hash = _hash_entry(
            timestamp=ts,
            agent=agent,
            run_id=run_id,
            action=action,
            payload=payload,
            previous_hash=previous,
        )

        # Tamper: mutate the payload AFTER the hash was set.
        emitted_payload = payload
        if tampered_index is not None and i == int(tampered_index):
            emitted_payload = {**payload, "tampered": True}

        lines.append(
            json.dumps(
                {
                    "timestamp": ts,
                    "agent": agent,
                    "run_id": run_id,
                    "action": action,
                    "payload": emitted_payload,
                    "previous_hash": previous,
                    "entry_hash": entry_hash,
                }
            )
        )
        previous = entry_hash

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _evaluate(
    case: EvalCase,
    result: AuditQueryResult,
    *,
    workspace: Path,
) -> tuple[bool, str | None]:
    expected = case.expected
    expected_total = expected.get("total")
    if expected_total is not None and result.total != int(expected_total):
        return False, f"total expected {expected_total}, got {result.total}"

    expected_chain_valid = expected.get("chain_valid")
    if expected_chain_valid is not None:
        actual_chain_valid = _chain_valid_from_workspace(workspace)
        if actual_chain_valid != bool(expected_chain_valid):
            return False, (f"chain_valid expected {expected_chain_valid}, got {actual_chain_valid}")

    expected_action_counts = expected.get("count_by_action")
    if expected_action_counts is not None:
        actual = dict(result.count_by_action)
        for action, want in expected_action_counts.items():
            if actual.get(str(action), 0) != int(want):
                return False, (
                    f"count_by_action[{action!r}] expected {want}, got {actual.get(str(action), 0)}"
                )

    return True, None


def _chain_valid_from_workspace(workspace: Path) -> bool:
    """The agent driver writes `report.md` containing 'Chain valid' for a
    clean chain and 'Chain BROKEN' otherwise. We snoop the report
    rather than re-running the verifier — it's the operator-facing
    truth.
    """
    report = workspace / "report.md"
    if not report.is_file():
        return True
    text = report.read_text()
    return "Chain BROKEN" not in text


# ---------------------------- LLM stub for case 010 ---------------------


class _StubLLMProvider:
    """Lightweight LLM stub for the NL-query eval case.

    Wraps a fixed response string into the `LLMProvider` Protocol so
    `translate_nl_query` can run end-to-end without network access.
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


__all__ = ["AuditEvalRunner"]
