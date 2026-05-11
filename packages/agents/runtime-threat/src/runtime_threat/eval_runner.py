"""`RuntimeThreatEvalRunner` — the canonical `EvalRunner` for D.3.

Mirrors D.2's [`eval_runner.py`](../../../packages/agents/identity/src/identity/eval_runner.py)
shape — patches the three tool wrappers at the agent module's import
scope, builds an `ExecutionContract` rooted at the suite-supplied
workspace, calls `runtime_threat.agent.run`, then compares the
resulting `FindingsReport` to `case.expected`.

Fixture keys (under `fixture`):

- `falco_alerts: list[dict]` — each dict shapes a `FalcoAlert`.
  Required keys: `time`, `rule`, `priority`. Optional: `output`,
  `output_fields`, `tags`.
- `tracee_alerts: list[dict]` — each dict shapes a `TraceeAlert`.
  Required keys: `timestamp` (ns int OR ISO string), `event_name`.
  Optional: process / container / k8s / args / severity / description.
- `osquery_rows: list[dict[str, str]]` — pre-cooked OSQuery row dicts
  that bypass the real subprocess.
- `osquery_sql: str` — optional SQL string recorded on the
  `OsqueryResult` (cosmetic in the fixture).
- `osquery_severity: int` — caller-supplied 0-3 (default 2 → medium).
- `osquery_finding_context: str` — slug for the OSQuery finding_id
  context segment (default `query_hit`).

Comparison shape (under `expected`):

- `finding_count: int`
- `by_severity: {sev: int}` — checked when present.
- `by_finding_type: {ft: int}` — checked when present.

Registered via `pyproject.toml`'s
`[project.entry-points."nexus_eval_runners"]` so
`eval-framework run --runner runtime_threat` resolves it.
"""

from __future__ import annotations

from contextlib import ExitStack
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from unittest.mock import patch

from charter.contract import BudgetSpec, ExecutionContract
from charter.llm import LLMProvider
from eval_framework.cases import EvalCase
from eval_framework.runner import RunOutcome

from runtime_threat import agent as agent_mod
from runtime_threat.schemas import FindingsReport
from runtime_threat.tools.falco import FalcoAlert
from runtime_threat.tools.osquery import OsqueryResult
from runtime_threat.tools.tracee import TraceeAlert


class RuntimeThreatEvalRunner:
    """Reference `EvalRunner` for the Runtime Threat Agent."""

    @property
    def agent_name(self) -> str:
        return "runtime_threat"

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

        passed, failure_reason = _evaluate(case, report)
        actuals: dict[str, Any] = {
            "finding_count": report.total,
            "by_severity": report.count_by_severity(),
            "by_finding_type": report.count_by_finding_type(),
        }
        audit_log_path = Path(contract.workspace) / "audit.jsonl"
        return (
            passed,
            failure_reason,
            actuals,
            audit_log_path if audit_log_path.exists() else None,
        )


# ---------------------------- internals ----------------------------------


async def _run_case_async(
    case: EvalCase,
    contract: ExecutionContract,
    *,
    llm_provider: LLMProvider | None,
) -> FindingsReport:
    fixture = case.fixture

    falco_alerts = tuple(_parse_falco(a) for a in fixture.get("falco_alerts", []) or [])
    tracee_alerts = tuple(_parse_tracee(a) for a in fixture.get("tracee_alerts", []) or [])

    osquery_rows = fixture.get("osquery_rows", []) or []
    osquery_sql = str(fixture.get("osquery_sql", "SELECT 1"))
    osquery_severity = int(fixture.get("osquery_severity", 2))
    osquery_finding_context = str(fixture.get("osquery_finding_context", "query_hit"))
    osquery_result = (
        OsqueryResult(
            sql=osquery_sql,
            rows=tuple({str(k): str(v) for k, v in row.items()} for row in osquery_rows),
        )
        if osquery_rows
        else None
    )

    async def fake_falco(**_: Any) -> tuple[FalcoAlert, ...]:
        return falco_alerts

    async def fake_tracee(**_: Any) -> tuple[TraceeAlert, ...]:
        return tracee_alerts

    async def fake_osquery(**_: Any) -> OsqueryResult:
        # The agent driver skips invoking the tool when the SQL pack is empty,
        # so this fake is only entered when `osquery_result` is non-None.
        # Returning an empty result here is a defensive fallback.
        return osquery_result or OsqueryResult(sql="", rows=())

    # The agent reads the OSQuery `.sql` pack file from disk. We synthesize a
    # tmpfile under the contract's workspace and write the SQL there iff the
    # fixture asks OSQuery to be exercised.
    workspace = Path(contract.workspace)
    workspace.mkdir(parents=True, exist_ok=True)
    osquery_pack: Path | None = None
    if osquery_result is not None:
        osquery_pack = workspace / "_fixture_pack.sql"
        osquery_pack.write_text(osquery_sql)

    # Mirror the per-feed file existence the agent driver checks. Falco/Tracee
    # readers need a real path on disk to skip the missing-file guard.
    falco_feed: Path | None = None
    tracee_feed: Path | None = None
    if falco_alerts:
        falco_feed = workspace / "_fixture_falco.jsonl"
        falco_feed.write_text("placeholder\n")  # body ignored — reader is patched
    if tracee_alerts:
        tracee_feed = workspace / "_fixture_tracee.jsonl"
        tracee_feed.write_text("placeholder\n")

    with ExitStack() as stack:
        stack.enter_context(patch.object(agent_mod, "falco_alerts_read", fake_falco))
        stack.enter_context(patch.object(agent_mod, "tracee_alerts_read", fake_tracee))
        stack.enter_context(patch.object(agent_mod, "osquery_run", fake_osquery))
        return await agent_mod.run(
            contract=contract,
            llm_provider=llm_provider,
            falco_feed=falco_feed,
            tracee_feed=tracee_feed,
            osquery_pack=osquery_pack,
            osquery_severity=osquery_severity,
            osquery_finding_context=osquery_finding_context,
        )


def _build_contract(case: EvalCase, workspace_root: Path) -> ExecutionContract:
    return ExecutionContract(
        schema_version="0.1",
        delegation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
        source_agent="supervisor",
        target_agent="runtime_threat",
        customer_id="cust_eval",
        task=case.description or case.case_id,
        required_outputs=["findings.json", "summary.md"],
        budget=BudgetSpec(
            llm_calls=1,
            tokens=1,
            wall_clock_sec=60.0,
            cloud_api_calls=10,
            mb_written=10,
        ),
        permitted_tools=["falco_alerts_read", "tracee_alerts_read", "osquery_run"],
        completion_condition="findings.json exists",
        escalation_rules=[],
        workspace=str(workspace_root / "ws"),
        persistent_root=str(workspace_root / "p"),
        created_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(hours=1),
    )


def _evaluate(case: EvalCase, report: FindingsReport) -> tuple[bool, str | None]:
    sev_counts = report.count_by_severity()
    type_counts = report.count_by_finding_type()

    expected_count = case.expected.get("finding_count")
    if expected_count is not None and report.total != int(expected_count):
        return False, f"finding_count expected {expected_count}, got {report.total}"

    expected_sev = case.expected.get("by_severity") or {}
    for sev, want in expected_sev.items():
        actual = sev_counts.get(str(sev), 0)
        if actual != int(want):
            return False, f"severity '{sev}' expected {want}, got {actual}"

    expected_types = case.expected.get("by_finding_type") or {}
    for ft, want in expected_types.items():
        actual = type_counts.get(str(ft), 0)
        if actual != int(want):
            return False, f"finding_type '{ft}' expected {want}, got {actual}"

    return True, None


# ---------------------------- fixture -> dataclass parsing ---------------


def _parse_falco(raw: dict[str, Any]) -> FalcoAlert:
    time_value = _parse_dt(raw.get("time"))
    if time_value is None:
        time_value = datetime.now(UTC)
    tags_raw = raw.get("tags", []) or []
    return FalcoAlert(
        time=time_value,
        rule=str(raw.get("rule", "")),
        priority=str(raw.get("priority", "")),
        output=str(raw.get("output", "")),
        output_fields=dict(raw.get("output_fields", {}) or {}),
        tags=tuple(str(t) for t in tags_raw if isinstance(t, str)),
    )


def _parse_tracee(raw: dict[str, Any]) -> TraceeAlert:
    timestamp = _parse_timestamp_any(raw.get("timestamp"))
    if timestamp is None:
        timestamp = datetime.now(UTC)
    args_raw = raw.get("args", {}) or {}
    args = {str(k): str(v) for k, v in args_raw.items()} if isinstance(args_raw, dict) else {}
    return TraceeAlert(
        timestamp=timestamp,
        event_name=str(raw.get("event_name", "")),
        process_name=str(raw.get("process_name", "")),
        process_id=int(raw.get("process_id", 0)),
        host_name=str(raw.get("host_name", "")),
        container_image=str(raw.get("container_image", "")),
        container_id=str(raw.get("container_id", "")),
        args=args,
        severity=int(raw.get("severity", 0)),
        description=str(raw.get("description", "")),
        pod_name=str(raw.get("pod_name", "")),
        namespace=str(raw.get("namespace", "")),
    )


def _parse_dt(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    if isinstance(value, str) and value:
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    return None


def _parse_timestamp_any(value: Any) -> datetime | None:
    """Tracee timestamps come either as ns since epoch (int) or ISO string."""
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value / 1_000_000_000, tz=UTC)
    return _parse_dt(value)


__all__ = ["RuntimeThreatEvalRunner"]
