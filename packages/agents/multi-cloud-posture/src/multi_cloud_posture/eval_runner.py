"""`MultiCloudPostureEvalRunner` — the canonical `EvalRunner` for D.5.

Mirrors D.4's
[`eval_runner.py`](../../../network-threat/src/network_threat/eval_runner.py)
shape — patches the four reader tools at the agent module's import
scope, builds an `ExecutionContract` rooted at the suite-supplied
workspace, calls `multi_cloud_posture.agent.run`, then compares the
resulting `FindingsReport` to `case.expected`.

**Fixture keys** (under `fixture`):

- `defender: list[dict]` — each item shaped per `AzureDefenderFinding`.
- `activity: list[dict]` — each item shaped per `AzureActivityRecord`.
- `scc: list[dict]` — each item shaped per `GcpSccFinding`.
- `iam: list[dict]` — each item shaped per `GcpIamFinding`.
- `customer_domain_allowlist: list[str]` — optional; forwarded to the
  GCP IAM reader for external-user severity grading.

**Comparison shape** (under `expected`):

- `finding_count: int`
- `by_severity: {sev: int}` — checked when present.

Registered via `pyproject.toml`'s
`[project.entry-points."nexus_eval_runners"]` so
`eval-framework run --runner multi_cloud_posture` resolves it.
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

from multi_cloud_posture import agent as agent_mod
from multi_cloud_posture.schemas import FindingsReport
from multi_cloud_posture.tools.azure_activity import AzureActivityRecord
from multi_cloud_posture.tools.azure_defender import AzureDefenderFinding
from multi_cloud_posture.tools.gcp_iam import GcpIamFinding
from multi_cloud_posture.tools.gcp_scc import GcpSccFinding


class MultiCloudPostureEvalRunner:
    """Reference `EvalRunner` for the Multi-Cloud Posture Agent."""

    @property
    def agent_name(self) -> str:
        return "multi_cloud_posture"

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

    defender = tuple(_parse_defender(r) for r in fixture.get("defender", []) or [])
    activity = tuple(_parse_activity(r) for r in fixture.get("activity", []) or [])
    scc = tuple(_parse_scc(r) for r in fixture.get("scc", []) or [])
    iam = tuple(_parse_iam(r) for r in fixture.get("iam", []) or [])

    async def fake_defender(**_: Any) -> tuple[AzureDefenderFinding, ...]:
        return defender

    async def fake_activity(**_: Any) -> tuple[AzureActivityRecord, ...]:
        return activity

    async def fake_scc(**_: Any) -> tuple[GcpSccFinding, ...]:
        return scc

    async def fake_iam(**_: Any) -> tuple[GcpIamFinding, ...]:
        return iam

    workspace = Path(contract.workspace)
    workspace.mkdir(parents=True, exist_ok=True)

    # The agent driver skips the call_tool dispatch if the feed path is None.
    # Synthesize sentinel files when the fixture has records for that feed.
    defender_feed: Path | None = None
    activity_feed: Path | None = None
    scc_feed: Path | None = None
    iam_feed: Path | None = None
    if defender:
        defender_feed = workspace / "_fixture_defender.json"
        defender_feed.write_text("placeholder")
    if activity:
        activity_feed = workspace / "_fixture_activity.json"
        activity_feed.write_text("placeholder")
    if scc:
        scc_feed = workspace / "_fixture_scc.json"
        scc_feed.write_text("placeholder")
    if iam:
        iam_feed = workspace / "_fixture_iam.json"
        iam_feed.write_text("placeholder")

    customer_domain_allowlist_raw = fixture.get("customer_domain_allowlist") or []
    customer_domain_allowlist = tuple(
        str(d) for d in customer_domain_allowlist_raw if isinstance(d, str)
    )

    with ExitStack() as stack:
        stack.enter_context(patch.object(agent_mod, "read_azure_findings", fake_defender))
        stack.enter_context(patch.object(agent_mod, "read_azure_activity", fake_activity))
        stack.enter_context(patch.object(agent_mod, "read_gcp_findings", fake_scc))
        stack.enter_context(patch.object(agent_mod, "read_gcp_iam_findings", fake_iam))
        return await agent_mod.run(
            contract=contract,
            llm_provider=llm_provider,
            azure_findings_feed=defender_feed,
            azure_activity_feed=activity_feed,
            gcp_findings_feed=scc_feed,
            gcp_iam_feed=iam_feed,
            customer_domain_allowlist=customer_domain_allowlist,
        )


def _build_contract(case: EvalCase, workspace_root: Path) -> ExecutionContract:
    return ExecutionContract(
        schema_version="0.1",
        delegation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
        source_agent="supervisor",
        target_agent="multi_cloud_posture",
        customer_id="cust_eval",
        task=case.description or case.case_id,
        required_outputs=["findings.json", "report.md"],
        budget=BudgetSpec(
            llm_calls=1,
            tokens=1,
            wall_clock_sec=60.0,
            cloud_api_calls=10,
            mb_written=10,
        ),
        permitted_tools=[
            "read_azure_findings",
            "read_azure_activity",
            "read_gcp_findings",
            "read_gcp_iam_findings",
        ],
        completion_condition="findings.json exists",
        escalation_rules=[],
        workspace=str(workspace_root / "ws"),
        persistent_root=str(workspace_root / "p"),
        created_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(hours=1),
    )


def _evaluate(case: EvalCase, report: FindingsReport) -> tuple[bool, str | None]:
    sev_counts = report.count_by_severity()

    expected_count = case.expected.get("finding_count")
    if expected_count is not None and report.total != int(expected_count):
        return False, f"finding_count expected {expected_count}, got {report.total}"

    expected_sev = case.expected.get("by_severity") or {}
    for sev, want in expected_sev.items():
        actual = sev_counts.get(str(sev), 0)
        if actual != int(want):
            return False, f"severity '{sev}' expected {want}, got {actual}"

    return True, None


# ---------------------------- fixture -> dataclass parsing ---------------


def _parse_defender(raw: dict[str, Any]) -> AzureDefenderFinding:
    return AzureDefenderFinding(
        kind=str(raw.get("kind", "assessment")),
        record_id=str(raw.get("record_id", "")),
        display_name=str(raw.get("display_name", "")),
        severity=str(raw.get("severity", "Medium")),
        status=str(raw.get("status", "Unhealthy")),
        description=str(raw.get("description", "")),
        resource_id=str(raw.get("resource_id", "")),
        subscription_id=str(raw.get("subscription_id", "")),
        assessment_type=str(raw.get("assessment_type", "")),
        detected_at=_parse_dt(raw.get("detected_at")) or datetime.now(UTC),
        unmapped=dict(raw.get("unmapped", {}) or {}),
    )


def _parse_activity(raw: dict[str, Any]) -> AzureActivityRecord:
    return AzureActivityRecord(
        record_id=str(raw.get("record_id", "")),
        operation_name=str(raw.get("operation_name", "")),
        operation_class=str(raw.get("operation_class", "other")),
        category=str(raw.get("category", "Administrative")),
        level=str(raw.get("level", "Informational")),
        status=str(raw.get("status", "")),
        caller=str(raw.get("caller", "")),
        resource_id=str(raw.get("resource_id", "")),
        subscription_id=str(raw.get("subscription_id", "")),
        resource_group=str(raw.get("resource_group", "")),
        detected_at=_parse_dt(raw.get("detected_at")) or datetime.now(UTC),
        unmapped=dict(raw.get("unmapped", {}) or {}),
    )


def _parse_scc(raw: dict[str, Any]) -> GcpSccFinding:
    return GcpSccFinding(
        finding_name=str(raw.get("finding_name", "")),
        parent=str(raw.get("parent", "")),
        resource_name=str(raw.get("resource_name", "")),
        category=str(raw.get("category", "")),
        state=str(raw.get("state", "ACTIVE")),
        severity=str(raw.get("severity", "MEDIUM")),
        description=str(raw.get("description", "")),
        external_uri=str(raw.get("external_uri", "")),
        project_id=str(raw.get("project_id", "")),
        detected_at=_parse_dt(raw.get("detected_at")) or datetime.now(UTC),
        unmapped=dict(raw.get("unmapped", {}) or {}),
    )


def _parse_iam(raw: dict[str, Any]) -> GcpIamFinding:
    return GcpIamFinding(
        asset_name=str(raw.get("asset_name", "")),
        asset_type=str(raw.get("asset_type", "")),
        project_id=str(raw.get("project_id", "")),
        role=str(raw.get("role", "")),
        member=str(raw.get("member", "")),
        severity=str(raw.get("severity", "MEDIUM")),
        reason=str(raw.get("reason", "")),
        detected_at=_parse_dt(raw.get("detected_at")) or datetime.now(UTC),
        unmapped=dict(raw.get("unmapped", {}) or {}),
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


__all__ = ["MultiCloudPostureEvalRunner"]
