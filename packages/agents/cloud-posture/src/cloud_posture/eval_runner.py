"""`CloudPostureEvalRunner` — the canonical `EvalRunner` for cloud-posture.

Per F.2 plan Task 7. Migrates the patch + contract-build + evaluate logic
from `_eval_local._run_case_async`, lifts the case schema to the
framework's `EvalCase`, and returns the framework's `RunOutcome` shape so
the eval runs through `eval_framework.run_suite`.

`_eval_local.py` stays in place until F.2 Task 14 deletes it; this module
is what production code (the CLI in Task 13, future Meta-Harness rollups)
calls.
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

from cloud_posture import agent as agent_mod
from cloud_posture.schemas import FindingsReport
from cloud_posture.tools import aws_iam, aws_s3, prowler


class CloudPostureEvalRunner:
    """Reference `EvalRunner` for the cloud-posture agent.

    Patches the four async tool wrappers from `case.fixture`, builds an
    `ExecutionContract` rooted at the suite-supplied `workspace`, calls
    `cloud_posture.agent.run`, and compares the resulting `FindingsReport`
    to `case.expected`.
    """

    @property
    def agent_name(self) -> str:
        return "cloud_posture"

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
        return passed, failure_reason, actuals, audit_log_path if audit_log_path.exists() else None


# ---------------------------- internals ----------------------------------


async def _run_case_async(
    case: EvalCase,
    contract: ExecutionContract,
    *,
    llm_provider: LLMProvider | None,
) -> FindingsReport:
    """Patch the four tool wrappers per the fixture and run the agent."""
    fixture = case.fixture
    prowler_rows: list[dict[str, Any]] = list(fixture.get("prowler_findings", []))
    no_mfa_users: list[str] = list(fixture.get("iam_users_without_mfa", []))
    admin_policies: list[dict[str, Any]] = list(fixture.get("iam_admin_policies", []))
    s3_buckets: list[str] = list(fixture.get("s3_buckets", []))

    async def fake_prowler(**_kwargs: Any) -> prowler.ProwlerResult:
        return prowler.ProwlerResult(raw_findings=list(prowler_rows))

    async def fake_users() -> list[str]:
        return list(no_mfa_users)

    async def fake_admin() -> list[dict[str, Any]]:
        return [dict(p) for p in admin_policies]

    async def fake_s3_list(**_kwargs: Any) -> list[str]:
        return list(s3_buckets)

    with ExitStack() as stack:
        stack.enter_context(patch.object(prowler, "run_prowler_aws", fake_prowler))
        stack.enter_context(patch.object(aws_iam, "list_users_without_mfa", fake_users))
        stack.enter_context(patch.object(aws_iam, "list_admin_policies", fake_admin))
        stack.enter_context(patch.object(aws_s3, "list_buckets", fake_s3_list))
        return await agent_mod.run(
            contract=contract,
            llm_provider=llm_provider,
            neo4j_driver=None,
        )


def _build_contract(case: EvalCase, workspace_root: Path) -> ExecutionContract:
    return ExecutionContract(
        schema_version="0.1",
        delegation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
        source_agent="supervisor",
        target_agent="cloud_posture",
        customer_id="cust_eval",
        task=case.description or case.case_id,
        required_outputs=["findings.json", "summary.md"],
        budget=BudgetSpec(
            llm_calls=10,
            tokens=20_000,
            wall_clock_sec=60.0,
            cloud_api_calls=500,
            mb_written=10,
        ),
        permitted_tools=[
            "prowler_scan",
            "aws_s3_list_buckets",
            "aws_s3_describe",
            "aws_iam_list_users_without_mfa",
            "aws_iam_list_admin_policies",
        ],
        completion_condition="findings.json exists",
        escalation_rules=[],
        workspace=str(workspace_root / "ws"),
        persistent_root=str(workspace_root / "p"),
        created_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(hours=1),
    )


def _evaluate(case: EvalCase, report: FindingsReport) -> tuple[bool, str | None]:
    """Compare the report to `case.expected`. Returns (passed, failure_reason)."""
    counts = report.count_by_severity()

    expected_count = case.expected.get("finding_count")
    if expected_count is not None and report.total != int(expected_count):
        return False, f"finding_count expected {expected_count}, got {report.total}"

    expected_sev = case.expected.get("has_severity") or {}
    for sev, want in expected_sev.items():
        actual = counts.get(str(sev), 0)
        if actual != int(want):
            return False, f"severity '{sev}' expected {want}, got {actual}"

    return True, None
