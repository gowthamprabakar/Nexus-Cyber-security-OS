"""Minimal local eval runner — placeholder until F.2 ships the eval-framework package.

Each YAML case is a fixture (mocks of Prowler / IAM / S3 tool outputs) plus
expected finding counts and severity distribution. `run_case(case)` runs the
agent driver against the fixture and returns a typed `EvalResult`.

Usage (CLI / script form, no pytest dep at runtime):

    from pathlib import Path
    from cloud_posture._eval_local import load_cases, run_case
    cases = load_cases(Path("packages/agents/cloud-posture/eval/cases"))
    results = [run_case(c) for c in cases]
    print(f"{sum(r.passed for r in results)}/{len(results)} passed")

When F.2 lands, the case schema and the comparison rules move into the
eval-framework package and this module is deleted.
"""

from __future__ import annotations

import asyncio
import tempfile
import uuid
from contextlib import ExitStack
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from unittest.mock import patch

import yaml
from charter.contract import BudgetSpec, ExecutionContract

from cloud_posture import agent as agent_mod
from cloud_posture.schemas import FindingsReport
from cloud_posture.tools import aws_iam, aws_s3, prowler


@dataclass(frozen=True, slots=True)
class EvalCase:
    """One eval fixture: tool outputs in, expected finding shape out."""

    case_id: str
    description: str
    fixture: dict[str, Any]
    expected: dict[str, Any]


@dataclass(frozen=True, slots=True)
class EvalResult:
    """Outcome of running a single `EvalCase` through the agent driver."""

    case_id: str
    passed: bool
    failure_reason: str | None
    actual_counts: dict[str, int]


def load_cases(directory: Path | str) -> list[EvalCase]:
    """Load every `*.yaml` case in `directory`, sorted lexicographically."""
    out: list[EvalCase] = []
    for path in sorted(Path(directory).glob("*.yaml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        out.append(
            EvalCase(
                case_id=str(data["case_id"]),
                description=str(data["description"]),
                fixture=dict(data.get("fixture", {})),
                expected=dict(data.get("expected", {})),
            )
        )
    return out


def run_case(case: EvalCase, workspace_root: Path | None = None) -> EvalResult:
    """Execute one eval case against the agent driver, mocking external tools.

    Async-aware: bridges the async agent into a sync interface using
    `asyncio.run`. Tool wrappers are patched at the module level so the
    registry sees the fakes when `build_registry()` constructs the tool
    metadata.
    """
    if workspace_root is None:
        # Fresh per-call workspace so concurrent runs don't collide.
        workspace_root = (
            Path(tempfile.gettempdir()) / "nexus-eval" / (f"{case.case_id}-{uuid.uuid4().hex[:8]}")
        )
    workspace_root.mkdir(parents=True, exist_ok=True)

    report = asyncio.run(_run_case_async(case, workspace_root))
    return _evaluate(case, report)


async def _run_case_async(case: EvalCase, workspace_root: Path) -> FindingsReport:
    """Patch the four async tool wrappers and run the agent under those fakes."""
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
        contract = _build_contract(case, workspace_root)
        return await agent_mod.run(contract=contract, neo4j_driver=None)


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


def _evaluate(case: EvalCase, report: FindingsReport) -> EvalResult:
    counts = report.count_by_severity()

    expected_count = case.expected.get("finding_count")
    if expected_count is not None and report.total != int(expected_count):
        return EvalResult(
            case_id=case.case_id,
            passed=False,
            failure_reason=(f"finding_count expected {expected_count}, got {report.total}"),
            actual_counts=counts,
        )

    expected_sev = case.expected.get("has_severity") or {}
    for sev, want in expected_sev.items():
        actual = counts.get(str(sev), 0)
        if actual != int(want):
            return EvalResult(
                case_id=case.case_id,
                passed=False,
                failure_reason=(f"severity '{sev}' expected {want}, got {actual}"),
                actual_counts=counts,
            )

    return EvalResult(
        case_id=case.case_id,
        passed=True,
        failure_reason=None,
        actual_counts=counts,
    )
