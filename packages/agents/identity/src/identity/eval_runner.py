"""`IdentityEvalRunner` — the canonical `EvalRunner` for the Identity Agent.

Mirrors D.1's [`eval_runner.py`](../../../packages/agents/vulnerability/src/vulnerability/eval_runner.py)
shape — patches the tool wrappers at the agent module's import scope so
the registered tools resolve to deterministic fakes, builds an
`ExecutionContract` rooted at the suite-supplied workspace, calls
`identity.agent.run`, then compares the resulting `FindingsReport` to
`case.expected`.

Fixture keys (under `fixture`):

- `iam_listing: {users, roles, groups}` — each principal is a dict that
  feeds the matching frozen dataclass. `last_used_at` accepts an ISO-8601
  string or null. Missing fields default sensibly.
- `analyzer_arn: str | null` — when present, the Access Analyzer wrapper
  is patched in and the value is forwarded to `agent.run`. When null, the
  wrapper is skipped (mirrors v0.1 default behavior).
- `access_analyzer_findings: list[dict]` — flat list parsed into
  `AccessAnalyzerFinding`s. Defaults to `[]`.
- `users_with_mfa: list[str]` — user names forming the MFA-satisfied set.
- `dormant_threshold_days: int` — overrides the agent's default (90).

Comparison shape (under `expected`):

- `finding_count: int`
- `by_severity: {sev: int}` — checked when present.
- `by_finding_type: {ft: int}` — checked when present.

Registered via `pyproject.toml`'s `[project.entry-points."nexus_eval_runners"]`
so `eval-framework run --runner identity` resolves it.
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

from identity import agent as agent_mod
from identity.schemas import FindingsReport
from identity.tools.aws_access_analyzer import AccessAnalyzerFinding
from identity.tools.aws_iam import IamGroup, IamRole, IamUser, IdentityListing


class IdentityEvalRunner:
    """Reference `EvalRunner` for the Identity Agent."""

    @property
    def agent_name(self) -> str:
        return "identity"

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

    listing = _parse_listing(fixture.get("iam_listing", {}))
    aa_findings = tuple(
        _parse_aa_finding(raw) for raw in fixture.get("access_analyzer_findings", []) or []
    )
    users_with_mfa = frozenset(fixture.get("users_with_mfa", []) or [])
    analyzer_arn = fixture.get("analyzer_arn") or None
    dormant_threshold_days = int(fixture.get("dormant_threshold_days", 90))

    async def fake_list(**_: Any) -> IdentityListing:
        return listing

    async def fake_aa(**_: Any) -> tuple[AccessAnalyzerFinding, ...]:
        return aa_findings

    with ExitStack() as stack:
        stack.enter_context(patch.object(agent_mod, "aws_iam_list_identities", fake_list))
        stack.enter_context(patch.object(agent_mod, "aws_access_analyzer_findings", fake_aa))
        return await agent_mod.run(
            contract=contract,
            llm_provider=llm_provider,
            analyzer_arn=analyzer_arn,
            users_with_mfa=users_with_mfa,
            dormant_threshold_days=dormant_threshold_days,
        )


def _build_contract(case: EvalCase, workspace_root: Path) -> ExecutionContract:
    return ExecutionContract(
        schema_version="0.1",
        delegation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
        source_agent="supervisor",
        target_agent="identity",
        customer_id="cust_eval",
        task=case.description or case.case_id,
        required_outputs=["findings.json", "summary.md"],
        budget=BudgetSpec(
            llm_calls=1,
            tokens=1,
            wall_clock_sec=60.0,
            cloud_api_calls=200,  # IAM listing + Access Analyzer registry costs (~30) + headroom
            mb_written=10,
        ),
        permitted_tools=[
            "aws_iam_list_identities",
            "aws_iam_simulate_principal_policy",
            "aws_access_analyzer_findings",
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


_FALLBACK_DATE = datetime(2026, 1, 1, tzinfo=UTC)


def _parse_dt(value: Any) -> datetime | None:
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value
    if isinstance(value, str):
        # tolerate trailing Z (Python 3.11+ accepts it; be defensive).
        normalized = value.replace("Z", "+00:00")
        return datetime.fromisoformat(normalized)
    raise ValueError(f"unparseable datetime: {value!r}")


def _parse_listing(raw: dict[str, Any]) -> IdentityListing:
    users = tuple(_parse_user(u) for u in raw.get("users", []) or [])
    roles = tuple(_parse_role(r) for r in raw.get("roles", []) or [])
    groups = tuple(_parse_group(g) for g in raw.get("groups", []) or [])
    return IdentityListing(users=users, roles=roles, groups=groups)


def _parse_user(raw: dict[str, Any]) -> IamUser:
    return IamUser(
        arn=str(raw["arn"]),
        name=str(raw["name"]),
        user_id=str(raw.get("user_id", f"AIDA-{raw['name'].upper()}")),
        create_date=_parse_dt(raw.get("create_date")) or _FALLBACK_DATE,
        last_used_at=_parse_dt(raw.get("last_used_at")),
        attached_policy_arns=tuple(raw.get("attached_policy_arns", []) or []),
        inline_policy_names=tuple(raw.get("inline_policy_names", []) or []),
        group_memberships=tuple(raw.get("group_memberships", []) or []),
    )


def _parse_role(raw: dict[str, Any]) -> IamRole:
    return IamRole(
        arn=str(raw["arn"]),
        name=str(raw["name"]),
        role_id=str(raw.get("role_id", f"AROA-{raw['name'].upper()}")),
        create_date=_parse_dt(raw.get("create_date")) or _FALLBACK_DATE,
        last_used_at=_parse_dt(raw.get("last_used_at")),
        assume_role_policy_document=dict(raw.get("assume_role_policy_document", {}) or {}),
        attached_policy_arns=tuple(raw.get("attached_policy_arns", []) or []),
        inline_policy_names=tuple(raw.get("inline_policy_names", []) or []),
    )


def _parse_group(raw: dict[str, Any]) -> IamGroup:
    return IamGroup(
        arn=str(raw["arn"]),
        name=str(raw["name"]),
        group_id=str(raw.get("group_id", f"AGPA-{raw['name'].upper()}")),
        create_date=_parse_dt(raw.get("create_date")) or _FALLBACK_DATE,
        member_user_names=tuple(raw.get("member_user_names", []) or []),
        attached_policy_arns=tuple(raw.get("attached_policy_arns", []) or []),
        inline_policy_names=tuple(raw.get("inline_policy_names", []) or []),
    )


def _parse_aa_finding(raw: dict[str, Any]) -> AccessAnalyzerFinding:
    return AccessAnalyzerFinding(
        id=str(raw["id"]),
        resource_arn=str(raw.get("resource_arn", "")),
        resource_type=str(raw.get("resource_type", "")),
        external_principals=tuple(raw.get("external_principals", []) or []),
        actions=tuple(raw.get("actions", []) or []),
        is_public=bool(raw.get("is_public", False)),
        status=str(raw.get("status", "ACTIVE")),
        finding_type=str(raw.get("finding_type", "ExternalAccess")),
        created_at=_parse_dt(raw.get("created_at")) or _FALLBACK_DATE,
        updated_at=_parse_dt(raw.get("updated_at")) or _FALLBACK_DATE,
    )


__all__ = ["IdentityEvalRunner"]
