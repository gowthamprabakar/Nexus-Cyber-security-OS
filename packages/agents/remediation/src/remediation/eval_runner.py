"""`RemediationEvalRunner` — canonical `EvalRunner` for A.1.

Mirrors D.6's
[`eval_runner.py`](../../../k8s-posture/src/k8s_posture/eval_runner.py) shape —
parses the YAML fixture, monkey-patches the agent's three side-effect surfaces
(filesystem ingest, kubectl executor, validator's D.6 detector closure), builds
an `ExecutionContract` rooted at the suite-supplied workspace, calls
`remediation.agent.run`, then compares the resulting `RemediationReport` to
`case.expected`.

**Fixture keys** (under `fixture`):

- `mode: str` — `recommend` (default) / `dry_run` / `execute`.
- `authorization: dict` — fields of `Authorization` (mode flags, allowlist,
  blast cap, rollback window). Missing keys fall back to the model defaults.
- `findings: list[dict]` — D.6 `ManifestFinding` records (the input shape A.1
  ingests).
- `dry_run_result: dict` — scripted `kubectl --dry-run=server` result
  (`exit_code` required; `stdout`, `stderr` optional). Used in `dry_run` and
  `execute` modes. Omit for "always succeeds" default.
- `execute_result: dict` — scripted `kubectl patch` result (execute mode only).
- `rollback_result: dict` — scripted inverse-patch result (execute mode only).
- `post_validate_findings: list[dict]` — what the validator's detector returns
  AFTER the rollback window. Empty (or omitted) = patch worked.
- `kubeconfig: str` / `in_cluster: bool` — passed through to `run()`.

**Comparison shape** (under `expected`):

- `finding_count: int` — `report.total`.
- `by_outcome: {outcome_name: int}` — `report.count_by_outcome()`. Checked only
  for the keys you name; other outcomes default to 0.
- `action_types_distinct: int` — number of unique `action_type` values across
  emitted findings. Useful for the mixed-action-class case.
- `raises: str` — exception class name (e.g. `"AuthorizationError"`). Inverts
  the success check: pass iff the call raises an exception of that type.

Registered via `pyproject.toml`'s `[project.entry-points."nexus_eval_runners"]`
so `eval-framework run --runner remediation` resolves it.
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
from k8s_posture.schemas import Severity
from k8s_posture.tools.manifests import ManifestFinding

from remediation import agent as agent_mod
from remediation import validator as validator_mod
from remediation.authz import Authorization, AuthorizationError
from remediation.schemas import (
    RemediationActionType,
    RemediationMode,
    RemediationReport,
)
from remediation.tools import kubectl_executor as kc_mod
from remediation.tools.kubectl_executor import PatchResult


class RemediationEvalRunner:
    """Reference `EvalRunner` for the Remediation Agent."""

    @property
    def agent_name(self) -> str:
        return "remediation"

    async def run(
        self,
        case: EvalCase,
        *,
        workspace: Path,
        llm_provider: LLMProvider | None = None,
    ) -> RunOutcome:
        workspace.mkdir(parents=True, exist_ok=True)
        contract = _build_contract(case, workspace)

        expected_raises = case.expected.get("raises")
        try:
            report = await _run_case_async(case, contract, llm_provider=llm_provider)
        except AuthorizationError as exc:
            if expected_raises == "AuthorizationError":
                audit_log_path = Path(contract.workspace) / "audit.jsonl"
                return (
                    True,
                    None,
                    {"raised": "AuthorizationError", "message": str(exc)},
                    audit_log_path if audit_log_path.exists() else None,
                )
            return (
                False,
                f"unexpected AuthorizationError: {exc}",
                {"raised": "AuthorizationError", "message": str(exc)},
                None,
            )

        if expected_raises:
            return (
                False,
                f"expected {expected_raises} to be raised; run completed normally",
                _actuals(report),
                Path(contract.workspace) / "audit.jsonl",
            )

        passed, failure_reason = _evaluate(case, report)
        audit_log_path = Path(contract.workspace) / "audit.jsonl"
        return (
            passed,
            failure_reason,
            _actuals(report),
            audit_log_path if audit_log_path.exists() else None,
        )


# ---------------------------- internals ----------------------------------


async def _run_case_async(
    case: EvalCase,
    contract: ExecutionContract,
    *,
    llm_provider: LLMProvider | None,
) -> RemediationReport:
    fixture = case.fixture
    mode = _parse_mode(fixture.get("mode", "recommend"))
    auth = _parse_authorization(fixture.get("authorization") or {})
    findings = tuple(_parse_manifest(r) for r in fixture.get("findings", []) or [])
    dry_run_result = _parse_patch_result(fixture.get("dry_run_result"), default_dry_run=True)
    execute_result = _parse_patch_result(fixture.get("execute_result"), default_dry_run=False)
    rollback_result = _parse_patch_result(fixture.get("rollback_result"), default_dry_run=False)
    post_validate = tuple(
        _parse_manifest(r) for r in fixture.get("post_validate_findings", []) or []
    )

    workspace = Path(contract.workspace)
    workspace.mkdir(parents=True, exist_ok=True)

    findings_path = workspace / "_fixture_findings.json"
    findings_path.write_text("placeholder")

    async def fake_read(*, path: Path | str) -> tuple[ManifestFinding, ...]:
        del path
        return findings

    async def _apply(artifact: Any, *, dry_run: bool, **_: Any) -> PatchResult:
        if dry_run:
            return dry_run_result
        # The validator's rollback() builds an inverse artifact with
        # correlation_id="<orig>-rollback"; key off that to route results.
        if artifact.correlation_id.endswith("-rollback"):
            return rollback_result
        return execute_result

    async def fake_detect() -> tuple[ManifestFinding, ...]:
        return post_validate

    def fake_factory(*, namespace: str, kubeconfig: Path | None, in_cluster: bool) -> Any:
        del namespace, kubeconfig, in_cluster
        return fake_detect

    async def _instant(_seconds: float) -> None:
        return None

    with ExitStack() as stack:
        stack.enter_context(patch.object(agent_mod, "read_findings", fake_read))
        stack.enter_context(patch.object(agent_mod, "apply_patch", _apply))
        stack.enter_context(patch.object(validator_mod, "apply_patch", _apply))
        stack.enter_context(patch.object(kc_mod, "apply_patch", _apply))
        stack.enter_context(patch.object(agent_mod, "build_d6_detector", fake_factory))
        # Bypass the validator's rollback-window wait. `patch.object` on
        # `validator_mod.asyncio` would require `asyncio` to be in
        # `validator.__all__` (mypy-strict), so target the attribute path via
        # string-form `patch()` instead.
        stack.enter_context(patch("remediation.validator.asyncio.sleep", _instant))
        # Stub the binary check so absence of kubectl doesn't fail eval-time.
        stack.enter_context(
            patch.object(kc_mod, "_kubectl_binary", lambda: "/usr/local/bin/kubectl")
        )
        return await agent_mod.run(
            contract=contract,
            llm_provider=llm_provider,
            findings_path=findings_path,
            mode=mode,
            authorization=auth,
        )


def _build_contract(case: EvalCase, workspace_root: Path) -> ExecutionContract:
    now = datetime.now(UTC)
    return ExecutionContract(
        schema_version="0.1",
        delegation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
        source_agent="supervisor",
        target_agent="remediation",
        customer_id="cust_eval",
        task=case.description or case.case_id,
        required_outputs=["findings.json", "report.md"],
        budget=BudgetSpec(
            llm_calls=1,
            tokens=1,
            wall_clock_sec=60.0,
            cloud_api_calls=20,
            mb_written=10,
        ),
        permitted_tools=["read_findings", "apply_patch"],
        completion_condition="findings.json AND report.md exist",
        escalation_rules=[],
        workspace=str(workspace_root / "ws"),
        persistent_root=str(workspace_root / "p"),
        created_at=now,
        expires_at=now + timedelta(hours=1),
    )


def _evaluate(case: EvalCase, report: RemediationReport) -> tuple[bool, str | None]:
    expected = case.expected

    finding_count = expected.get("finding_count")
    if finding_count is not None and report.total != int(finding_count):
        return False, f"finding_count expected {finding_count}, got {report.total}"

    by_outcome = expected.get("by_outcome") or {}
    counts = report.count_by_outcome()
    for outcome_name, want in by_outcome.items():
        actual = counts.get(str(outcome_name), 0)
        if actual != int(want):
            return False, (
                f"by_outcome[{outcome_name!r}] expected {want}, got {actual} "
                f"(full counts: {counts})"
            )

    distinct = expected.get("action_types_distinct")
    if distinct is not None:
        seen = _distinct_action_types(report)
        if len(seen) != int(distinct):
            return False, (
                f"action_types_distinct expected {distinct}, got {len(seen)} ({sorted(seen)})"
            )

    return True, None


def _actuals(report: RemediationReport) -> dict[str, Any]:
    return {
        "finding_count": report.total,
        "by_outcome": report.count_by_outcome(),
        "action_types_distinct": len(_distinct_action_types(report)),
    }


def _distinct_action_types(report: RemediationReport) -> set[str]:
    """Pull `action_type` out of each OCSF 2007 finding (under `finding_info.types[0]`)."""
    seen: set[str] = set()
    for raw in report.findings:
        try:
            types = raw["finding_info"]["types"]
        except (KeyError, TypeError):
            continue
        if isinstance(types, list) and types and isinstance(types[0], str):
            seen.add(types[0])
    return seen


# ---------------------------- fixture -> dataclass parsing ---------------


def _parse_mode(value: Any) -> RemediationMode:
    if isinstance(value, RemediationMode):
        return value
    return RemediationMode(str(value).lower())


def _parse_authorization(raw: dict[str, Any]) -> Authorization:
    return Authorization.model_validate(raw)


def _parse_patch_result(raw: Any, *, default_dry_run: bool) -> PatchResult:
    """Build a PatchResult from a fixture dict.

    Defaults to "succeeded" so the simple-success cases don't need to spell out
    `exit_code: 0` repeatedly. Pre/post hashes are stubbed deterministically
    for execute results so the audit chain stays uniform.
    """
    raw = raw or {}
    exit_code = int(raw.get("exit_code", 0))
    succeeded = exit_code == 0
    dry_run_flag = bool(raw.get("dry_run", default_dry_run))
    return PatchResult(
        exit_code=exit_code,
        stdout=str(raw.get("stdout", "deployment.apps/test patched" if succeeded else "")),
        stderr=str(raw.get("stderr", "" if succeeded else "kubectl: error")),
        dry_run=dry_run_flag,
        pre_patch_hash=("a" * 64) if (succeeded and not dry_run_flag) else None,
        post_patch_hash=("b" * 64) if (succeeded and not dry_run_flag) else None,
        pre_patch_resource={"kind": "Deployment"} if (succeeded and not dry_run_flag) else None,
        post_patch_resource=(
            {"kind": "Deployment", "patched": True} if (succeeded and not dry_run_flag) else None
        ),
    )


def _parse_manifest(raw: dict[str, Any]) -> ManifestFinding:
    return ManifestFinding(
        rule_id=str(raw.get("rule_id", "")),
        rule_title=str(raw.get("rule_title", "")),
        severity=_parse_severity(raw.get("severity", "high")),
        workload_kind=str(raw.get("workload_kind", "")),
        workload_name=str(raw.get("workload_name", "")),
        namespace=str(raw.get("namespace", "default")),
        container_name=str(raw.get("container_name", "")),
        manifest_path=str(raw.get("manifest_path", "")),
        detected_at=_parse_dt(raw.get("detected_at")) or datetime.now(UTC),
        unmapped=dict(raw.get("unmapped", {}) or {}),
    )


def _parse_severity(value: Any) -> Severity:
    if isinstance(value, Severity):
        return value
    return Severity(str(value).lower())


def _parse_dt(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    if isinstance(value, str) and value:
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    return None


# Reserved for the v0.2+ expanded action-class set; the test suite asserts
# the registry is still in sync.
_KNOWN_ACTION_TYPES: set[str] = {t.value for t in RemediationActionType}


__all__ = ["RemediationEvalRunner"]
