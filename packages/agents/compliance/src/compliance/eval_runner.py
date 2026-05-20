"""`ComplianceEvalRunner` — the canonical `EvalRunner` for D.6.

Mirrors D.8's
[`eval_runner.py`](../../../threat-intel/src/threat_intel/eval_runner.py)
shape — patches the bundled CIS YAML reader (when the case needs a
tighter fixture), synthesises any required F.3 / D.5 sibling-
workspace ``findings.json`` files from the case fixture, builds an
``ExecutionContract`` rooted at the suite-supplied workspace, calls
``compliance.agent.run``, then compares the resulting
``FindingsReport`` to ``case.expected``.

Fixture keys (under ``fixture``):

Sibling-workspace synthesiser directives (the runner writes
``findings.json`` files into ephemeral sub-paths so the correlators
exercise their real read path):

  - ``f3_findings_with_rules: list[dict]`` -- one F.3 finding per
    entry (rule_id, finding_id, resource_arn).
  - ``d5_findings_with_rules: list[dict]`` -- one D.5 finding per
    entry (rule_id, finding_id, bucket).
  - ``malformed_f3_findings_json: bool`` -- if true, the F.3
    workspace's findings.json is intentionally malformed so the
    correlator's forgiving-read posture is exercised.
  - ``custom_controls: list[dict]`` -- if present, replaces the
    bundled CIS library with the supplied control records (one
    dict per control; same shape as the bundled YAML). Used for
    `severity-canonicalization` + `cis-attribution-in-output`
    edge cases where we need a tight control library to assert
    against.

Comparison shape (under ``expected``):

  - ``finding_count: int``
  - ``by_severity: {sev: int}`` -- checked when present.
  - ``by_control: {control_id: int}`` -- checked when present.
  - ``report_md_contains: list[str]`` -- substrings that must
    appear in the rendered report.md.

Registered via ``pyproject.toml`` ``[project.entry-points.
"nexus_eval_runners"]`` so ``eval-framework run --runner
compliance`` resolves it.
"""

from __future__ import annotations

import json
from contextlib import ExitStack
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from unittest.mock import patch

from charter.contract import BudgetSpec, ExecutionContract
from charter.llm import LLMProvider
from cloud_posture.schemas import AffectedResource as CspmAffectedResource
from cloud_posture.schemas import Severity as CspmSeverity
from cloud_posture.schemas import build_finding as build_cspm_finding
from eval_framework.cases import EvalCase
from eval_framework.runner import RunOutcome
from shared.fabric.envelope import NexusEnvelope

from compliance import agent as agent_mod
from compliance.schemas import ControlLevel, ControlMapping, FindingsReport
from compliance.tools.cis_aws_benchmark import CisControl


class ComplianceEvalRunner:
    """Reference ``EvalRunner`` for the Compliance Agent (D.6)."""

    @property
    def agent_name(self) -> str:
        return "compliance"

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

        passed, failure_reason = _evaluate(case, report, contract)
        actuals: dict[str, Any] = {
            "finding_count": report.total,
            "by_severity": report.count_by_severity(),
            "by_control": _count_by_control(report),
        }
        audit_log_path = Path(contract.workspace) / "audit.jsonl"
        return (
            passed,
            failure_reason,
            actuals,
            audit_log_path if audit_log_path.exists() else None,
        )


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------


async def _run_case_async(
    case: EvalCase,
    contract: ExecutionContract,
    *,
    llm_provider: LLMProvider | None,
) -> FindingsReport:
    fixture = case.fixture
    workspace = Path(contract.workspace)
    workspace.mkdir(parents=True, exist_ok=True)

    f3_ws = _write_f3_workspace(workspace, fixture)
    d5_ws = _write_d5_workspace(workspace, fixture)

    custom_controls = _build_custom_controls(fixture)

    async def maybe_patched_reader(*, path: Path) -> tuple[CisControl, ...]:
        del path
        return custom_controls

    with ExitStack() as stack:
        if custom_controls:
            stack.enter_context(
                patch.object(agent_mod, "read_cis_aws_benchmark", maybe_patched_reader)
            )
        return await agent_mod.run(
            contract=contract,
            llm_provider=llm_provider,
            cloud_posture_workspace=f3_ws,
            data_security_workspace=d5_ws,
        )


def _build_contract(case: EvalCase, workspace_root: Path) -> ExecutionContract:
    return ExecutionContract(
        schema_version="0.1",
        delegation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
        source_agent="supervisor",
        target_agent="compliance",
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
        permitted_tools=["read_cis_aws_benchmark"],
        completion_condition="findings.json exists",
        escalation_rules=[],
        workspace=str(workspace_root / "ws"),
        persistent_root=str(workspace_root / "p"),
        created_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(hours=1),
    )


# ---------------------------------------------------------------------------
# Evaluation helpers
# ---------------------------------------------------------------------------


def _evaluate(
    case: EvalCase, report: FindingsReport, contract: ExecutionContract
) -> tuple[bool, str | None]:
    sev_counts = report.count_by_severity()
    type_counts = _count_by_control(report)

    expected_count = case.expected.get("finding_count")
    if expected_count is not None and report.total != int(expected_count):
        return False, f"finding_count expected {expected_count}, got {report.total}"

    expected_sev = case.expected.get("by_severity") or {}
    for sev, want in expected_sev.items():
        actual = sev_counts.get(str(sev), 0)
        if actual != int(want):
            return False, f"severity '{sev}' expected {want}, got {actual}"

    expected_controls = case.expected.get("by_control") or {}
    for ctrl, want in expected_controls.items():
        actual = type_counts.get(str(ctrl), 0)
        if actual != int(want):
            return False, f"control '{ctrl}' expected {want}, got {actual}"

    md_required = case.expected.get("report_md_contains") or []
    if md_required:
        report_md = (Path(contract.workspace) / "report.md").read_text(encoding="utf-8")
        for substring in md_required:
            if str(substring) not in report_md:
                return False, f"report.md missing required substring: {substring!r}"

    return True, None


def _count_by_control(report: FindingsReport) -> dict[str, int]:
    """Count emitted compliance findings by `compliance.control` value."""
    counts: dict[str, int] = {}
    for raw in report.findings:
        compliance = raw.get("compliance")
        if not isinstance(compliance, dict):
            continue
        control = compliance.get("control")
        if isinstance(control, str):
            counts[control] = counts.get(control, 0) + 1
    return counts


# ---------------------------------------------------------------------------
# Custom-control library
# ---------------------------------------------------------------------------


def _build_custom_controls(fixture: dict[str, Any]) -> tuple[CisControl, ...]:
    """Build a custom control library from fixture YAML (overrides the bundled
    library for the duration of the run). Returns empty tuple to fall through
    to the bundled library."""
    raw_controls = fixture.get("custom_controls") or []
    if not isinstance(raw_controls, list) or not raw_controls:
        return ()
    out: list[CisControl] = []
    for raw in raw_controls:
        if not isinstance(raw, dict):
            continue
        control_id = str(raw.get("control_id", ""))
        if not control_id:
            continue
        level_str = str(raw.get("level", "level_1"))
        try:
            level = ControlLevel(level_str)
        except ValueError:
            level = ControlLevel.LEVEL_1
        required = bool(raw.get("required", True))
        mappings: list[ControlMapping] = []
        for m in raw.get("source_mappings", []) or []:
            if not isinstance(m, dict):
                continue
            sa = m.get("source_agent")
            sr = m.get("source_rule_id")
            if not isinstance(sa, str) or not isinstance(sr, str):
                continue
            mappings.append(
                ControlMapping(
                    source_agent=sa,
                    source_rule_id=sr,
                    control_id=control_id,
                    level=level,
                    required=required,
                )
            )
        out.append(
            CisControl(
                control_id=control_id,
                name=str(raw.get("name", f"CIS {control_id}")),
                level=level,
                required=required,
                applicability=tuple(raw.get("applicability") or []),
                description=str(raw.get("description", "Eval-fixture control.")),
                source_mappings=tuple(mappings),
            )
        )
    return tuple(out)


# ---------------------------------------------------------------------------
# Sibling-workspace synthesisers
# ---------------------------------------------------------------------------


def _eval_envelope(agent_id: str) -> NexusEnvelope:
    return NexusEnvelope(
        correlation_id="00000000-0000-0000-0000-000000000eee",
        tenant_id="cust_eval",
        agent_id=agent_id,
        nlah_version="0.1.0",
        model_pin="deterministic",
        charter_invocation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
    )


def _write_f3_workspace(workspace: Path, fixture: dict[str, Any]) -> Path | None:
    entries = fixture.get("f3_findings_with_rules") or []
    malformed = bool(fixture.get("malformed_f3_findings_json", False))
    if not entries and not malformed:
        return None
    f3_ws = workspace / "_f3"
    f3_ws.mkdir(parents=True, exist_ok=True)
    if malformed:
        (f3_ws / "findings.json").write_text("{not-json", encoding="utf-8")
        return f3_ws

    findings: list[dict[str, Any]] = []
    for idx, entry in enumerate(entries, start=1):
        if not isinstance(entry, dict):
            continue
        rule_id = str(entry.get("rule_id", ""))
        if not rule_id:
            continue
        finding_id = str(entry.get("finding_id", f"{rule_id}-{idx:03d}"))
        resource_arn = str(
            entry.get(
                "resource_arn",
                f"arn:aws:iam::123456789012:user/user-{idx}",
            )
        )
        finding = build_cspm_finding(
            finding_id=finding_id,
            rule_id=rule_id,
            severity=CspmSeverity.HIGH,
            title=f"F.3 fixture for {rule_id}",
            description="eval fixture",
            affected=[
                CspmAffectedResource(
                    cloud="aws",
                    account_id="123456789012",
                    region="us-east-1",
                    resource_type="aws_iam_user",
                    resource_id=resource_arn.rsplit("/", 1)[-1] or "x",
                    arn=resource_arn,
                )
            ],
            detected_at=datetime.now(UTC),
            envelope=_eval_envelope("cloud_posture"),
        )
        findings.append(finding.to_dict())
    (f3_ws / "findings.json").write_text(
        json.dumps(
            {
                "agent": "cloud_posture",
                "agent_version": "0.1.0",
                "customer_id": "cust_eval",
                "run_id": "run_eval_f3",
                "scan_started_at": "2026-05-21T00:00:00+00:00",
                "scan_completed_at": "2026-05-21T00:00:05+00:00",
                "findings": findings,
            }
        ),
        encoding="utf-8",
    )
    return f3_ws


def _write_d5_workspace(workspace: Path, fixture: dict[str, Any]) -> Path | None:
    entries = fixture.get("d5_findings_with_rules") or []
    if not entries:
        return None
    d5_ws = workspace / "_d5"
    d5_ws.mkdir(parents=True, exist_ok=True)

    findings: list[dict[str, Any]] = []
    for idx, entry in enumerate(entries, start=1):
        if not isinstance(entry, dict):
            continue
        rule_id = str(entry.get("rule_id", ""))
        if not rule_id:
            continue
        bucket = str(entry.get("bucket", f"bucket-{idx}"))
        finding_id = str(entry.get("finding_id", f"CSPM-AWS-PUBLIC-{idx:03d}-{bucket}"))
        finding = build_cspm_finding(
            finding_id=finding_id,
            rule_id=rule_id,
            severity=CspmSeverity.HIGH,
            title=f"D.5 fixture for {rule_id}",
            description="eval fixture",
            affected=[
                CspmAffectedResource(
                    cloud="aws",
                    account_id="123456789012",
                    region="us-east-1",
                    resource_type="aws_s3_bucket",
                    resource_id=bucket,
                    arn=f"arn:aws:s3:::{bucket}",
                )
            ],
            detected_at=datetime.now(UTC),
            envelope=_eval_envelope("data_security"),
        )
        findings.append(finding.to_dict())
    (d5_ws / "findings.json").write_text(
        json.dumps(
            {
                "agent": "data_security",
                "agent_version": "0.1.0",
                "customer_id": "cust_eval",
                "run_id": "run_eval_d5",
                "scan_started_at": "2026-05-21T00:00:00+00:00",
                "scan_completed_at": "2026-05-21T00:00:05+00:00",
                "findings": findings,
            }
        ),
        encoding="utf-8",
    )
    return d5_ws


__all__ = ["ComplianceEvalRunner"]
