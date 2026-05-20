"""``DataSecurityEvalRunner`` — the canonical ``EvalRunner`` for D.5.

Mirrors multi-cloud-posture's
[`eval_runner.py`](../../../multi-cloud-posture/src/multi_cloud_posture/eval_runner.py)
shape — patches the three reader tools at the agent module's import
scope, builds an ``ExecutionContract`` rooted at the suite-supplied
workspace, calls ``data_security.agent.run``, then compares the
resulting ``FindingsReport`` against ``case.expected``.

**Fixture keys** (under ``fixture``):

- ``buckets: list[dict]`` — each item shaped per ``BucketInventory``.
- ``objects: list[dict]`` — each item with ``bucket`` / ``key`` /
  ``content_sample_b64`` (base64-encoded sample bytes, ≤ 16 KiB).
- ``cloud_posture_findings: list[dict]`` — optional. When present,
  simulates an F.3 sibling workspace containing these findings.
- ``trusted_sensitivity_tag: str`` — optional override for the
  ``Sensitivity`` tag value driving the sensitive-location detector.

**Comparison shape** (under ``expected``):

- ``finding_count: int``.
- ``by_severity: {sev: int}`` — checked when present.
- ``no_pii_strings: list[str]`` — **Q6 acceptance probe**. Each string
  in this list MUST NOT appear in ``findings.json`` or ``report.md``.
  This is the system-level Q6 guard; trips ⇒ case fails.

Registered via ``pyproject.toml``'s
``[project.entry-points."nexus_eval_runners"]`` so
``eval-framework run --runner data_security`` resolves it.
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

from data_security import agent as agent_mod
from data_security.schemas import FindingsReport
from data_security.tools.s3_inventory import BucketInventory
from data_security.tools.s3_objects import ObjectSample


class DataSecurityEvalRunner:
    """Reference ``EvalRunner`` for the Data Security Agent."""

    @property
    def agent_name(self) -> str:
        return "data_security"

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

        actuals: dict[str, Any] = {
            "finding_count": report.total,
            "by_severity": report.count_by_severity(),
        }
        passed, failure_reason = _evaluate(case, report, Path(contract.workspace))
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

    buckets = tuple(_parse_bucket(b) for b in fixture.get("buckets", []) or [])
    samples = tuple(_parse_sample(o) for o in fixture.get("objects", []) or [])
    f3_findings = tuple(
        dict(f) for f in fixture.get("cloud_posture_findings", []) or [] if isinstance(f, dict)
    )

    async def fake_inventory(**_: Any) -> tuple[BucketInventory, ...]:
        return buckets

    async def fake_objects(**_: Any) -> tuple[ObjectSample, ...]:
        return samples

    async def fake_f3(**_: Any) -> tuple[dict[str, Any], ...]:
        return f3_findings

    workspace = Path(contract.workspace)
    workspace.mkdir(parents=True, exist_ok=True)

    # Synthesize sentinel files — the agent driver skips call_tool
    # dispatch when the feed/workspace path is None.
    inventory_feed: Path | None = None
    objects_feed: Path | None = None
    f3_workspace: Path | None = None
    if buckets:
        inventory_feed = workspace / "_fixture_inventory.json"
        inventory_feed.write_text("placeholder", encoding="utf-8")
    if samples:
        objects_feed = workspace / "_fixture_objects.json"
        objects_feed.write_text("placeholder", encoding="utf-8")
    if f3_findings:
        f3_workspace = workspace / "_f3_workspace"
        f3_workspace.mkdir(exist_ok=True)

    trusted_tag = str(fixture.get("trusted_sensitivity_tag", "Restricted"))

    with ExitStack() as stack:
        stack.enter_context(patch.object(agent_mod, "read_s3_inventory", fake_inventory))
        stack.enter_context(patch.object(agent_mod, "read_s3_objects", fake_objects))
        stack.enter_context(patch.object(agent_mod, "read_f3_findings", fake_f3))
        return await agent_mod.run(
            contract=contract,
            llm_provider=llm_provider,
            s3_inventory_feed=inventory_feed,
            s3_objects_feed=objects_feed,
            cloud_posture_workspace=f3_workspace,
            trusted_sensitivity_tag=trusted_tag,
        )


def _build_contract(case: EvalCase, workspace_root: Path) -> ExecutionContract:
    return ExecutionContract(
        schema_version="0.1",
        delegation_id="01J0000000000000000000DSEC",
        source_agent="supervisor",
        target_agent="data_security",
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
            "read_s3_inventory",
            "read_s3_objects",
            "read_f3_findings",
        ],
        completion_condition="findings.json exists",
        escalation_rules=[],
        workspace=str(workspace_root / "ws"),
        persistent_root=str(workspace_root / "p"),
        created_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(hours=1),
    )


def _evaluate(
    case: EvalCase,
    report: FindingsReport,
    workspace: Path,
) -> tuple[bool, str | None]:
    sev_counts = report.count_by_severity()

    expected_count = case.expected.get("finding_count")
    if expected_count is not None and report.total != int(expected_count):
        return False, f"finding_count expected {expected_count}, got {report.total}"

    expected_sev = case.expected.get("by_severity") or {}
    for sev, want in expected_sev.items():
        actual = sev_counts.get(str(sev), 0)
        if actual != int(want):
            return False, f"severity {sev!r} expected {want}, got {actual}"

    # Q6 ACCEPTANCE PROBE — load-bearing.
    no_pii_strings = case.expected.get("no_pii_strings") or []
    if no_pii_strings:
        violation = _check_no_pii_strings(workspace, no_pii_strings)
        if violation is not None:
            return False, violation

    return True, None


def _check_no_pii_strings(workspace: Path, forbidden: list[str]) -> str | None:
    """Q6 system-level acceptance probe.

    Reads the rendered ``findings.json`` and ``report.md`` from the workspace
    and verifies NONE of the ``forbidden`` strings appear. Returns a
    failure reason if a violation is found, ``None`` otherwise.
    """
    findings_path = workspace / "findings.json"
    report_path = workspace / "report.md"
    findings_text = findings_path.read_text(encoding="utf-8") if findings_path.exists() else ""
    report_text = report_path.read_text(encoding="utf-8") if report_path.exists() else ""
    for needle in forbidden:
        if needle in findings_text:
            return f"Q6 violation: forbidden string {needle!r} found in findings.json"
        if needle in report_text:
            return f"Q6 violation: forbidden string {needle!r} found in report.md"
    return None


# ---------------------------- fixture -> dataclass parsing ---------------


def _parse_bucket(raw: dict[str, Any]) -> BucketInventory:
    # Direct pydantic validation — eval cases author the inventory shape
    # exactly. Test fixtures are trusted (operator-authored).
    return BucketInventory.model_validate(raw)


def _parse_sample(raw: dict[str, Any]) -> ObjectSample:
    # Same as above — fixture-authored.
    sample_raw = dict(raw)
    if "content_sample_b64" in sample_raw and "content_sample" not in sample_raw:
        sample_raw["content_sample"] = sample_raw.pop("content_sample_b64")
    return ObjectSample.model_validate(sample_raw)


__all__ = ["DataSecurityEvalRunner"]
