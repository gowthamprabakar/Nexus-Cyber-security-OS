"""`K8sPostureEvalRunner` — the canonical `EvalRunner` for D.6.

Mirrors D.5's
[`eval_runner.py`](../../../multi-cloud-posture/src/multi_cloud_posture/eval_runner.py)
shape — patches the three reader tools at the agent module's import
scope, builds an `ExecutionContract` rooted at the suite-supplied
workspace, calls `k8s_posture.agent.run`, then compares the resulting
`FindingsReport` to `case.expected`.

**Fixture keys** (under `fixture`):

- `kube_bench: list[dict]` — each item shaped per `KubeBenchFinding`.
- `polaris: list[dict]` — each item shaped per `PolarisFinding`.
- `manifest: list[dict]` — each item shaped per `ManifestFinding`.

**Comparison shape** (under `expected`):

- `finding_count: int`
- `by_severity: {sev: int}` — checked when present.

Registered via `pyproject.toml`'s
`[project.entry-points."nexus_eval_runners"]` so
`eval-framework run --runner k8s_posture` resolves it.
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

from k8s_posture import agent as agent_mod
from k8s_posture.schemas import FindingsReport, Severity
from k8s_posture.tools.kube_bench import KubeBenchFinding
from k8s_posture.tools.manifests import ManifestFinding
from k8s_posture.tools.polaris import PolarisFinding


class K8sPostureEvalRunner:
    """Reference `EvalRunner` for the Kubernetes Posture Agent."""

    @property
    def agent_name(self) -> str:
        return "k8s_posture"

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

    kube_bench = tuple(_parse_kube_bench(r) for r in fixture.get("kube_bench", []) or [])
    polaris = tuple(_parse_polaris(r) for r in fixture.get("polaris", []) or [])
    manifest = tuple(_parse_manifest(r) for r in fixture.get("manifest", []) or [])

    async def fake_kb(**_: Any) -> tuple[KubeBenchFinding, ...]:
        return kube_bench

    async def fake_polaris(**_: Any) -> tuple[PolarisFinding, ...]:
        return polaris

    async def fake_manifests(**_: Any) -> tuple[ManifestFinding, ...]:
        return manifest

    workspace = Path(contract.workspace)
    workspace.mkdir(parents=True, exist_ok=True)

    # The agent driver skips the call_tool dispatch if the feed path is None.
    # Synthesize sentinel paths when the fixture has records for that feed.
    kb_feed: Path | None = None
    polaris_feed: Path | None = None
    manifest_dir: Path | None = None
    if kube_bench:
        kb_feed = workspace / "_fixture_kube_bench.json"
        kb_feed.write_text("placeholder")
    if polaris:
        polaris_feed = workspace / "_fixture_polaris.json"
        polaris_feed.write_text("placeholder")
    if manifest:
        manifest_dir = workspace / "_fixture_manifests"
        manifest_dir.mkdir(exist_ok=True)

    with ExitStack() as stack:
        stack.enter_context(patch.object(agent_mod, "read_kube_bench", fake_kb))
        stack.enter_context(patch.object(agent_mod, "read_polaris", fake_polaris))
        stack.enter_context(patch.object(agent_mod, "read_manifests", fake_manifests))
        return await agent_mod.run(
            contract=contract,
            llm_provider=llm_provider,
            kube_bench_feed=kb_feed,
            polaris_feed=polaris_feed,
            manifest_dir=manifest_dir,
        )


def _build_contract(case: EvalCase, workspace_root: Path) -> ExecutionContract:
    return ExecutionContract(
        schema_version="0.1",
        delegation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
        source_agent="supervisor",
        target_agent="k8s_posture",
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
        permitted_tools=["read_kube_bench", "read_polaris", "read_manifests"],
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


def _parse_kube_bench(raw: dict[str, Any]) -> KubeBenchFinding:
    return KubeBenchFinding(
        control_id=str(raw.get("control_id", "")),
        control_text=str(raw.get("control_text", "")),
        section_id=str(raw.get("section_id", "")),
        section_desc=str(raw.get("section_desc", "")),
        node_type=str(raw.get("node_type", "")),
        status=str(raw.get("status", "FAIL")),
        severity_marker=str(raw.get("severity_marker", "")),
        audit=str(raw.get("audit", "")),
        actual_value=str(raw.get("actual_value", "")),
        remediation=str(raw.get("remediation", "")),
        scored=bool(raw.get("scored", True)),
        detected_at=_parse_dt(raw.get("detected_at")) or datetime.now(UTC),
        unmapped=dict(raw.get("unmapped", {}) or {}),
    )


def _parse_polaris(raw: dict[str, Any]) -> PolarisFinding:
    return PolarisFinding(
        check_id=str(raw.get("check_id", "")),
        message=str(raw.get("message", "")),
        severity=str(raw.get("severity", "danger")),
        category=str(raw.get("category", "")),
        workload_kind=str(raw.get("workload_kind", "")),
        workload_name=str(raw.get("workload_name", "")),
        namespace=str(raw.get("namespace", "default")),
        container_name=str(raw.get("container_name", "")),
        check_level=str(raw.get("check_level", "workload")),
        detected_at=_parse_dt(raw.get("detected_at")) or datetime.now(UTC),
        unmapped=dict(raw.get("unmapped", {}) or {}),
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


__all__ = ["K8sPostureEvalRunner"]
