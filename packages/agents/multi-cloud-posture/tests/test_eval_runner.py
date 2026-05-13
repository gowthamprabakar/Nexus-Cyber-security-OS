"""Tests for `multi_cloud_posture.eval_runner.MultiCloudPostureEvalRunner`.

Two surfaces tested:

1. Protocol satisfaction + happy / mismatch shape on synthetic cases.
2. The **10/10 acceptance gate** against the YAMLs in `eval/cases/`.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from eval_framework.cases import EvalCase
from eval_framework.runner import EvalRunner
from multi_cloud_posture.eval_runner import MultiCloudPostureEvalRunner

CASES_DIR = Path(__file__).resolve().parents[1] / "eval" / "cases"


def _load_case(path: Path) -> EvalCase:
    raw = yaml.safe_load(path.read_text())
    return EvalCase.model_validate(raw)


# ---------------------------- protocol satisfaction ----------------------


def test_runner_satisfies_protocol() -> None:
    runner = MultiCloudPostureEvalRunner()
    assert isinstance(runner, EvalRunner)
    assert runner.agent_name == "multi_cloud_posture"


# ---------------------------- happy / mismatch synthetic cases -----------


@pytest.mark.asyncio
async def test_run_empty_case_yields_pass(tmp_path: Path) -> None:
    case = EvalCase(
        case_id="synthetic_empty",
        description="all feeds empty",
        fixture={"defender": [], "activity": [], "scc": [], "iam": []},
        expected={"finding_count": 0},
    )
    passed, reason, actuals, audit = await MultiCloudPostureEvalRunner().run(
        case, workspace=tmp_path
    )
    assert passed is True
    assert reason is None
    assert actuals["finding_count"] == 0
    assert audit is not None and audit.is_file()


@pytest.mark.asyncio
async def test_run_finding_count_mismatch_returns_failure_reason(tmp_path: Path) -> None:
    case = EvalCase(
        case_id="synthetic_count_mismatch",
        description="empty but expects one finding",
        fixture={"defender": [], "activity": [], "scc": [], "iam": []},
        expected={"finding_count": 1},
    )
    passed, reason, _, _ = await MultiCloudPostureEvalRunner().run(case, workspace=tmp_path)
    assert passed is False
    assert reason is not None
    assert "finding_count" in reason


@pytest.mark.asyncio
async def test_run_severity_mismatch_returns_failure_reason(tmp_path: Path) -> None:
    case = EvalCase(
        case_id="synthetic_sev_mismatch",
        description="Defender HIGH but bogus expected severity count",
        fixture={
            "defender": [
                {
                    "kind": "assessment",
                    "record_id": "/subscriptions/x/providers/Microsoft.Security/assessments/x",
                    "display_name": "Test",
                    "severity": "High",
                    "status": "Unhealthy",
                    "resource_id": "/subscriptions/x/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/sa1",
                    "subscription_id": "x",
                    "detected_at": "2026-05-13T12:00:00Z",
                }
            ],
            "activity": [],
            "scc": [],
            "iam": [],
        },
        expected={"by_severity": {"high": 99}},
    )
    passed, reason, _, _ = await MultiCloudPostureEvalRunner().run(case, workspace=tmp_path)
    assert passed is False
    assert reason is not None
    assert "high" in reason


@pytest.mark.asyncio
async def test_customer_domain_allowlist_passthrough(tmp_path: Path) -> None:
    """Fixture key `customer_domain_allowlist` forwards through to the GCP IAM reader path
    (we don't assert on the reader behaviour — the IAM fixture pre-grades severity — but
    the runner must not crash when the key is present).
    """
    case = EvalCase(
        case_id="synthetic_allowlist",
        description="iam with allowlist key set",
        fixture={
            "defender": [],
            "activity": [],
            "scc": [],
            "iam": [
                {
                    "asset_name": "//cloudresourcemanager.googleapis.com/projects/p",
                    "asset_type": "cloudresourcemanager.googleapis.com/Project",
                    "project_id": "p",
                    "role": "roles/owner",
                    "member": "user:a@example.com",
                    "severity": "HIGH",
                    "reason": "x",
                    "detected_at": "2026-05-13T12:00:00Z",
                }
            ],
            "customer_domain_allowlist": ["example.com"],
        },
        expected={"finding_count": 1},
    )
    passed, _, _, _ = await MultiCloudPostureEvalRunner().run(case, workspace=tmp_path)
    assert passed is True


# ---------------------------- 10/10 acceptance gate ----------------------


def _all_case_paths() -> list[Path]:
    return sorted(CASES_DIR.glob("*.yaml"))


def test_ten_cases_on_disk() -> None:
    paths = _all_case_paths()
    assert len(paths) == 10, f"expected 10 eval cases, found {len(paths)}"


@pytest.mark.parametrize("case_path", _all_case_paths(), ids=lambda p: p.stem)
@pytest.mark.asyncio
async def test_case_passes(case_path: Path, tmp_path: Path) -> None:
    case = _load_case(case_path)
    passed, reason, actuals, _ = await MultiCloudPostureEvalRunner().run(case, workspace=tmp_path)
    assert passed, f"case {case.case_id} failed: {reason}; actuals={actuals}"


# ---------------------------- entry-point discovery ---------------------


def test_eval_runner_entry_point_discoverable() -> None:
    """`eval-framework run --runner multi_cloud_posture` resolves through this entry-point."""
    from importlib.metadata import entry_points

    eps = entry_points(group="nexus_eval_runners")
    matched = [ep for ep in eps if ep.name == "multi_cloud_posture"]
    assert len(matched) == 1, f"expected one multi_cloud_posture entry-point, got {len(matched)}"
    klass = matched[0].load()
    runner = klass()
    assert runner.agent_name == "multi_cloud_posture"
