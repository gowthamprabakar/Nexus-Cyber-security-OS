"""CLI tests for D.6 v0.2 — `--kubeconfig` + `--cluster-namespace` flags + Q6 XOR."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
import yaml
from charter.contract import BudgetSpec, ExecutionContract
from click.testing import CliRunner
from k8s_posture import agent as agent_mod
from k8s_posture.cli import main
from k8s_posture.tools.manifests import ManifestFinding

NOW = datetime(2026, 5, 16, 12, 0, 0, tzinfo=UTC)


def _contract_yaml(tmp_path: Path) -> Path:
    contract = ExecutionContract(
        schema_version="0.1",
        delegation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
        source_agent="supervisor",
        target_agent="k8s_posture",
        customer_id="cust_test",
        task="K8s posture (live)",
        required_outputs=["findings.json", "report.md"],
        budget=BudgetSpec(
            llm_calls=1,
            tokens=1,
            wall_clock_sec=60.0,
            cloud_api_calls=10,
            mb_written=10,
        ),
        permitted_tools=[
            "read_kube_bench",
            "read_polaris",
            "read_manifests",
            "read_cluster_workloads",
        ],
        completion_condition="findings.json exists",
        escalation_rules=[],
        workspace=str(tmp_path / "ws"),
        persistent_root=str(tmp_path / "p"),
        created_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(hours=1),
    )
    path = tmp_path / "contract.yaml"
    path.write_text(yaml.safe_dump(contract.model_dump(mode="json")))
    return path


def _manifest_finding() -> ManifestFinding:
    return ManifestFinding(
        rule_id="run-as-root",
        rule_title="Container running as root",
        severity="high",
        workload_kind="Deployment",
        workload_name="frontend",
        namespace="production",
        container_name="nginx",
        manifest_path="cluster:///production/Deployment/frontend",
        detected_at=NOW,
    )


def _patch_cluster_reader(
    mp: pytest.MonkeyPatch,
    *,
    records: list[ManifestFinding] | None = None,
    capture: dict[str, Any] | None = None,
) -> None:
    async def fake(**kwargs: Any) -> tuple[ManifestFinding, ...]:
        if capture is not None:
            capture.update(kwargs)
        return tuple(records or [])

    mp.setattr(agent_mod, "read_cluster_workloads", fake)


# ---------------------------- --help surfaces ----------------------------


def test_help_lists_new_kubeconfig_flag() -> None:
    result = CliRunner().invoke(main, ["run", "--help"])
    assert result.exit_code == 0
    assert "--kubeconfig" in result.output
    assert "--cluster-namespace" in result.output


# ---------------------------- happy path: kubeconfig only ----------------


def test_run_with_only_kubeconfig_succeeds(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_cluster_reader(monkeypatch, records=[_manifest_finding()])
    contract = _contract_yaml(tmp_path)
    kubeconfig = tmp_path / "kc.yaml"
    kubeconfig.write_text("apiVersion: v1\nkind: Config\nclusters: []\n")

    result = CliRunner().invoke(
        main,
        ["run", "--contract", str(contract), "--kubeconfig", str(kubeconfig)],
    )
    assert result.exit_code == 0, result.output
    assert "findings: 1" in result.output
    assert "agent: k8s_posture" in result.output
    # No "warning" line since a feed was supplied.
    assert "warning" not in result.output


def test_run_with_kubeconfig_and_namespace_forwarded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`--cluster-namespace` reaches the reader (not just the agent driver)."""
    captured: dict[str, Any] = {}
    _patch_cluster_reader(monkeypatch, capture=captured)
    contract = _contract_yaml(tmp_path)
    kubeconfig = tmp_path / "kc.yaml"
    kubeconfig.write_text("k: v\n")

    result = CliRunner().invoke(
        main,
        [
            "run",
            "--contract",
            str(contract),
            "--kubeconfig",
            str(kubeconfig),
            "--cluster-namespace",
            "production",
        ],
    )
    assert result.exit_code == 0, result.output
    assert captured["namespace"] == "production"


# ---------------------------- mutual exclusion (Q6) ----------------------


def test_kubeconfig_and_manifest_dir_together_exit_nonzero(tmp_path: Path) -> None:
    contract = _contract_yaml(tmp_path)
    kubeconfig = tmp_path / "kc.yaml"
    kubeconfig.write_text("k: v\n")
    manifest_dir = tmp_path / "manifests"
    manifest_dir.mkdir()

    result = CliRunner().invoke(
        main,
        [
            "run",
            "--contract",
            str(contract),
            "--kubeconfig",
            str(kubeconfig),
            "--manifest-dir",
            str(manifest_dir),
        ],
    )
    assert result.exit_code != 0
    assert "mutually exclusive" in result.output


def test_cluster_namespace_without_kubeconfig_exits_nonzero(tmp_path: Path) -> None:
    contract = _contract_yaml(tmp_path)
    result = CliRunner().invoke(
        main,
        [
            "run",
            "--contract",
            str(contract),
            "--cluster-namespace",
            "production",
        ],
    )
    assert result.exit_code != 0
    assert "requires --kubeconfig" in result.output


# ---------------------------- no-feed warning still fires with no feeds --


def test_no_feeds_still_warns_in_v0_2(tmp_path: Path) -> None:
    """Even with the kubeconfig flag available, an empty invocation must still warn."""
    contract = _contract_yaml(tmp_path)
    result = CliRunner().invoke(main, ["run", "--contract", str(contract)])
    assert result.exit_code == 0, result.output
    assert "warning" in result.output


# ---------------------------- v0.1 manifest_dir path unchanged ----------


def test_manifest_dir_alone_still_works(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """v0.1 file-reader path remains; we should not have broken it."""
    cluster_called = False

    async def fake_cluster(**_: Any) -> tuple[ManifestFinding, ...]:
        nonlocal cluster_called
        cluster_called = True
        return ()

    async def fake_manifests(**_: Any) -> tuple[ManifestFinding, ...]:
        return (_manifest_finding(),)

    monkeypatch.setattr(agent_mod, "read_cluster_workloads", fake_cluster)
    monkeypatch.setattr(agent_mod, "read_manifests", fake_manifests)

    contract = _contract_yaml(tmp_path)
    manifest_dir = tmp_path / "manifests"
    manifest_dir.mkdir()
    (manifest_dir / "frontend.yaml").write_text("placeholder")

    result = CliRunner().invoke(
        main,
        ["run", "--contract", str(contract), "--manifest-dir", str(manifest_dir)],
    )
    assert result.exit_code == 0, result.output
    assert "findings: 1" in result.output
    assert cluster_called is False
