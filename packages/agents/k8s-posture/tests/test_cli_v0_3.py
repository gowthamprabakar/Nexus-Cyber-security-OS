"""CLI tests for D.6 v0.3 — `--in-cluster` flag + 3-way mutual exclusion."""

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
        task="K8s posture (in-cluster)",
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


def test_help_lists_in_cluster_flag() -> None:
    result = CliRunner().invoke(main, ["run", "--help"])
    assert result.exit_code == 0
    assert "--in-cluster" in result.output


# ---------------------------- happy path: --in-cluster only --------------


def test_run_with_only_in_cluster_succeeds(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_cluster_reader(monkeypatch, records=[_manifest_finding()])
    contract = _contract_yaml(tmp_path)

    result = CliRunner().invoke(
        main,
        ["run", "--contract", str(contract), "--in-cluster"],
    )
    assert result.exit_code == 0, result.output
    assert "findings: 1" in result.output
    # No warning since a feed (in_cluster) was supplied.
    assert "warning" not in result.output


def test_run_in_cluster_forwards_to_reader(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The CLI flag must reach `read_cluster_workloads(in_cluster=True)`."""
    captured: dict[str, Any] = {}
    _patch_cluster_reader(monkeypatch, capture=captured)
    contract = _contract_yaml(tmp_path)

    result = CliRunner().invoke(
        main,
        ["run", "--contract", str(contract), "--in-cluster"],
    )
    assert result.exit_code == 0, result.output
    assert captured.get("in_cluster") is True


def test_run_in_cluster_with_namespace_forwarded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """--cluster-namespace is allowed alongside --in-cluster (not just --kubeconfig)."""
    captured: dict[str, Any] = {}
    _patch_cluster_reader(monkeypatch, capture=captured)
    contract = _contract_yaml(tmp_path)

    result = CliRunner().invoke(
        main,
        [
            "run",
            "--contract",
            str(contract),
            "--in-cluster",
            "--cluster-namespace",
            "production",
        ],
    )
    assert result.exit_code == 0, result.output
    assert captured.get("in_cluster") is True
    assert captured.get("namespace") == "production"


# ---------------------------- 3-way mutual exclusion ---------------------


def test_in_cluster_and_kubeconfig_together_exit_nonzero(tmp_path: Path) -> None:
    contract = _contract_yaml(tmp_path)
    kubeconfig = tmp_path / "kc.yaml"
    kubeconfig.write_text("k: v\n")

    result = CliRunner().invoke(
        main,
        ["run", "--contract", str(contract), "--in-cluster", "--kubeconfig", str(kubeconfig)],
    )
    assert result.exit_code != 0
    assert "mutually exclusive" in result.output


def test_in_cluster_and_manifest_dir_together_exit_nonzero(tmp_path: Path) -> None:
    contract = _contract_yaml(tmp_path)
    manifest_dir = tmp_path / "manifests"
    manifest_dir.mkdir()

    result = CliRunner().invoke(
        main,
        ["run", "--contract", str(contract), "--in-cluster", "--manifest-dir", str(manifest_dir)],
    )
    assert result.exit_code != 0
    assert "mutually exclusive" in result.output


def test_all_three_workload_sources_together_exit_nonzero(tmp_path: Path) -> None:
    """Defensive: even all three at once raises a clear UsageError."""
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
            "--in-cluster",
            "--kubeconfig",
            str(kubeconfig),
            "--manifest-dir",
            str(manifest_dir),
        ],
    )
    assert result.exit_code != 0
    assert "mutually exclusive" in result.output


# ---------------------------- --cluster-namespace now permits --in-cluster


def test_cluster_namespace_with_in_cluster_does_not_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """v0.2 required `--cluster-namespace` to come with `--kubeconfig`; v0.3 widens that
    to ALSO allow `--in-cluster` (since both are live-ingest sources)."""
    _patch_cluster_reader(monkeypatch)
    contract = _contract_yaml(tmp_path)

    result = CliRunner().invoke(
        main,
        [
            "run",
            "--contract",
            str(contract),
            "--in-cluster",
            "--cluster-namespace",
            "default",
        ],
    )
    assert result.exit_code == 0, result.output


def test_cluster_namespace_without_kubeconfig_or_in_cluster_exits_nonzero(
    tmp_path: Path,
) -> None:
    """Bare `--cluster-namespace` without either live source is still an error."""
    contract = _contract_yaml(tmp_path)
    result = CliRunner().invoke(
        main,
        ["run", "--contract", str(contract), "--cluster-namespace", "production"],
    )
    assert result.exit_code != 0
    assert "requires --kubeconfig or --in-cluster" in result.output


# ---------------------------- v0.1 + v0.2 paths unchanged ----------------


def test_v0_2_kubeconfig_alone_still_works(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Defensive: ensure the v0.2 invocation pattern continues to work."""
    captured: dict[str, Any] = {}
    _patch_cluster_reader(monkeypatch, records=[_manifest_finding()], capture=captured)
    contract = _contract_yaml(tmp_path)
    kubeconfig = tmp_path / "kc.yaml"
    kubeconfig.write_text("k: v\n")

    result = CliRunner().invoke(
        main,
        ["run", "--contract", str(contract), "--kubeconfig", str(kubeconfig)],
    )
    assert result.exit_code == 0, result.output
    assert captured.get("kubeconfig") == kubeconfig
    assert captured.get("in_cluster") is not True
