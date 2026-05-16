"""Agent driver tests for D.6 v0.2 — the `kubeconfig` workload-source branch.

v0.1 driver tests live in `test_agent_unit.py` and remain unchanged. v0.2 adds
a kubeconfig-based path that routes workload ingest through
`read_cluster_workloads` instead of `read_manifests`. Tests mock the cluster
reader at the agent module's import site (same pattern as the v0.1 patches).
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from charter.contract import BudgetSpec, ExecutionContract
from k8s_posture import agent as agent_mod
from k8s_posture.agent import run
from k8s_posture.schemas import Severity
from k8s_posture.tools.manifests import ManifestFinding

NOW = datetime(2026, 5, 16, 12, 0, 0, tzinfo=UTC)


def _contract(tmp_path: Path) -> ExecutionContract:
    return ExecutionContract(
        schema_version="0.1",
        delegation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
        source_agent="supervisor",
        target_agent="k8s_posture",
        customer_id="cust_test",
        task="Kubernetes posture scan (live cluster)",
        required_outputs=["findings.json", "report.md"],
        budget=BudgetSpec(
            llm_calls=5,
            tokens=10_000,
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
        completion_condition="findings.json AND report.md exist",
        escalation_rules=[],
        workspace=str(tmp_path / "ws"),
        persistent_root=str(tmp_path / "p"),
        created_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )


def _manifest_finding(
    *,
    rule_id: str = "run-as-root",
    severity: Severity = Severity.HIGH,
    workload_name: str = "frontend",
    namespace: str = "production",
    container_name: str = "nginx",
    manifest_path: str = "cluster:///production/Deployment/frontend",
) -> ManifestFinding:
    return ManifestFinding(
        rule_id=rule_id,
        rule_title="Container running as root",
        severity=severity,
        workload_kind="Deployment",
        workload_name=workload_name,
        namespace=namespace,
        container_name=container_name,
        manifest_path=manifest_path,
        detected_at=NOW,
    )


def _patch_cluster_reader(
    mp: pytest.MonkeyPatch,
    records: list[ManifestFinding],
    *,
    capture: dict[str, Any] | None = None,
) -> None:
    """Patch `read_cluster_workloads` at the agent module's import site.

    When `capture` is provided, the fake reader writes its kwargs into it so
    tests can assert which kubeconfig / namespace was passed.
    """

    async def fake(**kwargs: Any) -> tuple[ManifestFinding, ...]:
        if capture is not None:
            capture.update(kwargs)
        return tuple(records)

    mp.setattr(agent_mod, "read_cluster_workloads", fake)


# ---------------------------- registry ------------------------------------


def test_registry_now_includes_cluster_workloads() -> None:
    """The v0.2 reader must be registered alongside the v0.1 readers."""
    reg = agent_mod.build_registry()
    assert "read_cluster_workloads" in reg.known_tools()


# ---------------------------- happy path ----------------------------------


@pytest.mark.asyncio
async def test_kubeconfig_only_emits_manifest_finding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A kubeconfig-driven run produces the same OCSF source-type as a manifest-dir
    run (both go through `normalize_manifest`)."""
    _patch_cluster_reader(monkeypatch, [_manifest_finding()])
    kubeconfig = tmp_path / "kubeconfig"
    kubeconfig.write_text("apiVersion: v1\nkind: Config\nclusters: []\n")

    report = await run(_contract(tmp_path), kubeconfig=kubeconfig)
    payload = json.loads((tmp_path / "ws" / "findings.json").read_text())

    assert report.total == 1
    assert payload["findings"][0]["evidences"][0]["source_finding_type"] == "cspm_k8s_manifest"


@pytest.mark.asyncio
async def test_cluster_reader_invoked_with_kubeconfig_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The driver forwards the kubeconfig argument to `read_cluster_workloads`."""
    captured: dict[str, Any] = {}
    _patch_cluster_reader(monkeypatch, [], capture=captured)
    kubeconfig = tmp_path / "kc.yaml"
    kubeconfig.write_text("k: v\n")

    await run(_contract(tmp_path), kubeconfig=kubeconfig)
    assert captured["kubeconfig"] == kubeconfig


@pytest.mark.asyncio
async def test_cluster_reader_invoked_with_namespace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """When `cluster_namespace` is passed, the driver forwards it through."""
    captured: dict[str, Any] = {}
    _patch_cluster_reader(monkeypatch, [], capture=captured)
    kubeconfig = tmp_path / "kc.yaml"
    kubeconfig.write_text("k: v\n")

    await run(_contract(tmp_path), kubeconfig=kubeconfig, cluster_namespace="production")
    assert captured["namespace"] == "production"


@pytest.mark.asyncio
async def test_cluster_reader_default_namespace_is_none(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No `cluster_namespace` → None reaches the reader (cluster-wide)."""
    captured: dict[str, Any] = {}
    _patch_cluster_reader(monkeypatch, [], capture=captured)
    kubeconfig = tmp_path / "kc.yaml"
    kubeconfig.write_text("k: v\n")

    await run(_contract(tmp_path), kubeconfig=kubeconfig)
    assert captured["namespace"] is None


# ---------------------------- mutual exclusion (Q6) -----------------------


@pytest.mark.asyncio
async def test_kubeconfig_and_manifest_dir_together_raise(tmp_path: Path) -> None:
    """Q6 — workload source is exclusive. Supplying both is a programmer error."""
    kubeconfig = tmp_path / "kc.yaml"
    kubeconfig.write_text("k: v\n")
    manifest_dir = tmp_path / "manifests"
    manifest_dir.mkdir()

    with pytest.raises(ValueError, match="mutually exclusive"):
        await run(_contract(tmp_path), kubeconfig=kubeconfig, manifest_dir=manifest_dir)


# ---------------------------- coexistence with other feeds ----------------


@pytest.mark.asyncio
async def test_kubeconfig_runs_alongside_kube_bench_and_polaris(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The two file feeds (kube-bench, polaris) coexist with kubeconfig — only the
    workload source is XOR'd. All three concurrent reads succeed."""
    from k8s_posture.tools.kube_bench import KubeBenchFinding
    from k8s_posture.tools.polaris import PolarisFinding

    async def fake_kb(**_: Any) -> tuple[KubeBenchFinding, ...]:
        return (
            KubeBenchFinding(
                control_id="1.1.1",
                control_text="Ensure API server pod spec file permissions",
                section_id="1.1",
                section_desc="Master",
                node_type="master",
                status="FAIL",
                severity_marker="",
                audit="stat",
                actual_value="777",
                remediation="chmod 644",
                scored=True,
                detected_at=NOW,
            ),
        )

    async def fake_polaris(**_: Any) -> tuple[PolarisFinding, ...]:
        return (
            PolarisFinding(
                check_id="runAsRootAllowed",
                message="x",
                severity="danger",
                category="Security",
                workload_kind="Deployment",
                workload_name="frontend",
                namespace="production",
                container_name="nginx",
                check_level="container",
                detected_at=NOW,
            ),
        )

    monkeypatch.setattr(agent_mod, "read_kube_bench", fake_kb)
    monkeypatch.setattr(agent_mod, "read_polaris", fake_polaris)
    _patch_cluster_reader(monkeypatch, [_manifest_finding()])

    kb_feed = tmp_path / "kb.json"
    polaris_feed = tmp_path / "polaris.json"
    kubeconfig = tmp_path / "kc.yaml"
    kb_feed.write_text("placeholder")
    polaris_feed.write_text("placeholder")
    kubeconfig.write_text("placeholder")

    report = await run(
        _contract(tmp_path),
        kube_bench_feed=kb_feed,
        polaris_feed=polaris_feed,
        kubeconfig=kubeconfig,
    )
    payload = json.loads((tmp_path / "ws" / "findings.json").read_text())
    source_types = {
        f["evidences"][0]["source_finding_type"] for f in payload["findings"] if f.get("evidences")
    }
    assert source_types == {"cspm_k8s_cis", "cspm_k8s_polaris", "cspm_k8s_manifest"}
    assert report.total == 3


# ---------------------------- manifest_dir path unchanged ----------------


@pytest.mark.asyncio
async def test_manifest_dir_path_still_uses_file_reader(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """v0.1 behaviour preserved — when only `manifest_dir` is set, the file
    reader runs (not the cluster reader). Asserts the cluster reader is NOT
    invoked in that mode."""
    cluster_called = False

    async def fake_cluster(**_: Any) -> tuple[ManifestFinding, ...]:
        nonlocal cluster_called
        cluster_called = True
        return ()

    async def fake_manifests(**_: Any) -> tuple[ManifestFinding, ...]:
        return (_manifest_finding(),)

    monkeypatch.setattr(agent_mod, "read_cluster_workloads", fake_cluster)
    monkeypatch.setattr(agent_mod, "read_manifests", fake_manifests)

    manifest_dir = tmp_path / "manifests"
    manifest_dir.mkdir()
    (manifest_dir / "frontend.yaml").write_text("placeholder")

    report = await run(_contract(tmp_path), manifest_dir=manifest_dir)
    assert report.total == 1
    assert cluster_called is False
