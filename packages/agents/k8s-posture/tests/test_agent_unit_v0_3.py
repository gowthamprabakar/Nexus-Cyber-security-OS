"""Agent driver tests for D.6 v0.3 — the `in_cluster` workload-source branch.

v0.1 + v0.2 driver tests live in `test_agent_unit.py` and
`test_agent_unit_v0_2.py` respectively and remain unchanged. v0.3 adds
the in-cluster ServiceAccount path; tests cover routing + Q2 mutual
exclusion at the agent.run boundary.
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
        task="Kubernetes posture scan (in-cluster)",
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


def _manifest_finding() -> ManifestFinding:
    return ManifestFinding(
        rule_id="run-as-root",
        rule_title="Container running as root",
        severity=Severity.HIGH,
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


# ---------------------------- happy path ----------------------------------


@pytest.mark.asyncio
async def test_in_cluster_only_emits_manifest_finding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An in_cluster=True run goes through normalize_manifest like the v0.1/v0.2 paths."""
    _patch_cluster_reader(monkeypatch, records=[_manifest_finding()])

    report = await run(_contract(tmp_path), in_cluster=True)
    payload = json.loads((tmp_path / "ws" / "findings.json").read_text())

    assert report.total == 1
    assert payload["findings"][0]["evidences"][0]["source_finding_type"] == "cspm_k8s_manifest"


@pytest.mark.asyncio
async def test_in_cluster_forwarded_to_reader(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The driver forwards `in_cluster=True` to read_cluster_workloads."""
    captured: dict[str, Any] = {}
    _patch_cluster_reader(monkeypatch, capture=captured)

    await run(_contract(tmp_path), in_cluster=True)
    assert captured.get("in_cluster") is True


@pytest.mark.asyncio
async def test_in_cluster_with_namespace_forwards_both(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Namespace scope works in in-cluster mode too (Q3 of v0.2)."""
    captured: dict[str, Any] = {}
    _patch_cluster_reader(monkeypatch, capture=captured)

    await run(_contract(tmp_path), in_cluster=True, cluster_namespace="production")
    assert captured.get("in_cluster") is True
    assert captured.get("namespace") == "production"


@pytest.mark.asyncio
async def test_in_cluster_false_kubeconfig_unused_skips_workload_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Default invocation (no workload source) emits an empty report — same as v0.1/v0.2."""
    cluster_called = False

    async def fake_cluster(**_: Any) -> tuple[ManifestFinding, ...]:
        nonlocal cluster_called
        cluster_called = True
        return ()

    monkeypatch.setattr(agent_mod, "read_cluster_workloads", fake_cluster)
    report = await run(_contract(tmp_path))
    assert report.total == 0
    assert cluster_called is False


# ---------------------------- v0.3 Q2 mutual exclusion -------------------


@pytest.mark.asyncio
async def test_kubeconfig_and_in_cluster_together_raises(tmp_path: Path) -> None:
    """v0.3 Q2 — kubeconfig + in_cluster are mutually exclusive at the agent level."""
    kubeconfig = tmp_path / "kc.yaml"
    kubeconfig.write_text("k: v\n")

    with pytest.raises(ValueError, match="mutually exclusive"):
        await run(_contract(tmp_path), kubeconfig=kubeconfig, in_cluster=True)


@pytest.mark.asyncio
async def test_manifest_dir_and_in_cluster_together_raises(tmp_path: Path) -> None:
    """Workload-source exclusion generalises across all three sources."""
    manifest_dir = tmp_path / "manifests"
    manifest_dir.mkdir()

    with pytest.raises(ValueError, match="mutually exclusive"):
        await run(_contract(tmp_path), manifest_dir=manifest_dir, in_cluster=True)


@pytest.mark.asyncio
async def test_all_three_workload_sources_together_raises(tmp_path: Path) -> None:
    """Defensive: even all three at once raises a clear error."""
    kubeconfig = tmp_path / "kc.yaml"
    kubeconfig.write_text("k: v\n")
    manifest_dir = tmp_path / "manifests"
    manifest_dir.mkdir()

    with pytest.raises(ValueError, match="mutually exclusive"):
        await run(
            _contract(tmp_path),
            manifest_dir=manifest_dir,
            kubeconfig=kubeconfig,
            in_cluster=True,
        )


# ---------------------------- v0.2 path still works ----------------------


@pytest.mark.asyncio
async def test_v0_2_kubeconfig_path_unchanged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """v0.2 callers continue to work bit-for-bit; the new `in_cluster` arg defaults to False."""
    captured: dict[str, Any] = {}
    _patch_cluster_reader(monkeypatch, records=[_manifest_finding()], capture=captured)
    kubeconfig = tmp_path / "kc.yaml"
    kubeconfig.write_text("apiVersion: v1\nkind: Config\nclusters: []\n")

    report = await run(_contract(tmp_path), kubeconfig=kubeconfig)
    assert report.total == 1
    assert captured.get("kubeconfig") == kubeconfig
    # `in_cluster` keyword should NOT have been passed by the driver in v0.2 mode.
    assert captured.get("in_cluster") is not True


# ---------------------------- coexistence with file feeds ----------------


@pytest.mark.asyncio
async def test_in_cluster_runs_alongside_kube_bench_and_polaris(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Live in-cluster mode coexists with file-based kube-bench + polaris feeds."""
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
    _patch_cluster_reader(monkeypatch, records=[_manifest_finding()])

    kb_feed = tmp_path / "kb.json"
    polaris_feed = tmp_path / "polaris.json"
    kb_feed.write_text("placeholder")
    polaris_feed.write_text("placeholder")

    report = await run(
        _contract(tmp_path),
        kube_bench_feed=kb_feed,
        polaris_feed=polaris_feed,
        in_cluster=True,
    )
    payload = json.loads((tmp_path / "ws" / "findings.json").read_text())
    source_types = {
        f["evidences"][0]["source_finding_type"] for f in payload["findings"] if f.get("evidences")
    }
    assert source_types == {"cspm_k8s_cis", "cspm_k8s_polaris", "cspm_k8s_manifest"}
    assert report.total == 3
