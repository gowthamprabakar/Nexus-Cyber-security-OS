"""Unit tests for the Kubernetes Posture Agent driver.

All three reader tools are mocked at the agent module's import level;
the test surface is the agent's wiring of charter + readers + normalizers
+ dedup + summarizer.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from charter.contract import BudgetSpec, ExecutionContract
from k8s_posture import agent as agent_mod
from k8s_posture.agent import build_registry, run
from k8s_posture.tools.kube_bench import KubeBenchFinding
from k8s_posture.tools.manifests import ManifestFinding
from k8s_posture.tools.polaris import PolarisFinding

from k8s_posture.schemas import Severity  # isort: skip — keeps test imports grouped

NOW = datetime(2026, 5, 13, 12, 0, 0, tzinfo=UTC)


def _contract(tmp_path: Path) -> ExecutionContract:
    return ExecutionContract(
        schema_version="0.1",
        delegation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
        source_agent="supervisor",
        target_agent="k8s_posture",
        customer_id="cust_test",
        task="Kubernetes posture scan",
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
        ],
        completion_condition="findings.json AND report.md exist",
        escalation_rules=[],
        workspace=str(tmp_path / "ws"),
        persistent_root=str(tmp_path / "p"),
        created_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )


def _kb(
    *,
    control_id: str = "1.1.1",
    status: str = "FAIL",
    severity_marker: str = "",
    node_type: str = "master",
) -> KubeBenchFinding:
    return KubeBenchFinding(
        control_id=control_id,
        control_text="Ensure API server pod spec file permissions",
        section_id="1.1",
        section_desc="Master Node Configuration Files",
        node_type=node_type,
        status=status,
        severity_marker=severity_marker,
        audit="stat -c %a /etc/k8s",
        actual_value="777",
        remediation="chmod 644",
        scored=True,
        detected_at=NOW,
    )


def _polaris(
    *,
    check_id: str = "runAsRootAllowed",
    severity: str = "danger",
    workload_name: str = "frontend",
    namespace: str = "production",
    container_name: str = "nginx",
) -> PolarisFinding:
    return PolarisFinding(
        check_id=check_id,
        message="Should not run as root",
        severity=severity,
        category="Security",
        workload_kind="Deployment",
        workload_name=workload_name,
        namespace=namespace,
        container_name=container_name,
        check_level="container",
        detected_at=NOW,
    )


def _manifest(
    *,
    rule_id: str = "run-as-root",
    severity: Severity = Severity.HIGH,
    workload_name: str = "frontend",
    namespace: str = "production",
    container_name: str = "nginx",
) -> ManifestFinding:
    return ManifestFinding(
        rule_id=rule_id,
        rule_title="Container running as root",
        severity=severity,
        workload_kind="Deployment",
        workload_name=workload_name,
        namespace=namespace,
        container_name=container_name,
        manifest_path="/manifests/frontend.yaml",
        detected_at=NOW,
    )


def _patch_kb(mp: pytest.MonkeyPatch, records: list[KubeBenchFinding]) -> None:
    async def fake(*, path: Path, **_: Any) -> tuple[KubeBenchFinding, ...]:
        return tuple(records)

    mp.setattr(agent_mod, "read_kube_bench", fake)


def _patch_polaris(mp: pytest.MonkeyPatch, records: list[PolarisFinding]) -> None:
    async def fake(*, path: Path, **_: Any) -> tuple[PolarisFinding, ...]:
        return tuple(records)

    mp.setattr(agent_mod, "read_polaris", fake)


def _patch_manifests(mp: pytest.MonkeyPatch, records: list[ManifestFinding]) -> None:
    async def fake(*, path: Path, **_: Any) -> tuple[ManifestFinding, ...]:
        return tuple(records)

    mp.setattr(agent_mod, "read_manifests", fake)


# ---------------------------- registry -----------------------------------


def test_build_registry_includes_three_readers() -> None:
    reg = build_registry()
    known = reg.known_tools()
    for name in ("read_kube_bench", "read_polaris", "read_manifests"):
        assert name in known


# ---------------------------- empty path ---------------------------------


@pytest.mark.asyncio
async def test_run_with_no_feeds_yields_empty_report(tmp_path: Path) -> None:
    report = await run(_contract(tmp_path))
    assert report.total == 0
    assert (tmp_path / "ws" / "findings.json").is_file()
    assert (tmp_path / "ws" / "report.md").is_file()


@pytest.mark.asyncio
async def test_empty_findings_json_is_valid(tmp_path: Path) -> None:
    await run(_contract(tmp_path))
    payload = json.loads((tmp_path / "ws" / "findings.json").read_text())
    assert payload["agent"] == "k8s_posture"
    assert payload["customer_id"] == "cust_test"
    assert payload["findings"] == []


# ---------------------------- per-feed happy paths -----------------------


@pytest.mark.asyncio
async def test_kube_bench_only_emits_finding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_kb(monkeypatch, [_kb()])
    feed = tmp_path / "kb.json"
    feed.write_text("placeholder")

    report = await run(_contract(tmp_path), kube_bench_feed=feed)
    payload = json.loads((tmp_path / "ws" / "findings.json").read_text())

    assert report.total == 1
    finding = payload["findings"][0]
    assert finding["class_uid"] == 2003
    assert finding["evidences"][0]["source_finding_type"] == "cspm_k8s_cis"


@pytest.mark.asyncio
async def test_polaris_only_emits_finding(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_polaris(monkeypatch, [_polaris()])
    feed = tmp_path / "polaris.json"
    feed.write_text("placeholder")

    report = await run(_contract(tmp_path), polaris_feed=feed)
    payload = json.loads((tmp_path / "ws" / "findings.json").read_text())

    assert report.total == 1
    assert payload["findings"][0]["evidences"][0]["source_finding_type"] == "cspm_k8s_polaris"


@pytest.mark.asyncio
async def test_manifest_only_emits_finding(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_manifests(monkeypatch, [_manifest()])
    feed = tmp_path / "manifests"
    feed.mkdir()
    (feed / "frontend.yaml").write_text("placeholder")

    report = await run(_contract(tmp_path), manifest_dir=feed)
    payload = json.loads((tmp_path / "ws" / "findings.json").read_text())

    assert report.total == 1
    assert payload["findings"][0]["evidences"][0]["source_finding_type"] == "cspm_k8s_manifest"


# ---------------------------- multi-feed concurrency ---------------------


@pytest.mark.asyncio
async def test_three_feeds_concurrent(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """All three feeds running in parallel should emit findings from each source."""
    _patch_kb(monkeypatch, [_kb()])
    _patch_polaris(monkeypatch, [_polaris()])
    _patch_manifests(monkeypatch, [_manifest()])

    kb_feed = tmp_path / "kb.json"
    polaris_feed = tmp_path / "polaris.json"
    manifest_dir = tmp_path / "manifests"
    kb_feed.write_text("placeholder")
    polaris_feed.write_text("placeholder")
    manifest_dir.mkdir()

    report = await run(
        _contract(tmp_path),
        kube_bench_feed=kb_feed,
        polaris_feed=polaris_feed,
        manifest_dir=manifest_dir,
    )
    payload = json.loads((tmp_path / "ws" / "findings.json").read_text())
    types = {
        f["evidences"][0]["source_finding_type"] for f in payload["findings"] if f.get("evidences")
    }
    assert types == {"cspm_k8s_cis", "cspm_k8s_polaris", "cspm_k8s_manifest"}
    assert report.total == 3


# ---------------------------- DEDUP stage --------------------------------


@pytest.mark.asyncio
async def test_dedup_stage_collapses_intra_source_duplicates(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Two identical Polaris findings within 5min should collapse into one."""
    _patch_polaris(monkeypatch, [_polaris(check_id="x"), _polaris(check_id="x")])
    feed = tmp_path / "polaris.json"
    feed.write_text("placeholder")

    report = await run(_contract(tmp_path), polaris_feed=feed)
    assert report.total == 1


@pytest.mark.asyncio
async def test_dedup_critical_severity_wins_after_merge(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """If a CRITICAL kube-bench critical-marker and a HIGH Polaris finding had the
    same key, the survivor would be CRITICAL. In practice kube-bench arns differ
    from Polaris arns so they don't collide — but two Polaris findings with
    different severities on the same workload DO collide."""
    _patch_polaris(
        monkeypatch,
        [
            _polaris(severity="warning"),  # medium
            _polaris(severity="danger"),  # high — wins
        ],
    )
    feed = tmp_path / "polaris.json"
    feed.write_text("placeholder")

    report = await run(_contract(tmp_path), polaris_feed=feed)
    assert report.total == 1
    assert report.findings[0]["severity"] == "High"


# ---------------------------- output files -------------------------------


@pytest.mark.asyncio
async def test_outputs_have_expected_shape(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_polaris(monkeypatch, [_polaris()])
    feed = tmp_path / "polaris.json"
    feed.write_text("placeholder")

    await run(_contract(tmp_path), polaris_feed=feed)

    payload = json.loads((tmp_path / "ws" / "findings.json").read_text())
    assert payload["agent"] == "k8s_posture"
    assert payload["findings"][0]["class_uid"] == 2003

    report_md = (tmp_path / "ws" / "report.md").read_text()
    assert "# Kubernetes Posture Scan" in report_md
    assert "## Per-namespace breakdown" in report_md


# ---------------------------- audit chain --------------------------------


@pytest.mark.asyncio
async def test_audit_chain_emitted(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Per F.1: every run emits a hash-chained audit.jsonl in the workspace."""
    _patch_polaris(monkeypatch, [_polaris()])
    feed = tmp_path / "polaris.json"
    feed.write_text("placeholder")

    await run(_contract(tmp_path), polaris_feed=feed)
    audit_path = tmp_path / "ws" / "audit.jsonl"
    assert audit_path.is_file()
    lines = [ln for ln in audit_path.read_text().splitlines() if ln.strip()]
    assert lines, "audit.jsonl is empty"


# ---------------------------- llm_provider plumbed ------------------------


@pytest.mark.asyncio
async def test_llm_provider_is_plumbed_but_unused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`llm_provider` is accepted for forward-compatibility but not invoked in v0.1."""
    _patch_polaris(monkeypatch, [_polaris()])
    feed = tmp_path / "polaris.json"
    feed.write_text("placeholder")

    class Sentinel:
        called = False

    sentinel = Sentinel()
    # The signature must accept llm_provider; the test would fail to invoke if not.
    report = await run(
        _contract(tmp_path),
        llm_provider=sentinel,  # type: ignore[arg-type]
        polaris_feed=feed,
    )
    assert report.total == 1
    assert sentinel.called is False
