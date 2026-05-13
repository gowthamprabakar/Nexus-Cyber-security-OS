"""Unit tests for the Multi-Cloud Posture Agent driver.

All four reader tools are mocked at the agent module's import level;
the test surface is the agent's wiring of charter + readers + normalizers
+ summarizer.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from charter.contract import BudgetSpec, ExecutionContract
from multi_cloud_posture import agent as agent_mod
from multi_cloud_posture.agent import build_registry, run
from multi_cloud_posture.tools.azure_activity import AzureActivityRecord
from multi_cloud_posture.tools.azure_defender import AzureDefenderFinding
from multi_cloud_posture.tools.gcp_iam import GcpIamFinding
from multi_cloud_posture.tools.gcp_scc import GcpSccFinding

NOW = datetime(2026, 5, 13, 12, 0, 0, tzinfo=UTC)


def _contract(tmp_path: Path) -> ExecutionContract:
    return ExecutionContract(
        schema_version="0.1",
        delegation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
        source_agent="supervisor",
        target_agent="multi_cloud_posture",
        customer_id="cust_test",
        task="Multi-cloud posture scan",
        required_outputs=["findings.json", "report.md"],
        budget=BudgetSpec(
            llm_calls=5,
            tokens=10_000,
            wall_clock_sec=60.0,
            cloud_api_calls=10,
            mb_written=10,
        ),
        permitted_tools=[
            "read_azure_findings",
            "read_azure_activity",
            "read_gcp_findings",
            "read_gcp_iam_findings",
        ],
        completion_condition="findings.json AND report.md exist",
        escalation_rules=[],
        workspace=str(tmp_path / "ws"),
        persistent_root=str(tmp_path / "p"),
        created_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )


def _defender() -> AzureDefenderFinding:
    return AzureDefenderFinding(
        kind="assessment",
        record_id="/subscriptions/aaa-bbb/providers/Microsoft.Security/assessments/asmt-001",
        display_name="Restrict storage account public access",
        severity="High",
        status="Unhealthy",
        description="x",
        resource_id="/subscriptions/aaa-bbb/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/sa1",
        subscription_id="aaa-bbb",
        assessment_type="BuiltIn",
        detected_at=NOW,
    )


def _activity() -> AzureActivityRecord:
    return AzureActivityRecord(
        record_id="/subscriptions/aaa-bbb/providers/microsoft.insights/eventtypes/management/values/evt-001",
        operation_name="Microsoft.Authorization/roleAssignments/write",
        operation_class="iam",
        category="Administrative",
        level="Critical",
        status="Succeeded",
        caller="user@example.com",
        resource_id="/subscriptions/aaa-bbb/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/sa1",
        subscription_id="aaa-bbb",
        resource_group="rg1",
        detected_at=NOW,
    )


def _scc() -> GcpSccFinding:
    return GcpSccFinding(
        finding_name="organizations/123/sources/456/findings/finding-001",
        parent="organizations/123/sources/456",
        resource_name="//storage.googleapis.com/projects/proj-xyz/buckets/public-bucket",
        category="PUBLIC_BUCKET",
        state="ACTIVE",
        severity="HIGH",
        description="x",
        project_id="proj-xyz",
        detected_at=NOW,
    )


def _iam() -> GcpIamFinding:
    return GcpIamFinding(
        asset_name="//cloudresourcemanager.googleapis.com/projects/proj-xyz",
        asset_type="cloudresourcemanager.googleapis.com/Project",
        project_id="proj-xyz",
        role="roles/owner",
        member="user:bob@external.com",
        severity="CRITICAL",
        reason="external user with owner role",
        detected_at=NOW,
    )


def _patch_defender(mp: pytest.MonkeyPatch, records: list[AzureDefenderFinding]) -> None:
    async def fake(*, path: Path, **_: Any) -> tuple[AzureDefenderFinding, ...]:
        return tuple(records)

    mp.setattr(agent_mod, "read_azure_findings", fake)


def _patch_activity(mp: pytest.MonkeyPatch, records: list[AzureActivityRecord]) -> None:
    async def fake(*, path: Path, **_: Any) -> tuple[AzureActivityRecord, ...]:
        return tuple(records)

    mp.setattr(agent_mod, "read_azure_activity", fake)


def _patch_scc(mp: pytest.MonkeyPatch, records: list[GcpSccFinding]) -> None:
    async def fake(*, path: Path, **_: Any) -> tuple[GcpSccFinding, ...]:
        return tuple(records)

    mp.setattr(agent_mod, "read_gcp_findings", fake)


def _patch_iam(mp: pytest.MonkeyPatch, records: list[GcpIamFinding]) -> None:
    async def fake(*, path: Path, **_: Any) -> tuple[GcpIamFinding, ...]:
        return tuple(records)

    mp.setattr(agent_mod, "read_gcp_iam_findings", fake)


# ---------------------------- registry -----------------------------------


def test_build_registry_includes_four_readers() -> None:
    reg = build_registry()
    known = reg.known_tools()
    for name in (
        "read_azure_findings",
        "read_azure_activity",
        "read_gcp_findings",
        "read_gcp_iam_findings",
    ):
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
    assert payload["agent"] == "multi_cloud_posture"
    assert payload["customer_id"] == "cust_test"
    assert payload["findings"] == []


# ---------------------------- per-feed happy paths -----------------------


@pytest.mark.asyncio
async def test_azure_defender_only_emits_finding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_defender(monkeypatch, [_defender()])
    feed = tmp_path / "defender.json"
    feed.write_text("placeholder")

    report = await run(_contract(tmp_path), azure_findings_feed=feed)
    payload = json.loads((tmp_path / "ws" / "findings.json").read_text())

    assert report.total == 1
    finding = payload["findings"][0]
    assert finding["class_uid"] == 2003
    assert finding["evidences"][0]["source_finding_type"] == "cspm_azure_defender"


@pytest.mark.asyncio
async def test_azure_activity_only_emits_finding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_activity(monkeypatch, [_activity()])
    feed = tmp_path / "activity.json"
    feed.write_text("placeholder")

    report = await run(_contract(tmp_path), azure_activity_feed=feed)
    payload = json.loads((tmp_path / "ws" / "findings.json").read_text())

    assert report.total == 1
    assert payload["findings"][0]["evidences"][0]["source_finding_type"] == "cspm_azure_activity"


@pytest.mark.asyncio
async def test_gcp_scc_only_emits_finding(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_scc(monkeypatch, [_scc()])
    feed = tmp_path / "scc.json"
    feed.write_text("placeholder")

    report = await run(_contract(tmp_path), gcp_findings_feed=feed)
    payload = json.loads((tmp_path / "ws" / "findings.json").read_text())

    assert report.total == 1
    assert payload["findings"][0]["evidences"][0]["source_finding_type"] == "cspm_gcp_scc"


@pytest.mark.asyncio
async def test_gcp_iam_only_emits_finding(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_iam(monkeypatch, [_iam()])
    feed = tmp_path / "iam.json"
    feed.write_text("placeholder")

    report = await run(_contract(tmp_path), gcp_iam_feed=feed)
    payload = json.loads((tmp_path / "ws" / "findings.json").read_text())

    assert report.total == 1
    assert payload["findings"][0]["evidences"][0]["source_finding_type"] == "cspm_gcp_iam"
    # CRITICAL severity uplifted from the IAM analyser.
    assert payload["findings"][0]["severity"] == "Critical"


# ---------------------------- multi-feed ---------------------------------


@pytest.mark.asyncio
async def test_four_feeds_concurrent(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """All four feeds running in parallel should emit findings from each."""
    _patch_defender(monkeypatch, [_defender()])
    _patch_activity(monkeypatch, [_activity()])
    _patch_scc(monkeypatch, [_scc()])
    _patch_iam(monkeypatch, [_iam()])

    paths = {
        "az_f": tmp_path / "az-f.json",
        "az_a": tmp_path / "az-a.json",
        "gc_f": tmp_path / "gc-f.json",
        "gc_i": tmp_path / "gc-i.json",
    }
    for p in paths.values():
        p.write_text("placeholder")

    report = await run(
        _contract(tmp_path),
        azure_findings_feed=paths["az_f"],
        azure_activity_feed=paths["az_a"],
        gcp_findings_feed=paths["gc_f"],
        gcp_iam_feed=paths["gc_i"],
    )
    payload = json.loads((tmp_path / "ws" / "findings.json").read_text())
    types = {
        f["evidences"][0]["source_finding_type"] for f in payload["findings"] if f.get("evidences")
    }
    assert types == {
        "cspm_azure_defender",
        "cspm_azure_activity",
        "cspm_gcp_scc",
        "cspm_gcp_iam",
    }
    assert report.total == 4


# ---------------------------- domain allowlist plumbed -------------------


@pytest.mark.asyncio
async def test_customer_domain_allowlist_passed_to_iam_reader(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Verify the `customer_domain_allowlist` flag reaches `read_gcp_iam_findings`."""
    seen: dict[str, Any] = {}

    async def fake(**kwargs: Any) -> tuple[GcpIamFinding, ...]:
        seen.update(kwargs)
        return ()

    monkeypatch.setattr(agent_mod, "read_gcp_iam_findings", fake)
    feed = tmp_path / "iam.json"
    feed.write_text("placeholder")

    await run(
        _contract(tmp_path),
        gcp_iam_feed=feed,
        customer_domain_allowlist=("example.com", "corp.example.com"),
    )
    assert seen["customer_domain_allowlist"] == ("example.com", "corp.example.com")


# ---------------------------- output files -------------------------------


@pytest.mark.asyncio
async def test_outputs_have_expected_shape(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_scc(monkeypatch, [_scc()])
    feed = tmp_path / "scc.json"
    feed.write_text("placeholder")

    await run(_contract(tmp_path), gcp_findings_feed=feed)

    payload = json.loads((tmp_path / "ws" / "findings.json").read_text())
    assert payload["agent"] == "multi_cloud_posture"
    assert payload["findings"][0]["class_uid"] == 2003

    report_md = (tmp_path / "ws" / "report.md").read_text()
    assert "# Multi-Cloud Posture Scan" in report_md
    assert "## Per-cloud breakdown" in report_md


# ---------------------------- audit chain --------------------------------


@pytest.mark.asyncio
async def test_audit_chain_emitted(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Per F.1: every run emits a hash-chained audit.jsonl in the workspace."""
    _patch_scc(monkeypatch, [_scc()])
    feed = tmp_path / "scc.json"
    feed.write_text("placeholder")

    await run(_contract(tmp_path), gcp_findings_feed=feed)
    audit_path = tmp_path / "ws" / "audit.jsonl"
    assert audit_path.is_file()
    lines = [ln for ln in audit_path.read_text().splitlines() if ln.strip()]
    assert len(lines) >= 1
