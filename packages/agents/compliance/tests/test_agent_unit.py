"""Unit tests — D.6 Compliance agent driver (Task 11).

The bundled CIS YAML reader is monkeypatched at the agent module's
import scope when we need to inject a tighter fixture; most tests
use the real bundled library (Task 4) so the end-to-end wire shape
is exercised.

Sibling-workspace fixtures (F.3, D.5 findings.json) are built using
F.3's own ``build_finding`` so the wire shape is the real one.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock

import pytest
from charter.contract import BudgetSpec, ExecutionContract
from charter.memory import SemanticStore
from cloud_posture.schemas import AffectedResource as CspmAffectedResource
from cloud_posture.schemas import Severity as CspmSeverity
from cloud_posture.schemas import build_finding as build_cspm_finding
from compliance import agent as agent_mod
from compliance.agent import build_registry, run
from compliance.tools.cis_aws_benchmark import CisControl
from shared.fabric.envelope import NexusEnvelope

NOW = datetime(2026, 5, 21, 12, 0, 0, tzinfo=UTC)


def _contract(tmp_path: Path) -> ExecutionContract:
    return ExecutionContract(
        schema_version="0.1",
        delegation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
        source_agent="supervisor",
        target_agent="compliance",
        customer_id="acme",
        task="Compliance scan",
        required_outputs=["findings.json", "report.md"],
        budget=BudgetSpec(
            llm_calls=5,
            tokens=10_000,
            wall_clock_sec=60.0,
            cloud_api_calls=10,
            mb_written=10,
        ),
        permitted_tools=["read_cis_aws_benchmark"],
        completion_condition="findings.json AND report.md exist",
        escalation_rules=[],
        workspace=str(tmp_path / "ws"),
        persistent_root=str(tmp_path / "p"),
        created_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )


def _sibling_envelope(agent_id: str, *, correlation_id: str) -> NexusEnvelope:
    return NexusEnvelope(
        correlation_id=correlation_id,
        tenant_id="acme",
        agent_id=agent_id,
        nlah_version="0.1.0",
        model_pin="deterministic",
        charter_invocation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
    )


def _f3_affected(resource_id: str = "alice") -> list[CspmAffectedResource]:
    return [
        CspmAffectedResource(
            cloud="aws",
            account_id="123456789012",
            region="us-east-1",
            resource_type="aws_iam_user",
            resource_id=resource_id,
            arn=f"arn:aws:iam::123456789012:user/{resource_id}",
        )
    ]


def _write_f3_workspace(
    workspace: Path, *, rule_id: str = "CSPM-AWS-IAM-001", finding_id: str | None = None
) -> Path:
    workspace.mkdir(parents=True, exist_ok=True)
    payload = build_cspm_finding(
        finding_id=finding_id or f"{rule_id}-alice",
        rule_id=rule_id,
        severity=CspmSeverity.HIGH,
        title="F.3 fixture",
        description="x",
        affected=_f3_affected(),
        detected_at=NOW,
        envelope=_sibling_envelope(
            "cloud_posture", correlation_id="00000000-0000-0000-0000-00000000f3f3"
        ),
    ).to_dict()
    (workspace / "findings.json").write_text(
        json.dumps(
            {
                "agent": "cloud_posture",
                "agent_version": "0.1.0",
                "customer_id": "acme",
                "run_id": "run_f3",
                "scan_started_at": "2026-05-21T00:00:00+00:00",
                "scan_completed_at": "2026-05-21T00:00:05+00:00",
                "findings": [payload],
            }
        ),
        encoding="utf-8",
    )
    return workspace


def _d5_affected(bucket: str = "company-secrets") -> list[CspmAffectedResource]:
    return [
        CspmAffectedResource(
            cloud="aws",
            account_id="123456789012",
            region="us-east-1",
            resource_type="aws_s3_bucket",
            resource_id=bucket,
            arn=f"arn:aws:s3:::{bucket}",
        )
    ]


def _write_d5_workspace(
    workspace: Path, *, rule_id: str = "s3_bucket_public", bucket: str = "company-secrets"
) -> Path:
    workspace.mkdir(parents=True, exist_ok=True)
    payload = build_cspm_finding(
        finding_id=f"CSPM-AWS-PUBLIC-001-{bucket}",
        rule_id=rule_id,
        severity=CspmSeverity.HIGH,
        title="D.5 fixture",
        description="x",
        affected=_d5_affected(bucket),
        detected_at=NOW,
        envelope=_sibling_envelope(
            "data_security", correlation_id="00000000-0000-0000-0000-00000000d5d5"
        ),
    ).to_dict()
    (workspace / "findings.json").write_text(
        json.dumps(
            {
                "agent": "data_security",
                "agent_version": "0.1.0",
                "customer_id": "acme",
                "run_id": "run_d5",
                "scan_started_at": "2026-05-21T00:00:00+00:00",
                "scan_completed_at": "2026-05-21T00:00:05+00:00",
                "findings": [payload],
            }
        ),
        encoding="utf-8",
    )
    return workspace


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


def test_build_registry_includes_cis_loader() -> None:
    reg = build_registry()
    assert "read_cis_aws_benchmark" in reg.known_tools()


# ---------------------------------------------------------------------------
# Empty path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_run_with_no_workspaces_yields_empty_report(tmp_path: Path) -> None:
    """No sibling workspaces -> 0 findings; outputs still written."""
    report = await run(_contract(tmp_path))
    assert report.total == 0
    assert (tmp_path / "ws" / "findings.json").is_file()
    assert (tmp_path / "ws" / "report.md").is_file()


@pytest.mark.asyncio
async def test_empty_findings_json_is_valid_and_attribution_in_report(
    tmp_path: Path,
) -> None:
    await run(_contract(tmp_path))
    payload = json.loads((tmp_path / "ws" / "findings.json").read_text())
    assert payload["agent"] == "compliance"
    assert payload["customer_id"] == "acme"
    assert payload["findings"] == []
    md = (tmp_path / "ws" / "report.md").read_text()
    assert "CIS Benchmarks®" in md
    assert "cisecurity.org/cis-benchmarks/" in md


# ---------------------------------------------------------------------------
# F.3 cloud-posture correlation -> aggregator -> scorer end-to-end
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_f3_iam_no_mfa_lights_up_cis_1_10(tmp_path: Path) -> None:
    """F.3 emits CSPM-AWS-IAM-001 -> bundled YAML maps to CIS 1.10."""
    f3_ws = tmp_path / "f3"
    _write_f3_workspace(f3_ws, rule_id="CSPM-AWS-IAM-001")

    report = await run(_contract(tmp_path), cloud_posture_workspace=f3_ws)
    assert report.total == 1
    finding = report.findings[0]
    assert finding["compliance"]["control"] == "cis_aws_v3:1.10"
    # Canonical severity for Level 1 + required = HIGH.
    assert finding["severity_id"] == 4  # HIGH
    # aggregated context tag in finding-id.
    assert finding["finding_info"]["uid"].endswith("-aggregated")


@pytest.mark.asyncio
async def test_d5_s3_public_lights_up_cis_2_1_4_and_2_1_5(tmp_path: Path) -> None:
    """D.5 emits s3_bucket_public -> bundled YAML maps to BOTH 2.1.4 and 2.1.5.

    The aggregator collapses each (control, source-finding) emit, but since
    each control has its own bucket, we get 2 distinct aggregated findings.
    """
    d5_ws = tmp_path / "d5"
    _write_d5_workspace(d5_ws, rule_id="s3_bucket_public")

    report = await run(_contract(tmp_path), data_security_workspace=d5_ws)
    controls = {f["compliance"]["control"] for f in report.findings}
    assert controls == {"cis_aws_v3:2.1.4", "cis_aws_v3:2.1.5"}
    assert report.total == 2


@pytest.mark.asyncio
async def test_both_sibling_workspaces_combine_into_one_aggregated_view(
    tmp_path: Path,
) -> None:
    """F.3 + D.5 both contributing to CIS 2.1.4 collapse to one aggregated
    finding (control 2.1.4) with both contributors in evidence."""
    f3_ws = tmp_path / "f3"
    d5_ws = tmp_path / "d5"
    _write_f3_workspace(f3_ws, rule_id="CSPM-AWS-S3-001")  # maps to 2.1.4 + 2.1.5
    _write_d5_workspace(d5_ws, rule_id="s3_bucket_public")  # maps to 2.1.4 + 2.1.5

    report = await run(
        _contract(tmp_path),
        cloud_posture_workspace=f3_ws,
        data_security_workspace=d5_ws,
    )
    # CIS 2.1.4 + 2.1.5 each get one aggregated finding (the aggregator
    # collapses across (control, per-mapping) pairs).
    controls = [f["compliance"]["control"] for f in report.findings]
    assert sorted(controls) == ["cis_aws_v3:2.1.4", "cis_aws_v3:2.1.5"]
    # CIS 2.1.4 gets BOTH F.3 (via CSPM-AWS-S3-001) AND D.5 (via
    # s3_bucket_public) -> 2 contributors. CIS 2.1.5 only has the
    # D.5 mapping in the bundled YAML -> 1 contributor.
    by_control = {f["compliance"]["control"]: f for f in report.findings}
    assert by_control["cis_aws_v3:2.1.4"]["evidences"][0]["contributor_count"] == 2
    assert by_control["cis_aws_v3:2.1.5"]["evidences"][0]["contributor_count"] == 1


# ---------------------------------------------------------------------------
# Report metadata
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_report_carries_customer_and_delegation(tmp_path: Path) -> None:
    f3_ws = tmp_path / "f3"
    _write_f3_workspace(f3_ws)
    report = await run(_contract(tmp_path), cloud_posture_workspace=f3_ws)
    assert report.customer_id == "acme"
    assert report.run_id == "01J7M3X9Z1K8RPVQNH2T8DBHFZ"
    assert report.agent == "compliance"


@pytest.mark.asyncio
async def test_report_md_includes_cis_attribution_when_findings_present(
    tmp_path: Path,
) -> None:
    f3_ws = tmp_path / "f3"
    _write_f3_workspace(f3_ws)
    await run(_contract(tmp_path), cloud_posture_workspace=f3_ws)
    md = (tmp_path / "ws" / "report.md").read_text()
    assert "## CIS Level 1 failures" in md
    assert "## Attribution" in md
    assert "No verbatim CIS Securesuite text is reproduced" in md


# ---------------------------------------------------------------------------
# Audit chain
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_audit_jsonl_records_tool_call_and_outputs(tmp_path: Path) -> None:
    await run(_contract(tmp_path))
    audit_path = tmp_path / "ws" / "audit.jsonl"
    assert audit_path.is_file()
    events = [json.loads(line) for line in audit_path.read_text().splitlines() if line]
    actions = [e.get("action") for e in events]
    # 1 tool call (CIS loader) + 2 output writes (findings.json + report.md).
    assert actions.count("tool_call") == 1
    assert actions.count("output_written") == 2


# ---------------------------------------------------------------------------
# SemanticStore opt-in
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_run_with_no_semantic_store_skips_kg_writes(tmp_path: Path) -> None:
    """semantic_store=None default must not touch a substrate."""
    report = await run(_contract(tmp_path), semantic_store=None)
    assert report.total == 0


@pytest.mark.asyncio
async def test_run_with_semantic_store_persists_framework_and_controls(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Tightens the bundled-YAML fixture (just 1 control) so the test
    asserts a precise upsert count without depending on the full
    45-control library."""

    async def fake_reader(*, path: Path) -> tuple[CisControl, ...]:
        del path
        from compliance.schemas import ControlLevel

        return (
            CisControl(
                control_id="1.1",
                name="Test control",
                level=ControlLevel.LEVEL_1,
                required=True,
                applicability=("aws_iam",),
                description="Paraphrased summary",
                source_mappings=(),
            ),
        )

    monkeypatch.setattr(agent_mod, "read_cis_aws_benchmark", fake_reader)

    upserts: list[dict[str, Any]] = []

    async def fake_upsert_entity(
        *,
        tenant_id: str,
        entity_type: str,
        external_id: str,
        properties: dict[str, Any] | None = None,
    ) -> str:
        del properties
        upserts.append(
            {
                "tenant_id": tenant_id,
                "entity_type": entity_type,
                "external_id": external_id,
            }
        )
        return f"ent_{len(upserts)}"

    store = AsyncMock(spec=SemanticStore)
    store.upsert_entity.side_effect = fake_upsert_entity

    await run(_contract(tmp_path), semantic_store=store)

    entity_types = [u["entity_type"] for u in upserts]
    # 1 framework + 1 control = 2 upserts.
    assert entity_types == ["framework", "control"]
    assert upserts[0]["external_id"] == "cis_aws_v3"
    assert upserts[1]["external_id"] == "cis_aws_v3:1.1"
    assert all(u["tenant_id"] == "acme" for u in upserts)


# ---------------------------------------------------------------------------
# Forgiving on missing / malformed sibling workspaces
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_malformed_f3_workspace_does_not_block_d5_correlator(
    tmp_path: Path,
) -> None:
    """F.3 workspace exists but findings.json is malformed; D.5 still
    produces compliance findings (WI-5 regression probe analog)."""
    f3_ws = tmp_path / "f3"
    f3_ws.mkdir(parents=True, exist_ok=True)
    (f3_ws / "findings.json").write_text("{not-json", encoding="utf-8")

    d5_ws = tmp_path / "d5"
    _write_d5_workspace(d5_ws, rule_id="s3_bucket_public")

    report = await run(
        _contract(tmp_path),
        cloud_posture_workspace=f3_ws,
        data_security_workspace=d5_ws,
    )
    # D.5 -> 2.1.4 + 2.1.5 still emit.
    assert report.total == 2


@pytest.mark.asyncio
async def test_missing_workspaces_dirs_are_silently_skipped(tmp_path: Path) -> None:
    """A workspace path that doesn't exist as a directory yields zero
    findings from that source; the run still completes."""
    report = await run(
        _contract(tmp_path),
        cloud_posture_workspace=tmp_path / "nonexistent_f3",
        data_security_workspace=tmp_path / "nonexistent_d5",
    )
    assert report.total == 0


# Silence unused-import warnings — kept for future driver hooks.
_ = Sequence
