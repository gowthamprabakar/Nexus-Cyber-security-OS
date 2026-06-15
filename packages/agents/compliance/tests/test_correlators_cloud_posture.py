"""Tests — ``compliance.correlators.cloud_posture_correlator`` (Task 6).

Builds in-memory F.3 ``findings.json`` fixtures using F.3's own
``build_finding`` (so the wire shape is real) and asserts the
emitted ``ComplianceFinding``s. Forgiving-read posture from D.8 is
inherited via the same skip-on-failure paths.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from cloud_posture.schemas import AffectedResource as CspmAffectedResource
from cloud_posture.schemas import Severity as CspmSeverity
from cloud_posture.schemas import build_finding as build_cspm_finding
from compliance.correlators.cloud_posture_correlator import correlate_cloud_posture
from compliance.correlators.control_index import build_control_by_id, build_control_index
from compliance.schemas import ControlLevel, ControlMapping
from compliance.tools.cis_aws_benchmark import CisControl
from shared.fabric.envelope import NexusEnvelope


def _envelope(tenant: str = "acme") -> NexusEnvelope:
    return NexusEnvelope(
        correlation_id="00000000-0000-0000-0000-00000000d6d6",
        tenant_id=tenant,
        agent_id="compliance",
        nlah_version="d6-v0.1",
        model_pin="deterministic",
        charter_invocation_id="00000000-0000-0000-0000-000000000001",
    )


def _f3_envelope() -> NexusEnvelope:
    return NexusEnvelope(
        correlation_id="00000000-0000-0000-0000-00000000f3f3",
        tenant_id="acme",
        agent_id="cloud_posture",
        nlah_version="0.1.0",
        model_pin="deterministic",
        charter_invocation_id="00000000-0000-0000-0000-000000000001",
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


def _control(
    control_id: str = "1.10",
    *,
    level: ControlLevel = ControlLevel.LEVEL_1,
    required: bool = True,
    mappings: list[ControlMapping] | None = None,
) -> CisControl:
    return CisControl(
        control_id=control_id,
        name=f"CIS {control_id} test control",
        level=level,
        required=required,
        applicability=("aws_iam",),
        description=f"Paraphrased summary for {control_id}.",
        source_mappings=tuple(mappings or []),
    )


def _mapping(rule_id: str, control_id: str) -> ControlMapping:
    return ControlMapping(
        source_agent="cloud_posture",
        source_rule_id=rule_id,
        control_id=control_id,
        level=ControlLevel.LEVEL_1,
        required=True,
    )


def _f3_finding(
    *,
    finding_id: str = "CSPM-AWS-IAM-001-alice",
    rule_id: str = "CSPM-AWS-IAM-001",
    resource_id: str = "alice",
) -> dict[str, Any]:
    finding = build_cspm_finding(
        finding_id=finding_id,
        rule_id=rule_id,
        severity=CspmSeverity.HIGH,
        title=f"F.3 finding for {resource_id}",
        description="x",
        affected=_f3_affected(resource_id),
        detected_at=datetime(2026, 5, 21, tzinfo=UTC),
        envelope=_f3_envelope(),
    )
    return finding.to_dict()


def _write_f3_findings(workspace: Path, payloads: list[dict[str, Any]]) -> None:
    workspace.mkdir(parents=True, exist_ok=True)
    report = {
        "agent": "cloud_posture",
        "agent_version": "0.1.0",
        "customer_id": "acme",
        "run_id": "run_f3",
        "scan_started_at": "2026-05-21T00:00:00+00:00",
        "scan_completed_at": "2026-05-21T00:00:05+00:00",
        "findings": payloads,
    }
    (workspace / "findings.json").write_text(json.dumps(report), encoding="utf-8")


# ---------------------------------------------------------------------------
# Skip-cases
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_returns_empty_when_workspace_is_none() -> None:
    index = build_control_index([_control(mappings=[_mapping("CSPM-AWS-IAM-001", "1.10")])])
    findings = await correlate_cloud_posture(
        cloud_posture_workspace=None,
        control_index=index,
        correlated_at=datetime(2026, 5, 21, tzinfo=UTC),
        envelope=_envelope(),
    )
    assert findings == ()


@pytest.mark.asyncio
async def test_returns_empty_when_index_is_empty(tmp_path: Path) -> None:
    _write_f3_findings(tmp_path, [_f3_finding()])
    findings = await correlate_cloud_posture(
        cloud_posture_workspace=tmp_path,
        control_index={},
        correlated_at=datetime(2026, 5, 21, tzinfo=UTC),
        envelope=_envelope(),
    )
    assert findings == ()


@pytest.mark.asyncio
async def test_returns_empty_when_findings_json_missing(tmp_path: Path) -> None:
    index = build_control_index([_control(mappings=[_mapping("CSPM-AWS-IAM-001", "1.10")])])
    findings = await correlate_cloud_posture(
        cloud_posture_workspace=tmp_path,
        control_index=index,
        correlated_at=datetime(2026, 5, 21, tzinfo=UTC),
        envelope=_envelope(),
    )
    assert findings == ()


@pytest.mark.asyncio
async def test_returns_empty_when_findings_json_malformed(tmp_path: Path) -> None:
    (tmp_path / "findings.json").write_text("{nope", encoding="utf-8")
    index = build_control_index([_control(mappings=[_mapping("CSPM-AWS-IAM-001", "1.10")])])
    findings = await correlate_cloud_posture(
        cloud_posture_workspace=tmp_path,
        control_index=index,
        correlated_at=datetime(2026, 5, 21, tzinfo=UTC),
        envelope=_envelope(),
    )
    assert findings == ()


@pytest.mark.asyncio
async def test_returns_empty_when_no_rule_id_match(tmp_path: Path) -> None:
    _write_f3_findings(tmp_path, [_f3_finding(rule_id="CSPM-AWS-IAM-001")])
    index = build_control_index([_control(mappings=[_mapping("CSPM-AWS-RDS-001", "2.3.1")])])
    findings = await correlate_cloud_posture(
        cloud_posture_workspace=tmp_path,
        control_index=index,
        correlated_at=datetime(2026, 5, 21, tzinfo=UTC),
        envelope=_envelope(),
    )
    assert findings == ()


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_single_mapping_match_emits_one_finding(tmp_path: Path) -> None:
    _write_f3_findings(tmp_path, [_f3_finding(rule_id="CSPM-AWS-IAM-001")])
    index = build_control_index([_control(mappings=[_mapping("CSPM-AWS-IAM-001", "1.10")])])
    findings = await correlate_cloud_posture(
        cloud_posture_workspace=tmp_path,
        control_index=index,
        correlated_at=datetime(2026, 5, 21, tzinfo=UTC),
        envelope=_envelope(),
    )
    assert len(findings) == 1


@pytest.mark.asyncio
async def test_one_f3_finding_maps_to_two_cis_controls_emits_two(
    tmp_path: Path,
) -> None:
    """CSPM-AWS-S3-001 maps to both CIS 2.1.4 and 2.1.5 -> two emits."""
    _write_f3_findings(tmp_path, [_f3_finding(rule_id="CSPM-AWS-S3-001")])
    index = build_control_index(
        [
            _control(
                control_id="2.1.4",
                mappings=[_mapping("CSPM-AWS-S3-001", "2.1.4")],
            ),
            _control(
                control_id="2.1.5",
                mappings=[_mapping("CSPM-AWS-S3-001", "2.1.5")],
            ),
        ]
    )
    findings = await correlate_cloud_posture(
        cloud_posture_workspace=tmp_path,
        control_index=index,
        correlated_at=datetime(2026, 5, 21, tzinfo=UTC),
        envelope=_envelope(),
    )
    assert len(findings) == 2
    rule_ids = {f.rule_id for f in findings}
    assert rule_ids == {"cis_aws_v3:2.1.4", "cis_aws_v3:2.1.5"}


@pytest.mark.asyncio
async def test_finding_id_includes_control_token_and_f3_hash(tmp_path: Path) -> None:
    _write_f3_findings(
        tmp_path,
        [_f3_finding(finding_id="CSPM-AWS-IAM-001-alice", rule_id="CSPM-AWS-IAM-001")],
    )
    index = build_control_index([_control(mappings=[_mapping("CSPM-AWS-IAM-001", "1.10")])])
    findings = await correlate_cloud_posture(
        cloud_posture_workspace=tmp_path,
        control_index=index,
        correlated_at=datetime(2026, 5, 21, tzinfo=UTC),
        envelope=_envelope(),
    )
    fid = findings[0].finding_id
    assert fid.startswith("COMPLIANCE-CIS_AWS_V3-1_10-001-")
    assert "f3_" in fid


@pytest.mark.asyncio
async def test_severity_table_drives_emit_severity(tmp_path: Path) -> None:
    """Level 1 + required -> HIGH; Level 2 + recommended -> LOW."""
    from compliance.schemas import Severity

    _write_f3_findings(
        tmp_path,
        [
            _f3_finding(finding_id="CSPM-AWS-IAM-001-alice", rule_id="CSPM-AWS-IAM-001"),
            _f3_finding(finding_id="CSPM-AWS-KMS-001-key1", rule_id="CSPM-AWS-KMS-001"),
        ],
    )
    index = build_control_index(
        [
            _control(
                control_id="1.10",
                level=ControlLevel.LEVEL_1,
                required=True,
                mappings=[
                    ControlMapping(
                        source_agent="cloud_posture",
                        source_rule_id="CSPM-AWS-IAM-001",
                        control_id="1.10",
                        level=ControlLevel.LEVEL_1,
                        required=True,
                    )
                ],
            ),
            _control(
                control_id="2.4.1",
                level=ControlLevel.LEVEL_2,
                required=False,
                mappings=[
                    ControlMapping(
                        source_agent="cloud_posture",
                        source_rule_id="CSPM-AWS-KMS-001",
                        control_id="2.4.1",
                        level=ControlLevel.LEVEL_2,
                        required=False,
                    )
                ],
            ),
        ]
    )
    findings = await correlate_cloud_posture(
        cloud_posture_workspace=tmp_path,
        control_index=index,
        correlated_at=datetime(2026, 5, 21, tzinfo=UTC),
        envelope=_envelope(),
    )
    by_rule = {f.rule_id: f for f in findings}
    assert by_rule["cis_aws_v3:1.10"].severity == Severity.HIGH
    assert by_rule["cis_aws_v3:2.4.1"].severity == Severity.LOW


@pytest.mark.asyncio
async def test_f3_resources_propagated_to_compliance_finding(tmp_path: Path) -> None:
    """F.3's `resources[]` entries are projected into D.6's AffectedResource list."""
    _write_f3_findings(
        tmp_path,
        [_f3_finding(rule_id="CSPM-AWS-IAM-001", resource_id="alice")],
    )
    index = build_control_index([_control(mappings=[_mapping("CSPM-AWS-IAM-001", "1.10")])])
    findings = await correlate_cloud_posture(
        cloud_posture_workspace=tmp_path,
        control_index=index,
        correlated_at=datetime(2026, 5, 21, tzinfo=UTC),
        envelope=_envelope(),
    )
    resources = findings[0].resources
    assert len(resources) == 1
    assert resources[0]["type"] == "aws_iam_user"
    assert resources[0]["uid"].endswith("/alice")


@pytest.mark.asyncio
async def test_evidence_carries_source_finding_and_control_block(
    tmp_path: Path,
) -> None:
    _write_f3_findings(
        tmp_path,
        [_f3_finding(finding_id="CSPM-AWS-IAM-001-alice", rule_id="CSPM-AWS-IAM-001")],
    )
    index = build_control_index([_control(mappings=[_mapping("CSPM-AWS-IAM-001", "1.10")])])
    findings = await correlate_cloud_posture(
        cloud_posture_workspace=tmp_path,
        control_index=index,
        correlated_at=datetime(2026, 5, 21, tzinfo=UTC),
        envelope=_envelope(),
    )
    ev = findings[0].to_dict()["evidences"][0]
    assert ev["source_finding"]["agent"] == "cloud_posture"
    assert ev["source_finding"]["finding_id"] == "CSPM-AWS-IAM-001-alice"
    assert ev["source_finding"]["rule_id"] == "CSPM-AWS-IAM-001"
    assert ev["control"]["framework"] == "cis_aws_v3"
    assert ev["control"]["control_id"] == "1.10"
    assert ev["control"]["level"] == "level_1"
    assert ev["control"]["required"] is True


@pytest.mark.asyncio
async def test_envelope_tenant_propagates_into_resource_account_id(
    tmp_path: Path,
) -> None:
    """When F.3 emits an owner.account_uid, that wins (real AWS account).
    When F.3 owner is missing, fallback uses envelope.tenant_id."""
    _write_f3_findings(tmp_path, [_f3_finding(rule_id="CSPM-AWS-IAM-001")])
    index = build_control_index([_control(mappings=[_mapping("CSPM-AWS-IAM-001", "1.10")])])
    findings = await correlate_cloud_posture(
        cloud_posture_workspace=tmp_path,
        control_index=index,
        correlated_at=datetime(2026, 5, 21, tzinfo=UTC),
        envelope=_envelope("contoso"),
    )
    # F.3 carries account_id="123456789012" in its OCSF owner block;
    # the correlator MUST prefer the source-finding's account_id over
    # envelope.tenant_id (the latter is just the fallback).
    assert findings[0].resources[0]["owner"]["account_uid"] == "123456789012"


@pytest.mark.asyncio
async def test_sequence_increments_across_emits(tmp_path: Path) -> None:
    """Two source findings, each mapping to one control -> sequence 001, 002."""
    _write_f3_findings(
        tmp_path,
        [
            _f3_finding(finding_id="CSPM-AWS-IAM-001-alice", rule_id="CSPM-AWS-IAM-001"),
            _f3_finding(finding_id="CSPM-AWS-IAM-001-bob", rule_id="CSPM-AWS-IAM-001"),
        ],
    )
    index = build_control_index([_control(mappings=[_mapping("CSPM-AWS-IAM-001", "1.10")])])
    findings = await correlate_cloud_posture(
        cloud_posture_workspace=tmp_path,
        control_index=index,
        correlated_at=datetime(2026, 5, 21, tzinfo=UTC),
        envelope=_envelope(),
    )
    seqs = [f.finding_id.split("-")[3] for f in findings]
    assert seqs == ["001", "002"]


@pytest.mark.asyncio
async def test_non_2003_entries_skipped(tmp_path: Path) -> None:
    """A class_uid 2004 entry in the same file is silently skipped."""
    good = _f3_finding(rule_id="CSPM-AWS-IAM-001")
    other = {**good, "class_uid": 2004}
    _write_f3_findings(tmp_path, [other, good])
    index = build_control_index([_control(mappings=[_mapping("CSPM-AWS-IAM-001", "1.10")])])
    findings = await correlate_cloud_posture(
        cloud_posture_workspace=tmp_path,
        control_index=index,
        correlated_at=datetime(2026, 5, 21, tzinfo=UTC),
        envelope=_envelope(),
    )
    assert len(findings) == 1


@pytest.mark.asyncio
async def test_entries_with_missing_compliance_block_skipped(tmp_path: Path) -> None:
    good = _f3_finding(rule_id="CSPM-AWS-IAM-001")
    other = {**good, "compliance": None}
    _write_f3_findings(tmp_path, [other, good])
    index = build_control_index([_control(mappings=[_mapping("CSPM-AWS-IAM-001", "1.10")])])
    findings = await correlate_cloud_posture(
        cloud_posture_workspace=tmp_path,
        control_index=index,
        correlated_at=datetime(2026, 5, 21, tzinfo=UTC),
        envelope=_envelope(),
    )
    assert len(findings) == 1


@pytest.mark.asyncio
async def test_index_built_from_real_bundled_yaml_round_trips(tmp_path: Path) -> None:
    """Use the actual bundled CIS YAML; verify a real F.3 emit lights up."""
    from compliance.tools.cis_aws_benchmark import read_cis_aws_benchmark

    controls = await read_cis_aws_benchmark()
    index = build_control_index(controls)
    _write_f3_findings(tmp_path, [_f3_finding(rule_id="CSPM-AWS-IAM-001")])
    findings = await correlate_cloud_posture(
        cloud_posture_workspace=tmp_path,
        control_index=index,
        correlated_at=datetime(2026, 5, 21, tzinfo=UTC),
        envelope=_envelope(),
    )
    # CSPM-AWS-IAM-001 maps to CIS 1.10 in the bundled library.
    assert any(f.rule_id == "cis_aws_v3:1.10" for f in findings)


# ---------------------------------------------------------------------------
# A-3 native-CIS attribution (Prowler's own evidence.cis_controls)
# ---------------------------------------------------------------------------


def _f3_finding_with_cis(cis_controls: list[str], *, rule_id: str = "CSPM-AWS-NONE-999") -> dict:
    finding = _f3_finding(finding_id=f"{rule_id}-alice", rule_id=rule_id)
    finding["evidences"] = [{"prowler_check": "x", "cis_controls": cis_controls}]
    return finding


@pytest.mark.asyncio
async def test_native_cis_emits_for_catalog_control(tmp_path: Path) -> None:
    _write_f3_findings(tmp_path, [_f3_finding_with_cis(["CIS-3.0:1.10"])])
    findings = await correlate_cloud_posture(
        cloud_posture_workspace=tmp_path,
        control_index={},  # no YAML mapping → only the native pass can emit
        controls_by_id=build_control_by_id([_control("1.10")]),
        correlated_at=datetime(2026, 6, 15, tzinfo=UTC),
        envelope=_envelope(),
    )
    assert len(findings) == 1
    assert findings[0].to_dict()["compliance"]["control"].endswith("1.10")


@pytest.mark.asyncio
async def test_native_cis_ignores_wrong_version(tmp_path: Path) -> None:
    _write_f3_findings(tmp_path, [_f3_finding_with_cis(["CIS-2.0:1.10"])])
    findings = await correlate_cloud_posture(
        cloud_posture_workspace=tmp_path,
        control_index={},
        controls_by_id=build_control_by_id([_control("1.10")]),
        correlated_at=datetime(2026, 6, 15, tzinfo=UTC),
        envelope=_envelope(),
    )
    assert findings == ()


@pytest.mark.asyncio
async def test_native_cis_ignores_control_absent_from_catalog(tmp_path: Path) -> None:
    _write_f3_findings(tmp_path, [_f3_finding_with_cis(["CIS-3.0:9.99"])])
    findings = await correlate_cloud_posture(
        cloud_posture_workspace=tmp_path,
        control_index={},
        controls_by_id=build_control_by_id([_control("1.10")]),  # 9.99 not in catalog
        correlated_at=datetime(2026, 6, 15, tzinfo=UTC),
        envelope=_envelope(),
    )
    assert findings == ()


@pytest.mark.asyncio
async def test_native_cis_format_robust_underscore(tmp_path: Path) -> None:
    _write_f3_findings(tmp_path, [_f3_finding_with_cis(["cis_3.0_aws:1.10"])])
    findings = await correlate_cloud_posture(
        cloud_posture_workspace=tmp_path,
        control_index={},
        controls_by_id=build_control_by_id([_control("1.10")]),
        correlated_at=datetime(2026, 6, 15, tzinfo=UTC),
        envelope=_envelope(),
    )
    assert len(findings) == 1


@pytest.mark.asyncio
async def test_native_cis_deduped_against_yaml_pass(tmp_path: Path) -> None:
    # Finding maps to 1.10 via the YAML index AND carries native CIS-3.0:1.10 →
    # exactly ONE finding for (finding, 1.10), not two.
    rule_id = "CSPM-AWS-IAM-001"
    finding = _f3_finding(finding_id=f"{rule_id}-alice", rule_id=rule_id)
    finding["evidences"] = [{"cis_controls": ["CIS-3.0:1.10"]}]
    _write_f3_findings(tmp_path, [finding])
    control = _control("1.10", mappings=[_mapping(rule_id, "1.10")])
    findings = await correlate_cloud_posture(
        cloud_posture_workspace=tmp_path,
        control_index=build_control_index([control]),
        controls_by_id=build_control_by_id([control]),
        correlated_at=datetime(2026, 6, 15, tzinfo=UTC),
        envelope=_envelope(),
    )
    assert len(findings) == 1
