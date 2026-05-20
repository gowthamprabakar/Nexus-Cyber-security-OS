"""Tests — ``compliance.correlators.data_security_correlator`` (Task 7).

Builds in-memory D.5 ``findings.json`` fixtures using F.3's
``build_finding`` (D.5 re-uses F.3's emit shape; ``compliance.control``
carries the short D.5 rule_id like ``"s3_bucket_public"``). Asserts
the emitted D.6 ``ComplianceFinding``s + forgiving-read posture.
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
from compliance.correlators.control_index import build_control_index
from compliance.correlators.data_security_correlator import correlate_data_security
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


def _d5_envelope() -> NexusEnvelope:
    return NexusEnvelope(
        correlation_id="00000000-0000-0000-0000-00000000d5d5",
        tenant_id="acme",
        agent_id="data_security",
        nlah_version="0.1.0",
        model_pin="deterministic",
        charter_invocation_id="00000000-0000-0000-0000-000000000001",
    )


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


def _control(
    control_id: str = "2.1.4",
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
        applicability=("aws_s3",),
        description=f"Paraphrased summary for {control_id}.",
        source_mappings=tuple(mappings or []),
    )


def _mapping(rule_id: str, control_id: str) -> ControlMapping:
    return ControlMapping(
        source_agent="data_security",
        source_rule_id=rule_id,
        control_id=control_id,
        level=ControlLevel.LEVEL_1,
        required=True,
    )


def _d5_finding(
    *,
    finding_id: str = "CSPM-AWS-PUBLIC-001-company-secrets",
    rule_id: str = "s3_bucket_public",
    bucket: str = "company-secrets",
) -> dict[str, Any]:
    finding = build_cspm_finding(
        finding_id=finding_id,
        rule_id=rule_id,
        severity=CspmSeverity.HIGH,
        title=f"D.5 finding for {bucket}",
        description="x",
        affected=_d5_affected(bucket),
        detected_at=datetime(2026, 5, 21, tzinfo=UTC),
        envelope=_d5_envelope(),
    )
    return finding.to_dict()


def _write_d5_findings(workspace: Path, payloads: list[dict[str, Any]]) -> None:
    workspace.mkdir(parents=True, exist_ok=True)
    report = {
        "agent": "data_security",
        "agent_version": "0.1.0",
        "customer_id": "acme",
        "run_id": "run_d5",
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
    index = build_control_index([_control(mappings=[_mapping("s3_bucket_public", "2.1.4")])])
    findings = await correlate_data_security(
        data_security_workspace=None,
        control_index=index,
        correlated_at=datetime(2026, 5, 21, tzinfo=UTC),
        envelope=_envelope(),
    )
    assert findings == ()


@pytest.mark.asyncio
async def test_returns_empty_when_index_is_empty(tmp_path: Path) -> None:
    _write_d5_findings(tmp_path, [_d5_finding()])
    findings = await correlate_data_security(
        data_security_workspace=tmp_path,
        control_index={},
        correlated_at=datetime(2026, 5, 21, tzinfo=UTC),
        envelope=_envelope(),
    )
    assert findings == ()


@pytest.mark.asyncio
async def test_returns_empty_when_findings_json_missing(tmp_path: Path) -> None:
    index = build_control_index([_control(mappings=[_mapping("s3_bucket_public", "2.1.4")])])
    findings = await correlate_data_security(
        data_security_workspace=tmp_path,
        control_index=index,
        correlated_at=datetime(2026, 5, 21, tzinfo=UTC),
        envelope=_envelope(),
    )
    assert findings == ()


@pytest.mark.asyncio
async def test_returns_empty_when_findings_json_malformed(tmp_path: Path) -> None:
    (tmp_path / "findings.json").write_text("{nope", encoding="utf-8")
    index = build_control_index([_control(mappings=[_mapping("s3_bucket_public", "2.1.4")])])
    findings = await correlate_data_security(
        data_security_workspace=tmp_path,
        control_index=index,
        correlated_at=datetime(2026, 5, 21, tzinfo=UTC),
        envelope=_envelope(),
    )
    assert findings == ()


@pytest.mark.asyncio
async def test_returns_empty_when_no_rule_id_match(tmp_path: Path) -> None:
    _write_d5_findings(tmp_path, [_d5_finding(rule_id="s3_bucket_unencrypted")])
    index = build_control_index([_control(mappings=[_mapping("s3_bucket_public", "2.1.4")])])
    findings = await correlate_data_security(
        data_security_workspace=tmp_path,
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
    _write_d5_findings(tmp_path, [_d5_finding(rule_id="s3_bucket_public")])
    index = build_control_index([_control(mappings=[_mapping("s3_bucket_public", "2.1.4")])])
    findings = await correlate_data_security(
        data_security_workspace=tmp_path,
        control_index=index,
        correlated_at=datetime(2026, 5, 21, tzinfo=UTC),
        envelope=_envelope(),
    )
    assert len(findings) == 1
    assert findings[0].rule_id == "cis_aws_v3:2.1.4"


@pytest.mark.asyncio
async def test_one_d5_finding_maps_to_two_cis_controls_emits_two(
    tmp_path: Path,
) -> None:
    """s3_bucket_public maps to both CIS 2.1.4 (account BPA) and 2.1.5
    (per-bucket BPA) in the bundled library -> two emits."""
    _write_d5_findings(tmp_path, [_d5_finding(rule_id="s3_bucket_public")])
    index = build_control_index(
        [
            _control(
                control_id="2.1.4",
                mappings=[_mapping("s3_bucket_public", "2.1.4")],
            ),
            _control(
                control_id="2.1.5",
                mappings=[_mapping("s3_bucket_public", "2.1.5")],
            ),
        ]
    )
    findings = await correlate_data_security(
        data_security_workspace=tmp_path,
        control_index=index,
        correlated_at=datetime(2026, 5, 21, tzinfo=UTC),
        envelope=_envelope(),
    )
    assert len(findings) == 2
    rule_ids = {f.rule_id for f in findings}
    assert rule_ids == {"cis_aws_v3:2.1.4", "cis_aws_v3:2.1.5"}


@pytest.mark.asyncio
async def test_finding_id_carries_d5_provenance_hash(tmp_path: Path) -> None:
    _write_d5_findings(
        tmp_path,
        [_d5_finding(finding_id="CSPM-AWS-PUBLIC-002-x", rule_id="s3_bucket_public")],
    )
    index = build_control_index([_control(mappings=[_mapping("s3_bucket_public", "2.1.4")])])
    findings = await correlate_data_security(
        data_security_workspace=tmp_path,
        control_index=index,
        correlated_at=datetime(2026, 5, 21, tzinfo=UTC),
        envelope=_envelope(),
    )
    fid = findings[0].finding_id
    assert fid.startswith("COMPLIANCE-CIS_AWS_V3-2_1_4-001-")
    # D.5 correlator stamps `d5_<hash>` in the context (not f3_).
    assert "d5_" in fid
    assert "f3_" not in fid


@pytest.mark.asyncio
async def test_d5_resources_projected_into_compliance_finding(
    tmp_path: Path,
) -> None:
    _write_d5_findings(
        tmp_path, [_d5_finding(rule_id="s3_bucket_public", bucket="company-secrets")]
    )
    index = build_control_index([_control(mappings=[_mapping("s3_bucket_public", "2.1.4")])])
    findings = await correlate_data_security(
        data_security_workspace=tmp_path,
        control_index=index,
        correlated_at=datetime(2026, 5, 21, tzinfo=UTC),
        envelope=_envelope(),
    )
    resources = findings[0].resources
    assert len(resources) == 1
    assert resources[0]["type"] == "aws_s3_bucket"
    assert resources[0]["uid"] == "arn:aws:s3:::company-secrets"


@pytest.mark.asyncio
async def test_evidence_carries_data_security_provenance(tmp_path: Path) -> None:
    _write_d5_findings(
        tmp_path,
        [_d5_finding(finding_id="CSPM-AWS-PUBLIC-003-secrets", rule_id="s3_bucket_public")],
    )
    index = build_control_index([_control(mappings=[_mapping("s3_bucket_public", "2.1.4")])])
    findings = await correlate_data_security(
        data_security_workspace=tmp_path,
        control_index=index,
        correlated_at=datetime(2026, 5, 21, tzinfo=UTC),
        envelope=_envelope(),
    )
    ev = findings[0].to_dict()["evidences"][0]
    assert ev["source_finding"]["agent"] == "data_security"
    assert ev["source_finding"]["finding_id"] == "CSPM-AWS-PUBLIC-003-secrets"
    assert ev["source_finding"]["rule_id"] == "s3_bucket_public"
    assert ev["control"]["framework"] == "cis_aws_v3"
    assert ev["control"]["control_id"] == "2.1.4"


@pytest.mark.asyncio
async def test_severity_table_drives_emit_severity(tmp_path: Path) -> None:
    """Level 1 + required -> HIGH; Level 2 + recommended -> LOW."""
    from compliance.schemas import Severity

    _write_d5_findings(
        tmp_path,
        [
            _d5_finding(finding_id="CSPM-AWS-PUBLIC-004-a", rule_id="s3_bucket_public"),
            _d5_finding(
                finding_id="CSPM-AWS-SENSLOC-005-b",
                rule_id="s3_object_sensitive_in_untrusted_location",
            ),
        ],
    )
    index = build_control_index(
        [
            _control(
                control_id="2.1.4",
                level=ControlLevel.LEVEL_1,
                required=True,
                mappings=[
                    ControlMapping(
                        source_agent="data_security",
                        source_rule_id="s3_bucket_public",
                        control_id="2.1.4",
                        level=ControlLevel.LEVEL_1,
                        required=True,
                    )
                ],
            ),
            _control(
                control_id="2.1.7",
                level=ControlLevel.LEVEL_2,
                required=False,
                mappings=[
                    ControlMapping(
                        source_agent="data_security",
                        source_rule_id="s3_object_sensitive_in_untrusted_location",
                        control_id="2.1.7",
                        level=ControlLevel.LEVEL_2,
                        required=False,
                    )
                ],
            ),
        ]
    )
    findings = await correlate_data_security(
        data_security_workspace=tmp_path,
        control_index=index,
        correlated_at=datetime(2026, 5, 21, tzinfo=UTC),
        envelope=_envelope(),
    )
    by_rule = {f.rule_id: f for f in findings}
    assert by_rule["cis_aws_v3:2.1.4"].severity == Severity.HIGH
    assert by_rule["cis_aws_v3:2.1.7"].severity == Severity.LOW


@pytest.mark.asyncio
async def test_non_2003_entries_skipped(tmp_path: Path) -> None:
    good = _d5_finding(rule_id="s3_bucket_public")
    other = {**good, "class_uid": 2004}
    _write_d5_findings(tmp_path, [other, good])
    index = build_control_index([_control(mappings=[_mapping("s3_bucket_public", "2.1.4")])])
    findings = await correlate_data_security(
        data_security_workspace=tmp_path,
        control_index=index,
        correlated_at=datetime(2026, 5, 21, tzinfo=UTC),
        envelope=_envelope(),
    )
    assert len(findings) == 1


@pytest.mark.asyncio
async def test_entries_with_missing_compliance_block_skipped(tmp_path: Path) -> None:
    good = _d5_finding(rule_id="s3_bucket_public")
    other = {**good, "compliance": None}
    _write_d5_findings(tmp_path, [other, good])
    index = build_control_index([_control(mappings=[_mapping("s3_bucket_public", "2.1.4")])])
    findings = await correlate_data_security(
        data_security_workspace=tmp_path,
        control_index=index,
        correlated_at=datetime(2026, 5, 21, tzinfo=UTC),
        envelope=_envelope(),
    )
    assert len(findings) == 1


@pytest.mark.asyncio
async def test_sequence_increments_across_emits(tmp_path: Path) -> None:
    _write_d5_findings(
        tmp_path,
        [
            _d5_finding(finding_id="CSPM-AWS-PUBLIC-004-a", rule_id="s3_bucket_public"),
            _d5_finding(finding_id="CSPM-AWS-SENSLOC-005-b", rule_id="s3_bucket_public"),
        ],
    )
    index = build_control_index([_control(mappings=[_mapping("s3_bucket_public", "2.1.4")])])
    findings = await correlate_data_security(
        data_security_workspace=tmp_path,
        control_index=index,
        correlated_at=datetime(2026, 5, 21, tzinfo=UTC),
        envelope=_envelope(),
    )
    seqs = [f.finding_id.split("-")[3] for f in findings]
    assert seqs == ["001", "002"]


@pytest.mark.asyncio
async def test_bundled_yaml_round_trip(tmp_path: Path) -> None:
    """Real bundled CIS YAML; s3_bucket_public lights up CIS 2.1.4 + 2.1.5."""
    from compliance.tools.cis_aws_benchmark import read_cis_aws_benchmark

    controls = await read_cis_aws_benchmark()
    index = build_control_index(controls)
    _write_d5_findings(tmp_path, [_d5_finding(rule_id="s3_bucket_public")])
    findings = await correlate_data_security(
        data_security_workspace=tmp_path,
        control_index=index,
        correlated_at=datetime(2026, 5, 21, tzinfo=UTC),
        envelope=_envelope(),
    )
    rule_ids = {f.rule_id for f in findings}
    assert "cis_aws_v3:2.1.4" in rule_ids
    assert "cis_aws_v3:2.1.5" in rule_ids
