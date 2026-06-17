"""Tests — ``compliance.schemas`` (Task 2).

Verifies the F.3 schema re-export (Q1) and the D.9-specific
additions: finding-id regex, framework + control-level enums,
type-discriminator builder, canonical severity-for-level table,
``build_finding`` constructor, and the ``ComplianceFinding`` typed
wrapper. The wrapper validates class_uid == 2003, finding-id regex,
and envelope shape on construction.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest
from compliance.schemas import (
    COMPLIANCE_FINDING_ID_RE,
    OCSF_CATEGORY_UID,
    OCSF_CLASS_NAME,
    OCSF_CLASS_UID,
    OCSF_VERSION,
    AffectedResource,
    ComplianceFinding,
    ComplianceFramework,
    ControlLevel,
    ControlMapping,
    FindingsReport,
    Severity,
    build_finding,
    compliance_finding_type,
    compliance_type_token,
    severity_for_level,
    severity_from_id,
    severity_to_id,
)
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


def _affected() -> list[AffectedResource]:
    return [
        AffectedResource(
            cloud="aws",
            account_id="123456789012",
            region="us-east-1",
            resource_type="aws_iam_user",
            resource_id="alice",
            arn="arn:aws:iam::123456789012:user/alice",
        )
    ]


# ---------------------------------------------------------------------------
# OCSF constants (F.3 re-export verbatim)
# ---------------------------------------------------------------------------


def test_ocsf_constants_match_f3() -> None:
    assert OCSF_CLASS_UID == 2003
    assert OCSF_CLASS_NAME == "Compliance Finding"
    assert OCSF_CATEGORY_UID == 2
    assert OCSF_VERSION == "1.3.0"


def test_severity_round_trip() -> None:
    for s in Severity:
        assert severity_from_id(severity_to_id(s)) == s


def test_affected_resource_to_ocsf_shape() -> None:
    a = _affected()[0]
    ocsf = a.to_ocsf()
    assert ocsf["type"] == "aws_iam_user"
    assert ocsf["uid"] == "arn:aws:iam::123456789012:user/alice"
    assert ocsf["cloud_partition"] == "aws"
    assert ocsf["region"] == "us-east-1"
    assert ocsf["owner"]["account_uid"] == "123456789012"


def test_findings_report_round_trip() -> None:
    report = FindingsReport(
        agent="compliance",
        agent_version="0.1.0",
        customer_id="acme",
        run_id="run_1",
        scan_started_at=datetime(2026, 5, 21, tzinfo=UTC),
        scan_completed_at=datetime(2026, 5, 21, tzinfo=UTC),
    )
    assert report.total == 0
    counts = report.count_by_severity()
    assert counts == {s.value: 0 for s in Severity}


# ---------------------------------------------------------------------------
# Finding-id regex
# ---------------------------------------------------------------------------


def test_finding_id_regex_accepts_canonical_cis_aws_v3_shape() -> None:
    assert COMPLIANCE_FINDING_ID_RE.match("COMPLIANCE-CIS_AWS_V3-1_1-001-iam_admin")
    assert COMPLIANCE_FINDING_ID_RE.match("COMPLIANCE-CIS_AWS_V3-2_1_5-042-s3_public_bucket")


def test_finding_id_regex_rejects_lowercase_framework() -> None:
    assert not COMPLIANCE_FINDING_ID_RE.match("COMPLIANCE-cis_aws_v3-1_1-001-iam_admin")


def test_finding_id_regex_rejects_wrong_prefix() -> None:
    assert not COMPLIANCE_FINDING_ID_RE.match("CSPM-CIS_AWS_V3-1_1-001-iam_admin")


def test_finding_id_regex_rejects_short_sequence() -> None:
    assert not COMPLIANCE_FINDING_ID_RE.match("COMPLIANCE-CIS_AWS_V3-1_1-1-iam_admin")


# ---------------------------------------------------------------------------
# Framework + control-level enums + discriminator builders
# ---------------------------------------------------------------------------


def test_framework_enum_carries_full_cis_family_in_v0_2() -> None:
    # v0.2 §Q2: the full CIS family (additive vs v0.1's CIS_AWS_V3-only).
    assert {f.value for f in ComplianceFramework} == {
        "cis_aws_v3",
        "cis_azure_v2",
        "cis_gcp_v2",
        "cis_k8s_v18",
    }


def test_compliance_type_token_for_cis_aws_v3() -> None:
    assert compliance_type_token(ComplianceFramework.CIS_AWS_V3) == "CIS_AWS_V3"
    assert compliance_type_token(ComplianceFramework.CIS_K8S_V18) == "CIS_K8S_V18"


def test_compliance_finding_type_builds_stable_discriminator() -> None:
    assert (
        compliance_finding_type(ComplianceFramework.CIS_AWS_V3, "1.1")
        == "compliance_cis_aws_v3_1_1"
    )
    assert (
        compliance_finding_type(ComplianceFramework.CIS_AWS_V3, "2.1.5")
        == "compliance_cis_aws_v3_2_1_5"
    )


def test_control_level_enum_values() -> None:
    assert ControlLevel.LEVEL_1.value == "level_1"
    assert ControlLevel.LEVEL_2.value == "level_2"


# ---------------------------------------------------------------------------
# Canonical severity table (Q9 source of truth)
# ---------------------------------------------------------------------------


def test_severity_for_level_1_required_is_high() -> None:
    assert severity_for_level(ControlLevel.LEVEL_1, required=True) == Severity.HIGH


def test_severity_for_level_1_recommended_is_medium() -> None:
    assert severity_for_level(ControlLevel.LEVEL_1, required=False) == Severity.MEDIUM


def test_severity_for_level_2_required_is_medium() -> None:
    assert severity_for_level(ControlLevel.LEVEL_2, required=True) == Severity.MEDIUM


def test_severity_for_level_2_recommended_is_low() -> None:
    assert severity_for_level(ControlLevel.LEVEL_2, required=False) == Severity.LOW


# ---------------------------------------------------------------------------
# ControlMapping pydantic model
# ---------------------------------------------------------------------------


def test_control_mapping_defaults_required_to_true() -> None:
    m = ControlMapping(
        source_agent="cloud_posture",
        source_rule_id="iam_root_mfa_disabled",
        control_id="1.1",
        level=ControlLevel.LEVEL_1,
    )
    assert m.required is True


def test_control_mapping_carries_full_shape() -> None:
    m = ControlMapping(
        source_agent="data_security",
        source_rule_id="public_bucket",
        control_id="2.1.5",
        level=ControlLevel.LEVEL_2,
        required=False,
    )
    assert m.source_agent == "data_security"
    assert m.source_rule_id == "public_bucket"
    assert m.control_id == "2.1.5"
    assert m.level == ControlLevel.LEVEL_2
    assert m.required is False


# ---------------------------------------------------------------------------
# build_finding + ComplianceFinding wrapper
# ---------------------------------------------------------------------------


def test_build_finding_yields_class_uid_2003() -> None:
    finding = build_finding(
        finding_id="COMPLIANCE-CIS_AWS_V3-1_1-001-iam_root_mfa",
        framework=ComplianceFramework.CIS_AWS_V3,
        control_id="1.1",
        severity=Severity.HIGH,
        title="CIS 1.1 — Root MFA must be enabled",
        description="x",
        affected=_affected(),
        detected_at=datetime(2026, 5, 21, tzinfo=UTC),
        envelope=_envelope(),
    )
    payload = finding.to_dict()
    assert payload["class_uid"] == 2003
    assert payload["category_uid"] == 2
    assert payload["compliance"]["control"] == "cis_aws_v3:1.1"
    assert payload["compliance"]["status_id"] == 2  # OCSF compliance Failed


def test_build_finding_finding_info_types_carries_discriminator() -> None:
    finding = build_finding(
        finding_id="COMPLIANCE-CIS_AWS_V3-2_1_5-001-s3_public",
        framework=ComplianceFramework.CIS_AWS_V3,
        control_id="2.1.5",
        severity=Severity.HIGH,
        title="x",
        description="y",
        affected=_affected(),
        detected_at=datetime(2026, 5, 21, tzinfo=UTC),
        envelope=_envelope(),
    )
    assert finding.finding_type == "compliance_cis_aws_v3_2_1_5"


def test_build_finding_rule_id_is_framework_colon_control() -> None:
    finding = build_finding(
        finding_id="COMPLIANCE-CIS_AWS_V3-1_1-001-iam_root_mfa",
        framework=ComplianceFramework.CIS_AWS_V3,
        control_id="1.1",
        severity=Severity.HIGH,
        title="x",
        description="y",
        affected=_affected(),
        detected_at=datetime(2026, 5, 21, tzinfo=UTC),
        envelope=_envelope(),
    )
    assert finding.rule_id == "cis_aws_v3:1.1"


def test_build_finding_attaches_envelope_unchanged() -> None:
    env = _envelope("contoso")
    finding = build_finding(
        finding_id="COMPLIANCE-CIS_AWS_V3-1_1-001-iam_root_mfa",
        framework=ComplianceFramework.CIS_AWS_V3,
        control_id="1.1",
        severity=Severity.HIGH,
        title="x",
        description="y",
        affected=_affected(),
        detected_at=datetime(2026, 5, 21, tzinfo=UTC),
        envelope=env,
    )
    assert finding.envelope.tenant_id == "contoso"


def test_build_finding_rejects_bad_finding_id() -> None:
    with pytest.raises(ValueError, match="finding_id must match"):
        build_finding(
            finding_id="bogus",
            framework=ComplianceFramework.CIS_AWS_V3,
            control_id="1.1",
            severity=Severity.HIGH,
            title="x",
            description="y",
            affected=_affected(),
            detected_at=datetime(2026, 5, 21, tzinfo=UTC),
            envelope=_envelope(),
        )


def test_build_finding_rejects_empty_affected_list() -> None:
    with pytest.raises(ValueError, match="affected resources"):
        build_finding(
            finding_id="COMPLIANCE-CIS_AWS_V3-1_1-001-iam_root_mfa",
            framework=ComplianceFramework.CIS_AWS_V3,
            control_id="1.1",
            severity=Severity.HIGH,
            title="x",
            description="y",
            affected=[],
            detected_at=datetime(2026, 5, 21, tzinfo=UTC),
            envelope=_envelope(),
        )


def test_build_finding_resources_round_trip() -> None:
    finding = build_finding(
        finding_id="COMPLIANCE-CIS_AWS_V3-1_1-001-iam_root_mfa",
        framework=ComplianceFramework.CIS_AWS_V3,
        control_id="1.1",
        severity=Severity.HIGH,
        title="x",
        description="y",
        affected=_affected(),
        detected_at=datetime(2026, 5, 21, tzinfo=UTC),
        envelope=_envelope(),
    )
    resources = finding.resources
    assert len(resources) == 1
    assert resources[0]["type"] == "aws_iam_user"
    assert resources[0]["uid"] == "arn:aws:iam::123456789012:user/alice"


def test_compliance_finding_wrapper_rejects_wrong_class_uid() -> None:
    bad_payload: dict[str, Any] = {
        "class_uid": 2002,
        "finding_info": {"uid": "COMPLIANCE-CIS_AWS_V3-1_1-001-iam_root_mfa"},
    }
    with pytest.raises(ValueError, match="class_uid"):
        ComplianceFinding(bad_payload)


def test_compliance_finding_wrapper_rejects_bad_finding_id() -> None:
    bad_payload: dict[str, Any] = {
        "class_uid": 2003,
        "finding_info": {"uid": "garbage"},
    }
    with pytest.raises(ValueError, match="finding_id must match"):
        ComplianceFinding(bad_payload)


# ---------------------------------------------------------------------------
# Severity / severity_id sanity
# ---------------------------------------------------------------------------


def test_build_finding_severity_id_round_trip() -> None:
    finding = build_finding(
        finding_id="COMPLIANCE-CIS_AWS_V3-1_1-001-iam_root_mfa",
        framework=ComplianceFramework.CIS_AWS_V3,
        control_id="1.1",
        severity=Severity.HIGH,
        title="x",
        description="y",
        affected=_affected(),
        detected_at=datetime(2026, 5, 21, tzinfo=UTC),
        envelope=_envelope(),
    )
    payload = finding.to_dict()
    assert int(payload["severity_id"]) == 4  # HIGH
    assert finding.severity == Severity.HIGH
