"""Tests for the OCSF v1.3 Detection Finding (class_uid 2004) — Identity flavor."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from identity.schemas import (
    CVE_NA,
    FINDING_ID_RE,
    OCSF_CATEGORY_UID,
    OCSF_CLASS_UID,
    AffectedPrincipal,
    FindingsReport,
    FindingType,
    IdentityFinding,
    Severity,
    build_finding,
    severity_from_id,
    severity_to_id,
)
from shared.fabric.envelope import NexusEnvelope


def _envelope() -> NexusEnvelope:
    return NexusEnvelope(
        correlation_id="01J7M3X9Z1K8RPVQNH2T8SMKZ1",
        tenant_id="cust_test",
        agent_id="identity",
        nlah_version="0.1.0",
        model_pin="deterministic",
        charter_invocation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
    )


def _principal(*, name: str = "alice", arn: str | None = None) -> AffectedPrincipal:
    return AffectedPrincipal(
        principal_type="User",
        principal_name=name,
        arn=arn or f"arn:aws:iam::111122223333:user/{name}",
        account_id="111122223333",
        last_used_at=datetime(2026, 5, 1, tzinfo=UTC),
    )


# ---------------------------- OCSF class constants -----------------------


def test_ocsf_class_constants_are_2004_detection() -> None:
    """Q1 resolution: class_uid 2004 Detection Finding (not 2003 Compliance)."""
    assert OCSF_CLASS_UID == 2004
    assert OCSF_CATEGORY_UID == 2  # Findings


# ---------------------------- Severity round-trip ------------------------


def test_severity_round_trip_for_each_id() -> None:
    for sev in Severity:
        sid = severity_to_id(sev)
        assert severity_from_id(sid) is sev


def test_severity_id_6_collapses_to_critical() -> None:
    assert severity_from_id(6) is Severity.CRITICAL


def test_severity_from_id_rejects_unknown() -> None:
    with pytest.raises(ValueError, match="unknown OCSF severity_id"):
        severity_from_id(99)


# ---------------------------- FindingType enum ---------------------------


def test_finding_type_has_five_buckets() -> None:
    assert {ft.value for ft in FindingType} == {
        "overprivilege",
        "dormant",
        "external_access",
        "mfa_gap",
        "admin_path",
    }


# ---------------------------- AffectedPrincipal --------------------------


def test_affected_principal_to_ocsf_round_trip() -> None:
    p = _principal()
    ocsf = p.to_ocsf()
    assert ocsf["type"] == "User"
    assert ocsf["name"] == "alice"
    assert ocsf["uid"] == p.arn
    assert ocsf["account"]["uid"] == "111122223333"


def test_affected_principal_rejects_blank_arn() -> None:
    with pytest.raises(ValueError):
        AffectedPrincipal(
            principal_type="User",
            principal_name="x",
            arn="",
            account_id="111122223333",
            last_used_at=None,
        )


# ---------------------------- finding_id regex ---------------------------


def test_finding_id_regex_matches_canonical_shapes() -> None:
    assert FINDING_ID_RE.match("IDENT-OVERPRIV-AROAUSER123ABC-001-iam_admin")
    assert FINDING_ID_RE.match("IDENT-DORMANT-AIDAUSER1ABC-002-200_days")
    assert FINDING_ID_RE.match("IDENT-EXTERNAL-ROLE12345-003-cross-account")
    assert FINDING_ID_RE.match("IDENT-MFA-USR123-004-admin_no_mfa")
    # Wrong prefix.
    assert not FINDING_ID_RE.match("CSPM-AWS-S3-001-x")
    # Unknown finding type.
    assert not FINDING_ID_RE.match("IDENT-WHATEVER-USR-001-x")
    # Missing context suffix.
    assert not FINDING_ID_RE.match("IDENT-OVERPRIV-USR-001")


# ---------------------------- build_finding -----------------------------


def test_build_finding_yields_class_uid_2004() -> None:
    finding = build_finding(
        finding_id="IDENT-OVERPRIV-USR123-001-iam_admin_attached",
        finding_type=FindingType.OVERPRIVILEGE,
        severity=Severity.HIGH,
        title="alice has AdministratorAccess",
        description="User alice has the AWS-managed AdministratorAccess policy attached.",
        affected_principals=[_principal()],
        evidence={"attached_policies": ["arn:aws:iam::aws:policy/AdministratorAccess"]},
        detected_at=datetime.now(UTC),
        envelope=_envelope(),
    )
    payload = finding.to_dict()
    assert payload["class_uid"] == 2004
    assert payload["category_uid"] == 2
    assert payload["severity_id"] == 4  # high


def test_build_finding_attaches_envelope() -> None:
    env = _envelope()
    finding = build_finding(
        finding_id="IDENT-DORMANT-USR-001-stale",
        finding_type=FindingType.DORMANT,
        severity=Severity.MEDIUM,
        title="x",
        description="y",
        affected_principals=[_principal()],
        evidence={"days_dormant": 200},
        detected_at=datetime.now(UTC),
        envelope=env,
    )
    assert finding.envelope == env


def test_build_finding_requires_at_least_one_principal() -> None:
    with pytest.raises(ValueError, match="affected_principals"):
        build_finding(
            finding_id="IDENT-OVERPRIV-USR-001-x",
            finding_type=FindingType.OVERPRIVILEGE,
            severity=Severity.HIGH,
            title="x",
            description="y",
            affected_principals=[],
            evidence={},
            detected_at=datetime.now(UTC),
            envelope=_envelope(),
        )


def test_build_finding_rejects_invalid_finding_id() -> None:
    with pytest.raises(ValueError, match="finding_id"):
        build_finding(
            finding_id="NOT-VALID",
            finding_type=FindingType.OVERPRIVILEGE,
            severity=Severity.HIGH,
            title="x",
            description="y",
            affected_principals=[_principal()],
            evidence={},
            detected_at=datetime.now(UTC),
            envelope=_envelope(),
        )


# ---------------------------- IdentityFinding wrapper --------------------


def test_finding_wrapper_validates_class_uid() -> None:
    with pytest.raises(ValueError, match="class_uid"):
        IdentityFinding({"class_uid": 9999, "finding_info": {"uid": "x"}})


def test_finding_wrapper_exposes_finding_type_and_principals() -> None:
    finding = build_finding(
        finding_id="IDENT-EXTERNAL-ROLE123-001-cross_account",
        finding_type=FindingType.EXTERNAL_ACCESS,
        severity=Severity.HIGH,
        title="cross-account assume role",
        description="z",
        affected_principals=[_principal(name="bob")],
        evidence={"trusts": ["arn:aws:iam::999988887777:root"]},
        detected_at=datetime.now(UTC),
        envelope=_envelope(),
    )
    assert finding.finding_type is FindingType.EXTERNAL_ACCESS
    assert finding.severity is Severity.HIGH
    assert finding.principal_arns == [_principal(name="bob").arn]


# ---------------------------- FindingsReport -----------------------------


def test_findings_report_aggregates_severity_and_finding_type() -> None:
    env = _envelope()
    now = datetime.now(UTC)
    report = FindingsReport(
        agent="identity",
        agent_version="0.1.0",
        customer_id="cust_test",
        run_id="run_1",
        scan_started_at=now,
        scan_completed_at=now,
    )

    overpriv = build_finding(
        finding_id="IDENT-OVERPRIV-USR123-001-admin",
        finding_type=FindingType.OVERPRIVILEGE,
        severity=Severity.CRITICAL,
        title="x",
        description="y",
        affected_principals=[_principal()],
        evidence={},
        detected_at=now,
        envelope=env,
    )
    dormant = build_finding(
        finding_id="IDENT-DORMANT-USR456-002-stale",
        finding_type=FindingType.DORMANT,
        severity=Severity.MEDIUM,
        title="x",
        description="y",
        affected_principals=[_principal(name="dormant_user")],
        evidence={"days_dormant": 200},
        detected_at=now,
        envelope=env,
    )
    report.add_finding(overpriv)
    report.add_finding(dormant)

    assert report.total == 2
    sev = report.count_by_severity()
    assert sev["critical"] == 1
    assert sev["medium"] == 1

    by_type = report.count_by_finding_type()
    assert by_type["overprivilege"] == 1
    assert by_type["dormant"] == 1
    assert by_type["external_access"] == 0


def test_findings_report_empty_buckets_when_no_findings() -> None:
    now = datetime.now(UTC)
    report = FindingsReport(
        agent="identity",
        agent_version="0.1.0",
        customer_id="cust_test",
        run_id="run_1",
        scan_started_at=now,
        scan_completed_at=now,
    )
    sev = report.count_by_severity()
    assert all(v == 0 for v in sev.values())

    by_type = report.count_by_finding_type()
    assert all(v == 0 for v in by_type.values())
    assert set(by_type.keys()) == {ft.value for ft in FindingType}


# ---------------------------- spurious export sanity ---------------------


def test_cve_na_constant_exists() -> None:
    """The schema reuses some constants from the family; CVE_NA marks 'not applicable' for non-vuln findings."""
    assert CVE_NA == "CVE-NA"
