"""Tests for the SSPM OCSF 2003 schemas (D.10 PR1)."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from shared.fabric.envelope import unwrap_ocsf
from sspm.schemas import (
    FindingsReport,
    NexusEnvelope,
    SaaSAffectedResource,
    Severity,
    build_finding,
)

_NOW = datetime(2026, 6, 17, 12, 0, 0, tzinfo=UTC)


def _envelope() -> NexusEnvelope:
    return NexusEnvelope(
        correlation_id="corr-1",
        tenant_id="cust_test",
        agent_id="sspm",
        nlah_version="0.1.0",
        model_pin="deterministic",
        charter_invocation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
    )


def _finding(*, finding_id: str = "SSPM-GITHUB-001-acme-org"):
    return build_finding(
        finding_id=finding_id,
        rule_id="GH-ORG-2FA",
        finding_type="sspm_github_org_2fa_disabled",
        severity=Severity.HIGH,
        title="Org 2FA not enforced",
        description="The GitHub org does not require two-factor auth.",
        affected=[
            SaaSAffectedResource(
                provider="github",
                tenant_id="acme",
                resource_type="saas_tenant",
                resource_id="acme",
            )
        ],
        detected_at=_NOW,
        envelope=_envelope(),
    )


def test_build_finding_is_valid_ocsf_2003() -> None:
    f = _finding()
    d = f.to_dict()
    assert d["class_uid"] == 2003
    assert d["finding_info"]["uid"] == "SSPM-GITHUB-001-acme-org"
    assert d["finding_info"]["types"] == ["sspm_github_org_2fa_disabled"]
    assert d["resources"][0]["uid"] == "github:acme:acme"
    # Envelope is present + well-formed.
    _, env = unwrap_ocsf(d)
    assert env.tenant_id == "cust_test"
    # Typed accessors.
    assert f.severity is Severity.HIGH
    assert f.finding_type == "sspm_github_org_2fa_disabled"
    assert f.rule_id == "GH-ORG-2FA"


def test_bad_finding_id_rejected() -> None:
    with pytest.raises(ValueError, match="finding_id must match"):
        _finding(finding_id="not-a-valid-id")


def test_empty_finding_type_rejected() -> None:
    with pytest.raises(ValueError, match="finding_type"):
        build_finding(
            finding_id="SSPM-GITHUB-001-acme-org",
            rule_id="GH-ORG-2FA",
            finding_type="",
            severity=Severity.HIGH,
            title="t",
            description="d",
            affected=[
                SaaSAffectedResource(
                    provider="github", tenant_id="a", resource_type="saas_tenant", resource_id="a"
                )
            ],
            detected_at=_NOW,
            envelope=_envelope(),
        )


def test_empty_affected_rejected() -> None:
    with pytest.raises(ValueError, match="affected resources"):
        build_finding(
            finding_id="SSPM-GITHUB-001-acme-org",
            rule_id="GH-ORG-2FA",
            finding_type="sspm_github_org_2fa_disabled",
            severity=Severity.HIGH,
            title="t",
            description="d",
            affected=[],
            detected_at=_NOW,
            envelope=_envelope(),
        )


def test_report_add_and_count() -> None:
    report = FindingsReport(
        agent="sspm",
        agent_version="0.1.0",
        customer_id="cust_test",
        run_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
        scan_started_at=_NOW,
        scan_completed_at=_NOW,
    )
    report.add_finding(_finding())
    assert report.total == 1
    assert report.count_by_severity()["high"] == 1
    assert report.count_by_severity()["critical"] == 0
