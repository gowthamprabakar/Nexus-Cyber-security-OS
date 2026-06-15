"""Checkov normalizer + OCSF 2003 emission tests (D.14 B-1 PR2)."""

from __future__ import annotations

from datetime import UTC, datetime

from appsec.normalizers.checkov_iac import checkov_to_findings
from appsec.ocsf.emission import finding_to_ocsf
from appsec.schemas import AppSecFindingType, Severity

_FAILED_CHECK = {
    "check_id": "CKV_AWS_20",
    "check_name": "S3 Bucket has an ACL defined which allows public READ access",
    "check_result": {"result": "FAILED"},
    "file_path": "/main.tf",
    "file_line_range": [1, 25],
    "resource": "aws_s3_bucket.public",
    "severity": "HIGH",
}

# Single-framework dict shape.
_DICT_PAYLOAD = {"check_type": "terraform", "results": {"failed_checks": [_FAILED_CHECK]}}
# Multi-framework list shape.
_LIST_PAYLOAD = [_DICT_PAYLOAD, {"check_type": "kubernetes", "results": {"failed_checks": []}}]


def test_normalizes_dict_shape() -> None:
    findings = checkov_to_findings(_DICT_PAYLOAD, repo_slug="github/acme/api")
    assert len(findings) == 1
    f = findings[0]
    assert f.finding_type is AppSecFindingType.IAC_MISCONFIGURATION
    assert f.rule_id == "CKV_AWS_20"
    assert f.severity is Severity.HIGH
    assert f.location == "main.tf:1"
    assert f.repo_slug == "github/acme/api"


def test_normalizes_list_shape() -> None:
    findings = checkov_to_findings(_LIST_PAYLOAD, repo_slug="github/acme/api")
    assert len(findings) == 1  # only the terraform block had a failed check


def test_missing_severity_defaults_medium() -> None:
    check = {**_FAILED_CHECK, "severity": None}
    payload = {"results": {"failed_checks": [check]}}
    assert checkov_to_findings(payload, repo_slug="r")[0].severity is Severity.MEDIUM


def test_empty_and_malformed_yield_nothing() -> None:
    assert checkov_to_findings({}, repo_slug="r") == []
    assert checkov_to_findings({"results": {}}, repo_slug="r") == []
    assert checkov_to_findings({"results": {"failed_checks": "bad"}}, repo_slug="r") == []


def test_ocsf_emission_is_2003_with_discriminator() -> None:
    finding = checkov_to_findings(_DICT_PAYLOAD, repo_slug="github/acme/api")[0]
    ocsf = finding_to_ocsf(
        finding,
        customer_id="cust",
        run_id="run-1",
        detected_at=datetime(2026, 6, 15, tzinfo=UTC),
    )
    assert ocsf["class_uid"] == 2003
    assert ocsf["finding_info"]["types"] == ["appsec_iac_misconfiguration"]
    assert ocsf["evidences"][0]["source_finding_type"] == "appsec_iac_misconfiguration"
    assert ocsf["compliance"]["control"] == "CKV_AWS_20"
    assert ocsf["severity_id"] == 4  # HIGH
    assert ocsf["resources"][0]["uid"] == "github/acme/api/main.tf:1"
