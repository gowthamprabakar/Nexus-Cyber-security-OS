"""A-3 (v0.3, option B) — dual-shape Prowler parsing + native CIS extraction.

Verifies that ``_finding_from_prowler`` parses the REAL Prowler json-ocsf shape
(metadata.event_code / resources[].uid / cloud.account.uid / unmapped.compliance)
AND keeps the existing simplified-shape fixtures byte-identical, and that native
CIS attribution is surfaced from ``unmapped.compliance`` without any hardcoded map.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

from charter.contract import BudgetSpec, ExecutionContract
from cloud_posture.agent import _finding_from_prowler
from cloud_posture.prowler_compliance import aggregate_cis_coverage, extract_cis_controls

# Real Prowler 5.x json-ocsf finding (per official schema).
_OCSF_FINDING = {
    "metadata": {"event_code": "iam_user_hardware_mfa_enabled", "product": {"name": "Prowler"}},
    "severity": "High",
    "status_code": "FAIL",
    "finding_info": {
        "title": "Ensure hardware MFA is enabled for the root user",
        "uid": "prowler-aws-iam_user_hardware_mfa_enabled-111122223333-us-east-1-root",
    },
    "resources": [
        {
            "uid": "arn:aws:iam::111122223333:user/alice",
            "type": "AwsIamUser",
            "region": "us-east-1",
        }
    ],
    "cloud": {"account": {"uid": "111122223333"}, "region": "us-east-1"},
    "unmapped": {
        "compliance": {
            "CIS-3.0": ["1.10", "1.6"],
            "MITRE-ATTACK": ["T1078"],
            "AWS-Foundational-Security-Best-Practices": ["iam"],
        }
    },
}

# Legacy simplified-shape finding (what the existing fixtures use).
_LEGACY_FINDING = {
    "CheckID": "iam_user_no_mfa",
    "Severity": "high",
    "Status": "FAIL",
    "ResourceArn": "arn:aws:iam::111122223333:user/bob",
    "ResourceType": "AwsIamUser",
    "Region": "us-east-1",
    "AccountId": "111122223333",
    "StatusExtended": "User bob has no MFA",
}


def _contract(tmp_path: Path) -> ExecutionContract:
    return ExecutionContract(
        schema_version="0.1",
        delegation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
        source_agent="supervisor",
        target_agent="cloud_posture",
        customer_id="cust_test",
        task="Scan",
        required_outputs=["findings.json", "summary.md"],
        budget=BudgetSpec(
            llm_calls=5, tokens=10_000, wall_clock_sec=60.0, cloud_api_calls=500, mb_written=10
        ),
        permitted_tools=["prowler_scan"],
        completion_condition="findings.json AND summary.md exist",
        escalation_rules=[],
        workspace=str(tmp_path / "ws"),
        persistent_root=str(tmp_path / "p"),
        created_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )


# --- native CIS extraction --------------------------------------------------


def test_extract_cis_controls_from_unmapped() -> None:
    assert extract_cis_controls(_OCSF_FINDING) == ("CIS-3.0:1.10", "CIS-3.0:1.6")


def test_extract_cis_ignores_non_cis_frameworks() -> None:
    controls = extract_cis_controls(_OCSF_FINDING)
    assert all(c.startswith("CIS") for c in controls)
    assert not any("MITRE" in c or "AWS-Foundational" in c for c in controls)


def test_extract_cis_absent_is_empty() -> None:
    assert extract_cis_controls(_LEGACY_FINDING) == ()
    assert extract_cis_controls({"unmapped": {}}) == ()
    assert extract_cis_controls({"unmapped": {"compliance": "bad"}}) == ()


# --- dual-shape parsing -----------------------------------------------------


def test_ocsf_shape_parses_and_carries_cis(tmp_path: Path) -> None:
    finding = _finding_from_prowler(_OCSF_FINDING, contract=_contract(tmp_path), model_pin="x")
    assert finding is not None
    payload = finding.to_dict()
    affected = payload["resources"][0]
    assert affected["uid"] == "arn:aws:iam::111122223333:user/alice"
    assert affected["owner"]["account_uid"] == "111122223333"
    evidence = payload["evidences"][0]
    assert evidence["prowler_check"] == "iam_user_hardware_mfa_enabled"
    assert evidence["cis_controls"] == ["CIS-3.0:1.10", "CIS-3.0:1.6"]
    assert payload["finding_info"]["title"] == "Ensure hardware MFA is enabled for the root user"


def test_cis_coverage_aggregates_native_controls(tmp_path: Path) -> None:
    f1 = _finding_from_prowler(_OCSF_FINDING, contract=_contract(tmp_path), model_pin="x")
    f2 = _finding_from_prowler(_OCSF_FINDING, contract=_contract(tmp_path), model_pin="x")
    assert f1 is not None and f2 is not None
    coverage = aggregate_cis_coverage([f1.to_dict(), f2.to_dict()])
    # Distinct controls de-duped across findings; grouped by framework.
    assert coverage["total_controls_covered"] == 2
    assert coverage["controls"] == ["CIS-3.0:1.10", "CIS-3.0:1.6"]
    assert coverage["by_framework"]["CIS-3.0"] == ["1.10", "1.6"]


def test_cis_coverage_empty_without_native_cis(tmp_path: Path) -> None:
    f = _finding_from_prowler(_LEGACY_FINDING, contract=_contract(tmp_path), model_pin="x")
    assert f is not None
    coverage = aggregate_cis_coverage([f.to_dict()])
    assert coverage["total_controls_covered"] == 0
    assert coverage["by_framework"] == {}


def test_legacy_shape_still_parses_without_cis(tmp_path: Path) -> None:
    finding = _finding_from_prowler(_LEGACY_FINDING, contract=_contract(tmp_path), model_pin="x")
    assert finding is not None
    payload = finding.to_dict()
    assert payload["resources"][0]["uid"] == "arn:aws:iam::111122223333:user/bob"
    # mapped check → stable rule_id (not a synthetic hash)
    assert payload["compliance"]["control"] == "CSPM-AWS-IAM-001"
    # byte-identical evidence: no cis_controls key when source lacks native compliance
    assert "cis_controls" not in payload["evidences"][0]
