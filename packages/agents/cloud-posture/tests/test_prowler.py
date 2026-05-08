"""Tests for the Prowler subprocess wrapper."""

import json
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from cloud_posture.tools.prowler import (
    ProwlerError,
    ProwlerResult,
    run_prowler_aws,
)


def _fake_prowler_output() -> dict:
    return {
        "Findings": [
            {
                "CheckID": "iam_user_no_mfa",
                "Severity": "high",
                "Status": "FAIL",
                "ResourceArn": "arn:aws:iam::111122223333:user/alice",
                "ResourceType": "AwsIamUser",
                "Region": "us-east-1",
                "AccountId": "111122223333",
                "StatusExtended": "User alice has no MFA",
            }
        ]
    }


@patch("cloud_posture.tools.prowler.subprocess.run")
def test_run_prowler_aws_parses_json(mock_run: MagicMock, tmp_path: Path) -> None:
    output_file = tmp_path / "prowler.ocsf.json"
    output_file.write_text(json.dumps(_fake_prowler_output()["Findings"]))
    mock_run.return_value = subprocess.CompletedProcess(
        args=[], returncode=0, stdout="ok", stderr=""
    )

    result = run_prowler_aws(
        account_id="111122223333",
        region="us-east-1",
        output_dir=tmp_path,
    )
    assert isinstance(result, ProwlerResult)
    assert len(result.raw_findings) == 1
    assert result.raw_findings[0]["CheckID"] == "iam_user_no_mfa"


@patch("cloud_posture.tools.prowler.subprocess.run")
def test_run_prowler_nonzero_exit_raises(mock_run: MagicMock, tmp_path: Path) -> None:
    mock_run.return_value = subprocess.CompletedProcess(
        args=[], returncode=2, stdout="", stderr="auth error"
    )
    with pytest.raises(ProwlerError) as exc_info:
        run_prowler_aws(account_id="x", region="us-east-1", output_dir=tmp_path)
    assert "auth error" in str(exc_info.value)


@patch("cloud_posture.tools.prowler.subprocess.run")
def test_run_prowler_filters_by_severity(mock_run: MagicMock, tmp_path: Path) -> None:
    output = _fake_prowler_output()
    output["Findings"].append(
        {
            "CheckID": "low_check",
            "Severity": "low",
            "Status": "FAIL",
            "ResourceArn": "arn:aws:s3:::x",
            "ResourceType": "AwsS3Bucket",
            "Region": "us-east-1",
            "AccountId": "1",
            "StatusExtended": "x",
        }
    )
    output_file = tmp_path / "prowler.ocsf.json"
    output_file.write_text(json.dumps(output["Findings"]))
    mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")

    result = run_prowler_aws(
        account_id="1",
        region="us-east-1",
        output_dir=tmp_path,
        min_severity="medium",
    )
    assert len(result.raw_findings) == 1
    assert result.raw_findings[0]["CheckID"] == "iam_user_no_mfa"
