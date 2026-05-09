"""Tests for the Prowler async subprocess wrapper."""

import asyncio
import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from cloud_posture.tools.prowler import (
    ProwlerError,
    ProwlerResult,
    run_prowler_aws,
)


def _fake_prowler_findings() -> list[dict]:
    return [
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


def _make_proc(returncode: int = 0, stderr: bytes = b"") -> MagicMock:
    proc = MagicMock()
    proc.communicate = AsyncMock(return_value=(b"", stderr))
    proc.kill = MagicMock()
    proc.wait = AsyncMock(return_value=returncode)
    proc.returncode = returncode
    return proc


@pytest.mark.asyncio
@patch(
    "cloud_posture.tools.prowler.asyncio.create_subprocess_exec",
    new_callable=AsyncMock,
)
async def test_run_prowler_aws_parses_json(mock_exec: AsyncMock, tmp_path: Path) -> None:
    output_file = tmp_path / "prowler.ocsf.json"
    output_file.write_text(json.dumps(_fake_prowler_findings()))
    mock_exec.return_value = _make_proc(returncode=0)

    result = await run_prowler_aws(
        account_id="111122223333",
        region="us-east-1",
        output_dir=tmp_path,
    )
    assert isinstance(result, ProwlerResult)
    assert len(result.raw_findings) == 1
    assert result.raw_findings[0]["CheckID"] == "iam_user_no_mfa"


@pytest.mark.asyncio
@patch(
    "cloud_posture.tools.prowler.asyncio.create_subprocess_exec",
    new_callable=AsyncMock,
)
async def test_run_prowler_nonzero_exit_raises(mock_exec: AsyncMock, tmp_path: Path) -> None:
    mock_exec.return_value = _make_proc(returncode=2, stderr=b"auth error")
    with pytest.raises(ProwlerError) as exc_info:
        await run_prowler_aws(account_id="x", region="us-east-1", output_dir=tmp_path)
    assert "auth error" in str(exc_info.value)


@pytest.mark.asyncio
@patch(
    "cloud_posture.tools.prowler.asyncio.create_subprocess_exec",
    new_callable=AsyncMock,
)
async def test_run_prowler_filters_by_severity(mock_exec: AsyncMock, tmp_path: Path) -> None:
    findings = _fake_prowler_findings()
    findings.append(
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
    output_file.write_text(json.dumps(findings))
    mock_exec.return_value = _make_proc(returncode=0)

    result = await run_prowler_aws(
        account_id="1",
        region="us-east-1",
        output_dir=tmp_path,
        min_severity="medium",
    )
    assert len(result.raw_findings) == 1
    assert result.raw_findings[0]["CheckID"] == "iam_user_no_mfa"


@pytest.mark.asyncio
@patch(
    "cloud_posture.tools.prowler.asyncio.create_subprocess_exec",
    new_callable=AsyncMock,
)
async def test_run_prowler_timeout_raises(mock_exec: AsyncMock, tmp_path: Path) -> None:
    proc = MagicMock()

    async def _hang(*_args: object, **_kwargs: object) -> tuple[bytes, bytes]:
        await asyncio.sleep(10)
        return (b"", b"")

    proc.communicate = _hang
    proc.kill = MagicMock()
    proc.wait = AsyncMock(return_value=-9)
    proc.returncode = -9
    mock_exec.return_value = proc

    with pytest.raises(ProwlerError) as exc_info:
        await run_prowler_aws(
            account_id="x",
            region="us-east-1",
            output_dir=tmp_path,
            timeout=0.05,
        )
    assert "timed out" in str(exc_info.value)
    proc.kill.assert_called_once()
