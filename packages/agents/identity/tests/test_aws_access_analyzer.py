"""Tests for `identity.tools.aws_access_analyzer.aws_access_analyzer_findings`.

moto does not implement Access Analyzer, so we stub `boto3.Session` with
a fake that returns canned `list_findings_v2` responses (paginated via
`nextToken`). This isolates the tests from AWS and from moto's coverage
gaps while still exercising the wrapper's parsing and pagination logic.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest
from identity.tools import aws_access_analyzer as aa_mod
from identity.tools.aws_access_analyzer import (
    AccessAnalyzerError,
    AccessAnalyzerFinding,
    aws_access_analyzer_findings,
)

ANALYZER_ARN = "arn:aws:access-analyzer:us-east-1:123456789012:analyzer/nexus"
NOW = datetime(2026, 5, 11, tzinfo=UTC)


class _FakeAAClient:
    def __init__(self, pages: list[dict[str, Any]]) -> None:
        self._pages = list(pages)
        self.calls: list[dict[str, Any]] = []

    def list_findings_v2(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(kwargs)
        if not self._pages:
            return {"findings": []}
        return self._pages.pop(0)


class _FakeSession:
    def __init__(self, fake: _FakeAAClient, **_: Any) -> None:
        self._fake = fake

    def client(self, name: str) -> _FakeAAClient:
        assert name == "accessanalyzer", f"unexpected client: {name}"
        return self._fake


def _patch_session(monkeypatch: pytest.MonkeyPatch, fake: _FakeAAClient) -> None:
    def factory(**kwargs: Any) -> _FakeSession:
        return _FakeSession(fake, **kwargs)

    monkeypatch.setattr(aa_mod.boto3, "Session", factory)


def _finding(
    *,
    fid: str,
    principal: dict[str, str],
    is_public: bool = False,
    status: str = "ACTIVE",
    finding_type: str = "ExternalAccess",
    actions: tuple[str, ...] = ("s3:GetObject",),
) -> dict[str, Any]:
    return {
        "id": fid,
        "resource": f"arn:aws:s3:::bucket-{fid}",
        "resourceType": "AWS::S3::Bucket",
        "principal": principal,
        "action": list(actions),
        "isPublic": is_public,
        "status": status,
        "findingType": finding_type,
        "createdAt": NOW,
        "updatedAt": NOW,
    }


# ---------------------------- happy paths --------------------------------


@pytest.mark.asyncio
async def test_returns_findings_with_external_principals(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = _FakeAAClient(
        [
            {
                "findings": [
                    _finding(
                        fid="abc",
                        principal={"AWS": "arn:aws:iam::999999999999:role/cross"},
                    )
                ]
            }
        ]
    )
    _patch_session(monkeypatch, fake)

    findings = await aws_access_analyzer_findings(analyzer_arn=ANALYZER_ARN)

    assert len(findings) == 1
    f = findings[0]
    assert isinstance(f, AccessAnalyzerFinding)
    assert f.id == "abc"
    assert f.external_principals == ("arn:aws:iam::999999999999:role/cross",)
    assert f.is_public is False
    assert f.actions == ("s3:GetObject",)


@pytest.mark.asyncio
async def test_paginates_via_next_token(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeAAClient(
        [
            {
                "findings": [_finding(fid="a", principal={"AWS": "111111111111"})],
                "nextToken": "page2",
            },
            {
                "findings": [_finding(fid="b", principal={"AWS": "222222222222"})],
                "nextToken": "page3",
            },
            {"findings": [_finding(fid="c", principal={"AWS": "333333333333"})]},
        ]
    )
    _patch_session(monkeypatch, fake)

    findings = await aws_access_analyzer_findings(analyzer_arn=ANALYZER_ARN)

    assert {f.id for f in findings} == {"a", "b", "c"}
    assert len(fake.calls) == 3
    assert fake.calls[1].get("nextToken") == "page2"
    assert fake.calls[2].get("nextToken") == "page3"


@pytest.mark.asyncio
async def test_public_finding_flagged(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeAAClient(
        [
            {
                "findings": [
                    _finding(
                        fid="public-bucket",
                        principal={"AWS": "*"},
                        is_public=True,
                    )
                ]
            }
        ]
    )
    _patch_session(monkeypatch, fake)

    findings = await aws_access_analyzer_findings(analyzer_arn=ANALYZER_ARN)

    assert findings[0].is_public is True
    assert findings[0].external_principals == ("*",)


@pytest.mark.asyncio
async def test_empty_analyzer_returns_empty_tuple(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = _FakeAAClient([{"findings": []}])
    _patch_session(monkeypatch, fake)

    findings = await aws_access_analyzer_findings(analyzer_arn=ANALYZER_ARN)

    assert findings == ()


@pytest.mark.asyncio
async def test_status_filter_passed_to_api(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeAAClient([{"findings": []}])
    _patch_session(monkeypatch, fake)

    await aws_access_analyzer_findings(analyzer_arn=ANALYZER_ARN, statuses=("ACTIVE", "ARCHIVED"))

    assert fake.calls[0]["filter"]["status"]["eq"] == ["ACTIVE", "ARCHIVED"]


# ---------------------------- error paths --------------------------------


@pytest.mark.asyncio
async def test_boto_error_wrapped_as_access_analyzer_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _BoomClient(_FakeAAClient):
        def list_findings_v2(self, **kwargs: Any) -> dict[str, Any]:
            raise RuntimeError("boto blew up")

    fake = _BoomClient([])
    _patch_session(monkeypatch, fake)

    with pytest.raises(AccessAnalyzerError):
        await aws_access_analyzer_findings(analyzer_arn=ANALYZER_ARN)


def test_finding_dataclass_is_frozen() -> None:
    import dataclasses

    f = AccessAnalyzerFinding(
        id="x",
        resource_arn="arn:x",
        resource_type="AWS::S3::Bucket",
        external_principals=("*",),
        actions=("s3:GetObject",),
        is_public=True,
        status="ACTIVE",
        finding_type="ExternalAccess",
        created_at=NOW,
        updated_at=NOW,
    )
    assert dataclasses.is_dataclass(f)
    with pytest.raises(dataclasses.FrozenInstanceError):
        f.id = "mutated"  # type: ignore[misc]
