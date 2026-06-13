"""data-security Phase C SS4 — guarded live S3 route + scan_s3_live registration.

Proves the v0.2 live S3 readers are now (a) registered so they dispatch through the charter
proxy and (b) reachable from run() behind a guarded ``live_s3_account_id`` flag — the boto3
client is built inside the wrapper (mocked here), never injected.
"""

from __future__ import annotations

import io
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from charter.contract import BudgetSpec, ExecutionContract
from data_security.agent import build_registry, run
from data_security.tools.s3_live_scan import scan_s3_live

_ACCT = "111122223333"


class _FakeS3:
    """A combined fake S3 client: inventory surface + object-sampling surface."""

    def __init__(self, buckets: list[str], *, keys: list[str], content: bytes = b"hello") -> None:
        self._buckets = buckets
        self._keys = keys
        self._content = content

    # --- inventory surface (S3LiveInventoryReader) ---
    def list_buckets(self) -> dict[str, Any]:
        return {"Buckets": [{"Name": b} for b in self._buckets]}

    def get_bucket_location(self, *, Bucket: str) -> dict[str, Any]:
        return {"LocationConstraint": "us-east-1"}

    def get_bucket_acl(self, *, Bucket: str) -> dict[str, Any]:
        return {"Grants": []}

    def get_public_access_block(self, *, Bucket: str) -> dict[str, Any]:
        return {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            }
        }

    def get_bucket_encryption(self, *, Bucket: str) -> dict[str, Any]:
        return {
            "ServerSideEncryptionConfiguration": {
                "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
            }
        }

    def get_bucket_policy(self, *, Bucket: str) -> dict[str, Any]:
        raise RuntimeError("NoSuchBucketPolicy")

    def get_bucket_tagging(self, *, Bucket: str) -> dict[str, Any]:
        return {"TagSet": []}

    # --- object-sampling surface (S3LiveObjectSampler) ---
    def list_objects_v2(self, **kwargs: Any) -> dict[str, Any]:
        return {"Contents": [{"Key": k} for k in self._keys], "IsTruncated": False}

    def get_object(self, *, Bucket: str, Key: str) -> dict[str, Any]:
        return {"Body": io.BytesIO(self._content)}


class _FakeSession:
    def __init__(self, client: _FakeS3) -> None:
        self._client = client

    def client(self, name: str) -> _FakeS3:
        assert name == "s3"
        return self._client


def _patch_boto3(monkeypatch: pytest.MonkeyPatch, client: _FakeS3) -> None:
    import boto3

    monkeypatch.setattr(boto3, "Session", lambda **_kw: _FakeSession(client))


def _live_contract(workspace: Path) -> ExecutionContract:
    persistent = workspace / "_persistent"
    persistent.mkdir(exist_ok=True)
    return ExecutionContract(
        schema_version="0.1",
        delegation_id="01J0000000000000000000DSEC",
        source_agent="supervisor",
        target_agent="data_security",
        customer_id="cust_test",
        task="Live data security scan",
        required_outputs=["findings.json", "report.md"],
        budget=BudgetSpec(
            llm_calls=5, tokens=10_000, wall_clock_sec=60.0, cloud_api_calls=50, mb_written=10
        ),
        permitted_tools=[
            "read_s3_inventory",
            "read_s3_objects",
            "read_f3_findings",
            "scan_s3_live",
        ],
        completion_condition="findings.json AND report.md exist",
        escalation_rules=[],
        workspace=str(workspace),
        persistent_root=str(persistent),
        created_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )


def test_build_registry_includes_scan_s3_live() -> None:
    reg = build_registry()
    assert "scan_s3_live" in reg.known_tools()
    assert reg.cloud_calls("scan_s3_live") == 1  # boto3 list/get calls are budget-tracked


@pytest.mark.asyncio
async def test_scan_s3_live_returns_buckets_and_samples(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _FakeS3(["data-a", "data-b"], keys=[f"k{i}" for i in range(100)])
    _patch_boto3(monkeypatch, client)
    buckets, samples = await scan_s3_live(account_id=_ACCT)
    assert {b.name for b in buckets} == {"data-a", "data-b"}
    assert all(b.account_id == _ACCT for b in buckets)
    # 100 keys at the 1% default stride -> 1 sample per bucket -> 2 total.
    assert len(samples) == 2


@pytest.mark.asyncio
async def test_run_live_route_produces_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _FakeS3(["data-a"], keys=["secret.txt"])
    _patch_boto3(monkeypatch, client)
    report = await run(_live_contract(tmp_path), live_s3_account_id=_ACCT)
    # The live route ran end-to-end through the charter and wrote artifacts.
    assert (tmp_path / "findings.json").is_file()
    assert (tmp_path / "report.md").is_file()
    assert report.agent == "data_security"


@pytest.mark.asyncio
async def test_live_route_mutually_exclusive_with_feeds(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="mutually exclusive"):
        await run(
            _live_contract(tmp_path),
            live_s3_account_id=_ACCT,
            s3_inventory_feed=tmp_path / "inv.json",
        )
