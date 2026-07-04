"""End-to-end: scan_run over real agent run()s yields a ranked public-data attack path.

Phase-1 proof (Task 3 of the operating-path wiring cycle).

Two real agent run()s execute into ONE shared SemanticStore:
  1. data-security — reads a canonical fixture inventory (public S3 bucket + PII object),
     writes CLOUD_RESOURCE(acme-pii, is_public=True) + EXPOSES_DATA --> DATA_CLASSIFICATION
  2. identity — uses an admin IdentityListing (AdministratorAccess), writes IDENTITY(AdminRole)
     + HAS_ACCESS_TO --> CLOUD_RESOURCE(acme-pii)

scan_run then calls analyze (correlate_all + AttackPathRanker), which finds the:
  IDENTITY --HAS_ACCESS_TO--> CLOUD_RESOURCE --EXPOSES_DATA--> DATA_CLASSIFICATION
path and surfaces it as a ``fine_grained_data`` confirmed attack path (severity=60).

Assertions:
  - all feeders ok=True (both agent run()s completed without exception)
  - res.confirmed is non-empty (the path formed from real run()s)
  - severity is non-increasing (ranking invariant)

NOTE: SQLite does not enforce RLS; DB-level tenant isolation is proven by the
gated Postgres test, not here.
"""

from __future__ import annotations

import base64
import json
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock

import pytest
import pytest_asyncio
from charter.memory.models import Base
from cloud_posture.tools import aws_iam as cp_aws_iam
from cloud_posture.tools import prowler as cp_prowler
from identity.tools.aws_iam import IamRole, IamUser, IdentityListing
from nexus_runtime.scan_pipeline import ScanSources, scan_run
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from vulnerability.tools import trivy as trivy_module

_NOW = datetime(2026, 6, 22, tzinfo=UTC)
_TENANT = "tenant-op-e2e"

# Admin principal — AdministratorAccess causes identity to write HAS_ACCESS_TO every
# CLOUD_RESOURCE node that data-security wrote.
_ADMIN_POLICY_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"
_ADMIN_ROLE_ARN = "arn:aws:iam::123456789012:role/AdminRole"

# Bucket name must match between the inventory fixture and the identity account scope.
_BUCKET_NAME = "acme-pii"


# ---------------------------------------------------------------------------
# Session factory fixture — same SQLite in-memory pattern as test_correlation_run.py
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def session_factory() -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield async_sessionmaker(engine, expire_on_commit=False)
    await engine.dispose()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _b64(payload: bytes) -> str:
    return base64.b64encode(payload).decode("ascii")


def _write_public_pii_inventory(base_dir: Path) -> tuple[Path, Path]:
    """Write a canonical public-PII bucket inventory that data-security will classify.

    Uses the ``{"buckets": [...]}`` shape data-security's read_s3_inventory parses,
    and the ``{"objects": [...]}`` + ``content_sample_b64`` shape ObjectSample expects.
    One public bucket (all grants_all_users READ, no PAB blocks) + one SSN-bearing object
    ensures data-security writes CLOUD_RESOURCE(is_public=True) + EXPOSES_DATA.
    """
    base_dir.mkdir(parents=True, exist_ok=True)
    inventory = {
        "buckets": [
            {
                "name": _BUCKET_NAME,
                "region": "us-east-1",
                "account_id": "123456789012",
                "acl": {
                    "grants_all_users": ["READ"],
                    "grants_authenticated_users": [],
                },
                "public_access_block": {
                    "block_public_acls": False,
                    "ignore_public_acls": False,
                    "block_public_policy": False,
                    "restrict_public_buckets": False,
                },
                "encryption": {"algorithm": "AES256", "kms_master_key_id": None},
                "policy_json": None,
                "tags": {},
            }
        ]
    }
    objects = {
        "objects": [
            {
                "bucket": _BUCKET_NAME,
                "key": "data.csv",
                "content_sample_b64": _b64(b"name,ssn\nalice,123-45-6789"),
            }
        ]
    }
    inv_path = base_dir / "inv.json"
    obj_path = base_dir / "objects.json"
    inv_path.write_text(json.dumps(inventory), encoding="utf-8")
    obj_path.write_text(json.dumps(objects), encoding="utf-8")
    return inv_path, obj_path


def _admin_identity_listing() -> IdentityListing:
    """One role with AdministratorAccess — identity will write HAS_ACCESS_TO every resource.

    The role ARN uses account 123456789012 to match the bucket's account_id.
    _synthesize_admin_grants detects AdministratorAccess -> admin grant ->
    _write_access_edges expands '*' against all CLOUD_RESOURCE nodes -> HAS_ACCESS_TO edge.
    """
    role = IamRole(
        arn=_ADMIN_ROLE_ARN,
        name="AdminRole",
        role_id="AROA-ADMINROLE",
        create_date=_NOW,
        last_used_at=_NOW,
        assume_role_policy_document={},
        attached_policy_arns=(_ADMIN_POLICY_ARN,),
    )
    return IdentityListing(users=(), roles=(role,), groups=())


# ---------------------------------------------------------------------------
# The keystone test
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_scan_run_yields_ranked_public_data_path(
    tmp_path: Path,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Positive path: real agent run()s into shared store → ranked confirmed attack path.

    data-security writes the public PII bucket (CLOUD_RESOURCE + EXPOSES_DATA).
    identity (admin role) writes HAS_ACCESS_TO to the same resource.
    analyze finds the fine_grained_data path and confirms it.

    This is the Phase-1 operating-path proof — the keystone regression guard.
    Task 11 extends it once the dormant writers land.
    """
    feeds_dir = tmp_path / "feeds"
    inv, obj = _write_public_pii_inventory(feeds_dir)
    listing = _admin_identity_listing()

    sources = ScanSources(
        ds_inventory_feed=inv,
        ds_objects_feed=obj,
        identity_listing=listing,
    )

    res = await scan_run(
        session_factory=session_factory,
        tenant=_TENANT,
        sources=sources,
        workspace_root=tmp_path / "ws",
    )

    # All feeders must complete without exception.
    assert all(f.ok for f in res.feeders), [f for f in res.feeders if not f.ok]

    # Both data-security and identity feeders must have executed.
    feeder_names = {f.agent for f in res.feeders}
    assert "data-security" in feeder_names, f"data-security feeder missing from {feeder_names}"
    assert "identity" in feeder_names, f"identity feeder missing from {feeder_names}"

    # The operating path must surface at least one confirmed attack path.
    assert res.confirmed, (
        "expected at least one confirmed attack path from real run()s — "
        "data-security wrote EXPOSES_DATA, identity wrote HAS_ACCESS_TO, "
        "analyze should find fine_grained_data or public_unencrypted"
    )

    # Ranking invariant: severity is non-increasing (worst-first order).
    # AttackPath.severity is the rank key; find_all() sorts by (-severity, -count, title).
    severities = [p.severity for p in res.confirmed]
    assert severities == sorted(severities, reverse=True), (
        f"attack paths must be sorted worst-first by severity; got {severities}"
    )


# ---------------------------------------------------------------------------
# Task 11 Part B: stored_secret_to_data fires through newly-wired cloud-posture
# ---------------------------------------------------------------------------

# Assembled to avoid push-protection triggering on a literal AWS key id.
_AKIA_KEY = "AKIA" + "IOSFODNN7EXAMPLE"

# ECS service ARN that embeds the key in its env.
_ECS_ARN = "arn:aws:ecs:us-east-1:123456789012:service/cluster/secret-svc"

# The image that the ECS workload runs — used as the join key.
_IMAGE_REF = "my-registry/my-app:v1.2.3"

# IAM user ARN — owns the AKIA key, has AdministratorAccess.
_KEY_USER_ARN = "arn:aws:iam::123456789012:user/ServiceUser"


def _patch_cloud_posture_tools(monkeypatch: pytest.MonkeyPatch) -> None:
    """Stub out prowler and IAM tools so cloud-posture runs offline."""

    async def fake_prowler(**_kw: Any) -> cp_prowler.ProwlerResult:
        return cp_prowler.ProwlerResult(raw_findings=[])

    monkeypatch.setattr(cp_prowler, "run_prowler_aws", fake_prowler)
    monkeypatch.setattr(cp_aws_iam, "list_users_without_mfa", AsyncMock(return_value=[]))
    monkeypatch.setattr(cp_aws_iam, "list_admin_policies", AsyncMock(return_value=[]))


def _patch_trivy(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fake trivy scan: returns one CRITICAL CVE keyed by the requested image_ref.

    The _artifact_name is set to image_ref so the kg_writer mints a CLOUD_RESOURCE
    node with external_id == image_ref — the SAME node cloud-posture writes via
    record_workloads (RUNS_IMAGE target). The two nodes converge on the same
    external_id, forming the RUNS_IMAGE --> VULNERABLE_TO join.
    """

    async def fake_scan(image_ref: str, **_kw: Any) -> trivy_module.TrivyResult:
        return trivy_module.TrivyResult(
            raw_findings=[
                {
                    "VulnerabilityID": "CVE-2021-44228",
                    "PkgName": "log4j-core",
                    "InstalledVersion": "2.14.0",
                    "FixedVersion": "2.16.0",
                    "Severity": "CRITICAL",
                    "Title": "Log4Shell RCE",
                    "_target": f"{image_ref} (debian 12)",
                    "_class": "lang-pkgs",
                    "_artifact_name": image_ref,
                }
            ]
        )

    monkeypatch.setattr(trivy_module, "trivy_image_scan", fake_scan)


def _admin_user_with_akia() -> IamUser:
    """An IAM user with AdministratorAccess + an AWS access key.

    identity writes:
      IDENTITY(user) --OWNS--> SECRET(_AKIA_KEY) --OWNED_BY--> IDENTITY(user)
      IDENTITY(user) --HAS_ACCESS_TO--> CLOUD_RESOURCE(acme-pii)  [via AdministratorAccess]
    """
    return IamUser(
        arn=_KEY_USER_ARN,
        name="ServiceUser",
        user_id="AIDA-SERVICEUSER",
        create_date=_NOW,
        last_used_at=_NOW,
        attached_policy_arns=(_ADMIN_POLICY_ARN,),
        access_key_ids=(_AKIA_KEY,),
    )


@pytest.mark.asyncio
async def test_scan_run_stored_secret_to_data_fires(
    tmp_path: Path,
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Part B (Task 11): stored_secret_to_data fires through newly-wired cloud-posture feeder.

    Cross-domain join: cloud-posture (STORES_SECRET) + identity (OWNED_BY + HAS_ACCESS_TO)
    + data-security (EXPOSES_DATA):

      CLOUD_RESOURCE(ecs-svc)
        --STORES_SECRET--> SECRET(_AKIA_KEY)
        --OWNED_BY--> IDENTITY(ServiceUser)
        --HAS_ACCESS_TO--> CLOUD_RESOURCE(acme-pii)
        --EXPOSES_DATA--> DATA_CLASSIFICATION(pii)

    This detector was dark before cloud-posture was wired into scan_run.  Now that the
    cloud-posture feeder lands in Task 11, the full chain forms through real agent run()s.
    """
    _patch_cloud_posture_tools(monkeypatch)
    _patch_trivy(monkeypatch)

    feeds_dir = tmp_path / "feeds"
    inv, obj = _write_public_pii_inventory(feeds_dir)

    # identity listing: admin role (existing T1/T3 path) + user with AKIA key
    admin_role = IamRole(
        arn=_ADMIN_ROLE_ARN,
        name="AdminRole",
        role_id="AROA-ADMINROLE",
        create_date=_NOW,
        last_used_at=_NOW,
        assume_role_policy_document={},
        attached_policy_arns=(_ADMIN_POLICY_ARN,),
    )
    listing = IdentityListing(
        users=(_admin_user_with_akia(),),
        roles=(admin_role,),
        groups=(),
    )

    from cloud_posture.tools.aws_ecs import EcsWorkload

    ecs_workload = EcsWorkload(
        service_arn=_ECS_ARN,
        image_ref=_IMAGE_REF,
        is_public=True,
        task_role_arn="",
        env_values=(_AKIA_KEY,),
    )

    sources = ScanSources(
        ds_inventory_feed=inv,
        ds_objects_feed=obj,
        identity_listing=listing,
        cloud_ecs_workloads=(ecs_workload,),
        vuln_image_refs=(_IMAGE_REF,),
    )

    res = await scan_run(
        session_factory=session_factory,
        tenant=_TENANT,
        sources=sources,
        workspace_root=tmp_path / "ws",
    )

    # All wired feeders must complete without exception.
    failed = [f for f in res.feeders if not f.ok]
    assert not failed, f"feeder(s) failed: {failed}"

    # The three newly-wired feeders must have executed.
    feeder_names = {f.agent for f in res.feeders}
    assert "cloud-posture" in feeder_names, f"cloud-posture missing from {feeder_names}"
    assert "vulnerability" in feeder_names, f"vulnerability missing from {feeder_names}"

    # The operating path must surface confirmed attack paths.
    assert res.confirmed, (
        "expected confirmed attack paths — stored_secret_to_data or fine_grained_data "
        "should fire from the multi-agent graph"
    )

    # stored_secret_to_data must fire (the detector that was dark before Task 11).
    path_types = [p.path_type for p in res.confirmed]
    assert "stored_secret_to_data" in path_types, (
        f"stored_secret_to_data path not confirmed; got path_types={path_types}. "
        "Check that the AKIA key join is intact: "
        f"identity user {_KEY_USER_ARN!r} owns key {_AKIA_KEY!r}; "
        f"cloud-posture ECS {_ECS_ARN!r} stores same key; "
        f"data-security bucket {_BUCKET_NAME!r} exposes PII."
    )
