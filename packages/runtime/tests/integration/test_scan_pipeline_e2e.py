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
  - fine_grained_data path_type is present (the expected archetype for this fixture)

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
    Ordering by expected_loss (not severity) is proven by test_crown_jewel_outranks_single_store_by_expected_loss.
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

    # The operating path must surface the expected fine_grained_data path type.
    # (Ordering is by expected_loss, proven by test_crown_jewel_outranks_single_store_by_expected_loss;
    # this test's job is "the path forms from real run()s", so we assert the path is present.)
    assert any(p.path_type == "fine_grained_data" for p in res.confirmed), (
        f"expected fine_grained_data path from real run()s — "
        f"data-security wrote EXPOSES_DATA, identity wrote HAS_ACCESS_TO; "
        f"got path_types={[p.path_type for p in res.confirmed]}"
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


# ---------------------------------------------------------------------------
# G-3 Part A: e2e proof — newly-lit detectors fire through scan_run
# ---------------------------------------------------------------------------

_RDS_ARN = "arn:aws:rds:us-east-1:123456789012:db:prod-db"
_KMS_ARN = "arn:aws:kms:us-east-1:123456789012:key/abcd-1234"

# Account used by the aispm fake — same as the bucket's account so the canonical
# ARN produced by s3_bucket_arn("acme-pii") matches data-security's bucket node.
_AI_ACCOUNT_ID = "123456789012"


class _ExposedAiReader:
    """Fake AwsAiReader that returns one SageMaker endpoint with:
    - network_isolated=False  → aispm writes EXPOSES_MODEL to the internet sentinel
    - model_data_bucket="acme-pii"  → aispm writes HAS_ACCESS_TO the bucket node that
      data-security wrote with EXPOSES_DATA (canonical key arn:aws:s3:::acme-pii).

    These two edges combine with data-security's EXPOSES_DATA to form the
    find_exposed_ai_with_sensitive_data spine:
      AI_SERVICE --EXPOSES_MODEL--> internet
      AI_SERVICE --HAS_ACCESS_TO--> CLOUD_RESOURCE(acme-pii)
      CLOUD_RESOURCE(acme-pii) --EXPOSES_DATA--> DATA_CLASSIFICATION
    """

    def sagemaker_endpoints(self) -> list[dict[str, Any]]:
        return [
            {
                "name": "sensitive-ep",
                "data_capture_enabled": False,
                "model_name": "m1",
                "network_isolated": False,
                "model_data_bucket": "acme-pii",
            }
        ]

    def sagemaker_notebooks(self) -> list[dict[str, Any]]:
        return []

    def bedrock_logging_enabled(self) -> bool | None:
        return True

    def bedrock_guardrail_count(self) -> int:
        return 0


@pytest.mark.asyncio
async def test_scan_run_exposed_database_fires(
    tmp_path: Path,
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """G-3 Part A-1: find_exposed_database fires through scan_run with a public RDS instance.

    cloud-posture feeder receives a public RdsInstance via ScanSources.cloud_rds_instances.
    record_rds_instances writes CLOUD_RESOURCE{kind=rds-instance, is_public=True}.
    analyze → find_exposed_database → confirmed path_type == "exposed_database".
    """
    _patch_cloud_posture_tools(monkeypatch)

    from cloud_posture.tools.aws_rds import RdsInstance

    sources = ScanSources(
        cloud_rds_instances=(
            RdsInstance(
                instance_arn=_RDS_ARN,
                is_public=True,
                engine="mysql",
            ),
        ),
    )

    res = await scan_run(
        session_factory=session_factory,
        tenant=_TENANT,
        sources=sources,
        workspace_root=tmp_path / "ws",
    )

    failed = [f for f in res.feeders if not f.ok]
    assert not failed, f"feeder(s) failed: {failed}"

    feeder_names = {f.agent for f in res.feeders}
    assert "cloud-posture" in feeder_names, f"cloud-posture missing from {feeder_names}"

    path_types = [p.path_type for p in res.confirmed]
    assert "exposed_database" in path_types, (
        f"exposed_database path not confirmed; got path_types={path_types}. "
        f"Check cloud-posture wrote CLOUD_RESOURCE{{kind=rds-instance, is_public=True}} "
        f"for {_RDS_ARN!r} and find_exposed_database picked it up."
    )


@pytest.mark.asyncio
async def test_scan_run_exposed_kms_key_fires(
    tmp_path: Path,
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """G-3 Part A-2: find_exposed_kms_key fires through scan_run with a public KMS key.

    cloud-posture feeder receives a public KmsKey via ScanSources.cloud_kms_keys.
    record_kms_keys writes CLOUD_RESOURCE{kind=kms-key, is_public=True}.
    analyze → find_exposed_kms_key → confirmed path_type == "exposed_kms_key".
    """
    _patch_cloud_posture_tools(monkeypatch)

    from cloud_posture.tools.aws_kms import KmsKey

    sources = ScanSources(
        cloud_kms_keys=(
            KmsKey(
                key_arn=_KMS_ARN,
                is_public=True,
            ),
        ),
    )

    res = await scan_run(
        session_factory=session_factory,
        tenant=_TENANT,
        sources=sources,
        workspace_root=tmp_path / "ws",
    )

    failed = [f for f in res.feeders if not f.ok]
    assert not failed, f"feeder(s) failed: {failed}"

    feeder_names = {f.agent for f in res.feeders}
    assert "cloud-posture" in feeder_names, f"cloud-posture missing from {feeder_names}"

    path_types = [p.path_type for p in res.confirmed]
    assert "exposed_kms_key" in path_types, (
        f"exposed_kms_key path not confirmed; got path_types={path_types}. "
        f"Check cloud-posture wrote CLOUD_RESOURCE{{kind=kms-key, is_public=True}} "
        f"for {_KMS_ARN!r} and find_exposed_kms_key picked it up."
    )


@pytest.mark.asyncio
async def test_scan_run_exposed_ai_with_sensitive_data_fires(
    tmp_path: Path,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """G-3 Part A-3: find_exposed_ai_with_sensitive_data fires through scan_run end-to-end.

    Three feeders cooperate in the shared SemanticStore:
      1. data-security writes CLOUD_RESOURCE(acme-pii) + EXPOSES_DATA --> DATA_CLASSIFICATION
      2. aispm writes AI_SERVICE(sensitive-ep)
                     --EXPOSES_MODEL--> internet sentinel  (network_isolated=False)
                     --HAS_ACCESS_TO--> CLOUD_RESOURCE(arn:aws:s3:::acme-pii)
      3. analyze → find_exposed_ai_with_sensitive_data → confirmed "exposed_ai_sensitive_data"

    The bucket ARN join: data-security keys by canonical arn:aws:s3:::acme-pii; aispm kg_writer
    calls s3_bucket_arn("acme-pii") which produces the same string — the nodes reconcile.
    """
    feeds_dir = tmp_path / "feeds"
    inv, obj = _write_public_pii_inventory(feeds_dir)

    sources = ScanSources(
        ds_inventory_feed=inv,
        ds_objects_feed=obj,
        aispm_aws_reader=_ExposedAiReader(),
        aispm_aws_account_id=_AI_ACCOUNT_ID,
    )

    res = await scan_run(
        session_factory=session_factory,
        tenant=_TENANT,
        sources=sources,
        workspace_root=tmp_path / "ws",
    )

    failed = [f for f in res.feeders if not f.ok]
    assert not failed, f"feeder(s) failed: {failed}"

    feeder_names = {f.agent for f in res.feeders}
    assert "data-security" in feeder_names, f"data-security missing from {feeder_names}"
    assert "aispm" in feeder_names, f"aispm missing from {feeder_names}"

    path_types = [p.path_type for p in res.confirmed]
    assert "exposed_ai_sensitive_data" in path_types, (
        f"exposed_ai_sensitive_data path not confirmed; got path_types={path_types}. "
        "Check: aispm wrote AI_SERVICE --EXPOSES_MODEL--> internet AND "
        "AI_SERVICE --HAS_ACCESS_TO--> arn:aws:s3:::acme-pii; "
        "data-security wrote CLOUD_RESOURCE(acme-pii) --EXPOSES_DATA--> DATA_CLASSIFICATION."
    )


# ---------------------------------------------------------------------------
# Task 2 (last-three-detectors): real serviceAccountName → find_k8s_escape_to_cloud_data
# ---------------------------------------------------------------------------

# IRSA role ARN — shared between the SA annotation and the identity listing.
_IRSA_ROLE_ARN = "arn:aws:iam::123456789012:role/pod-role"
_IRSA_SA_NAME = "irsa-sa"
_IRSA_NAMESPACE = "default"


class _IrsaClusterReader:
    """A fake ClusterReader whose SA 'irsa-sa' carries the IRSA annotation.

    The SA annotation ``eks.amazonaws.com/role-arn: _IRSA_ROLE_ARN`` is the bridge
    that record_inventory writes as an IRSA_MAPPING edge (SA → IDENTITY(role_arn)).
    """

    def list_namespaces(self) -> list[dict]:  # type: ignore[type-arg]
        return [{"metadata": {"name": _IRSA_NAMESPACE}}]

    def list_service_accounts(self) -> list[dict]:  # type: ignore[type-arg]
        return [
            {
                "metadata": {
                    "name": _IRSA_SA_NAME,
                    "namespace": _IRSA_NAMESPACE,
                    "annotations": {"eks.amazonaws.com/role-arn": _IRSA_ROLE_ARN},
                }
            }
        ]

    def list_roles(self) -> list[dict]:  # type: ignore[type-arg]
        return []

    def list_role_bindings(self) -> list[dict]:  # type: ignore[type-arg]
        return []


def _write_privileged_irsa_pod(manifest_dir: Path) -> None:
    """Write a privileged pod manifest with serviceAccountName: irsa-sa."""
    manifest_dir.mkdir(parents=True, exist_ok=True)
    pod = {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": "irsa-pod", "namespace": _IRSA_NAMESPACE},
        "spec": {
            "serviceAccountName": _IRSA_SA_NAME,
            "containers": [
                {
                    "name": "app",
                    "image": "app:v1",
                    "securityContext": {"privileged": True},
                }
            ],
        },
    }
    import yaml

    (manifest_dir / "irsa-pod.yaml").write_text(yaml.safe_dump(pod), encoding="utf-8")


def _irsa_identity_listing() -> IdentityListing:
    """A role at _IRSA_ROLE_ARN with AdministratorAccess.

    identity's _synthesize_admin_grants detects AdministratorAccess and writes
    HAS_ACCESS_TO every CLOUD_RESOURCE node — including the public PII bucket that
    data-security wrote. The role ARN must match the IRSA annotation on the SA.
    """
    role = IamRole(
        arn=_IRSA_ROLE_ARN,
        name="pod-role",
        role_id="AROA-PODROLE",
        create_date=_NOW,
        last_used_at=_NOW,
        assume_role_policy_document={},
        attached_policy_arns=(_ADMIN_POLICY_ARN,),
    )
    return IdentityListing(users=(), roles=(role,), groups=())


@pytest.mark.asyncio
async def test_scan_run_k8s_escape_to_cloud_data_fires(
    tmp_path: Path,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """T2: real serviceAccountName wires the privileged-pod → IRSA → data path (C-2).

    Four feeders cooperate in the shared SemanticStore:
      1. data-security writes CLOUD_RESOURCE(acme-pii, is_public=True)
                              --EXPOSES_DATA--> DATA_CLASSIFICATION(pii)
      2. identity writes IDENTITY(pod-role)
                         --HAS_ACCESS_TO--> CLOUD_RESOURCE(acme-pii)
         (AdministratorAccess expands to all resources)
      3. k8s-posture (manifest_dir) reads irsa-pod.yaml with serviceAccountName=irsa-sa
         → ManifestFinding(privileged-container, unmapped["service_account"]="irsa-sa")
         → record_privileged_workloads writes
             K8S_OBJECT(irsa-pod)
               --USES_SERVICE_ACCOUNT-->
             K8S_OBJECT(SA:offline/default/irsa-sa)
      4. k8s-posture (cluster_reader) calls record_inventory for _IrsaClusterReader
         → writes K8S_OBJECT(SA:offline/default/irsa-sa)
               --IRSA_MAPPING--> IDENTITY(arn:.../pod-role)

    The full chain:
      K8S_OBJECT(irsa-pod, privileged=True)
        --USES_SERVICE_ACCOUNT--> K8S_OBJECT(irsa-sa)
        --IRSA_MAPPING--> IDENTITY(pod-role)
        --HAS_ACCESS_TO--> CLOUD_RESOURCE(acme-pii)
        --EXPOSES_DATA--> DATA_CLASSIFICATION(pii)

    All join keys must match: SA name "irsa-sa" (manifest ↔ inventory),
    role ARN _IRSA_ROLE_ARN (inventory ↔ identity), bucket key (identity ↔ ds).
    """
    feeds_dir = tmp_path / "feeds"
    inv, obj = _write_public_pii_inventory(feeds_dir)

    manifest_dir = tmp_path / "manifests"
    _write_privileged_irsa_pod(manifest_dir)

    sources = ScanSources(
        ds_inventory_feed=inv,
        ds_objects_feed=obj,
        identity_listing=_irsa_identity_listing(),
        k8s_manifest_dir=manifest_dir,
        k8s_cluster_reader=_IrsaClusterReader(),
    )

    res = await scan_run(
        session_factory=session_factory,
        tenant="t-k8s-escape",
        sources=sources,
        workspace_root=tmp_path / "ws",
    )

    failed = [f for f in res.feeders if not f.ok]
    assert not failed, f"feeder(s) failed: {failed}"

    feeder_names = {f.agent for f in res.feeders}
    assert "k8s-posture" in feeder_names, f"k8s-posture missing from {feeder_names}"
    assert "data-security" in feeder_names, f"data-security missing from {feeder_names}"
    assert "identity" in feeder_names, f"identity missing from {feeder_names}"

    path_types = [p.path_type for p in res.confirmed]
    assert "k8s_escape_to_cloud_data" in path_types, (
        f"k8s_escape_to_cloud_data not confirmed; got path_types={path_types}. "
        f"Join-key check: SA name {_IRSA_SA_NAME!r} (manifest serviceAccountName must "
        f"equal inventory SA name); role ARN {_IRSA_ROLE_ARN!r} (IRSA annotation must "
        f"equal identity role ARN); bucket {_BUCKET_NAME!r} (identity HAS_ACCESS_TO must "
        f"reach the same CLOUD_RESOURCE data-security wrote with EXPOSES_DATA)."
    )


# ---------------------------------------------------------------------------
# Task 1 (last-three-detectors): k8s ClusterInventory seam →
# find_rbac_privilege_escalation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_scan_run_rbac_privilege_escalation_fires(
    tmp_path: Path,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """A wildcard-admin ClusterRole bound to a service account → find_rbac_privilege_escalation.

    k8s-posture run() receives a canned ClusterReader (no live cluster) via
    ScanSources.k8s_cluster_reader.  The feeder calls inventory_from_reader →
    record_inventory, which writes the SA→BINDS→ClusterRole edges into the shared
    graph.  analyze → find_rbac_privilege_escalation → confirmed path.
    """
    from fleet_testkit.k8s_workloads import cluster_admin_rbac_reader

    reader = cluster_admin_rbac_reader(namespace="prod", sa_name="deployer", admin=True)
    sources = ScanSources(k8s_cluster_reader=reader)
    res = await scan_run(
        session_factory=session_factory,
        tenant="t-rbac",
        sources=sources,
        workspace_root=tmp_path / "ws",
    )
    assert all(f.ok for f in res.feeders), [f for f in res.feeders if not f.ok]
    assert any(p.path_type == "rbac_privilege_escalation" for p in res.confirmed), (
        f"expected rbac_privilege_escalation in confirmed paths; got "
        f"{[p.path_type for p in res.confirmed]}"
    )


# ---------------------------------------------------------------------------
# Task 3 (last-three-detectors): host-scan ARN attribution →
# find_internet_exposed_host_vulnerable
# ---------------------------------------------------------------------------

_HOST_INSTANCE_ARN = "arn:aws:ec2:us-east-1:111122223333:instance/i-abc"
_HOST_TENANT = "t-host-vuln"


def _patch_trivy_host_scan(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fake trivy_host_scan: returns one CRITICAL CVE for any target.

    The _artifact_name is intentionally NOT set here — agent.run() will override it
    with host_target_arn when provided, which is the behaviour under test.
    """
    from vulnerability.tools import trivy as trivy_mod

    async def fake_host_scan(target: str, **_kw: Any) -> trivy_mod.TrivyResult:
        return trivy_mod.TrivyResult(
            raw_findings=[
                {
                    "VulnerabilityID": "CVE-2024-99999",
                    "PkgName": "openssh-server",
                    "InstalledVersion": "8.9p1",
                    "Severity": "CRITICAL",
                    "Title": "OpenSSH RCE",
                    "_target": "/mnt/rootfs (alpine 3.18)",
                    "_class": "os-pkgs",
                }
            ]
        )

    monkeypatch.setattr(trivy_mod, "trivy_host_scan", fake_host_scan)


@pytest.mark.asyncio
async def test_scan_run_internet_exposed_host_vulnerable_fires(
    tmp_path: Path,
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Task 3: host-scan ARN attribution fires find_internet_exposed_host_vulnerable.

    Two feeders cooperate in the shared SemanticStore:
      1. cloud-posture receives a public Ec2Workload(instance_arn=_HOST_INSTANCE_ARN, is_public=True)
         via ScanSources.cloud_ec2_workloads.  record_ec2_workloads writes
         CLOUD_RESOURCE{instance_arn, is_public=True} keyed on instance_arn.
      2. vulnerability receives a host-scan source (vuln_host_target="/mnt/rootfs") with
         vuln_host_target_arn=_HOST_INSTANCE_ARN.  agent.run() relabels the host-scan
         raw findings so their _artifact_name == _HOST_INSTANCE_ARN before writing to the
         KnowledgeGraphWriter.  record_scan_results then mints a CLOUD_RESOURCE node
         keyed on instance_arn with a VULNERABLE_TO edge.

    The join key is _HOST_INSTANCE_ARN in both feeders.  The cloud-posture node carries
    is_public=True; the vuln node carries VULNERABLE_TO; they are the SAME node.
    analyze → find_internet_exposed_host_vulnerable → confirmed path_type.
    """
    _patch_cloud_posture_tools(monkeypatch)
    _patch_trivy_host_scan(monkeypatch)

    from cloud_posture.tools.aws_ec2 import Ec2Workload

    sources = ScanSources(
        cloud_ec2_workloads=(
            Ec2Workload(
                instance_arn=_HOST_INSTANCE_ARN,
                is_public=True,
            ),
        ),
        vuln_host_target="/mnt/rootfs",
        vuln_host_target_arn=_HOST_INSTANCE_ARN,
    )

    res = await scan_run(
        session_factory=session_factory,
        tenant=_HOST_TENANT,
        sources=sources,
        workspace_root=tmp_path / "ws",
    )

    failed = [f for f in res.feeders if not f.ok]
    assert not failed, f"feeder(s) failed: {failed}"

    feeder_names = {f.agent for f in res.feeders}
    assert "cloud-posture" in feeder_names, f"cloud-posture missing from {feeder_names}"
    assert "vulnerability" in feeder_names, f"vulnerability missing from {feeder_names}"

    path_types = [p.path_type for p in res.confirmed]
    assert "internet_exposed_host_vulnerable" in path_types, (
        f"internet_exposed_host_vulnerable path not confirmed; got path_types={path_types}. "
        f"Join-key check: cloud-posture instance_arn={_HOST_INSTANCE_ARN!r} (is_public=True); "
        f"vuln host_target_arn={_HOST_INSTANCE_ARN!r} must relabel _artifact_name so the "
        f"VULNERABLE_TO node keys on the SAME ARN as the cloud-posture is_public node."
    )


# ---------------------------------------------------------------------------
# G-4: e2e proof — find_kms_key_access fires through scan_run
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_scan_run_kms_key_access_fires(
    tmp_path: Path,
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """G-4: find_kms_key_access fires through scan_run with all three legs wired.

    Three legs cooperate in the shared SemanticStore:
      1. cloud-posture (record_kms_keys) writes
             CLOUD_RESOURCE{kind=kms-key, external_id=_KMS_ARN}
      2. cloud-posture (record_kms_protected_data) writes
             CLOUD_RESOURCE(kms-key) --EXPOSES_DATA--> DATA_CLASSIFICATION
      3. identity (AdministratorAccess admin role) writes
             IDENTITY(AdminRole) --HAS_ACCESS_TO--> CLOUD_RESOURCE(_KMS_ARN)

    The detector walk:
      IDENTITY --HAS_ACCESS_TO--> CLOUD_RESOURCE{kind=kms-key} --EXPOSES_DATA--> DATA_CLASSIFICATION
    → path_type == "kms_key_access"

    Join key: _KMS_ARN is the external_id for the kms-key node (written by record_kms_keys
    keyed by key_arn) AND the first element of the kms_protected_data tuple AND the target
    of identity's HAS_ACCESS_TO expansion (which covers all CLOUD_RESOURCE nodes for admins).
    """
    _patch_cloud_posture_tools(monkeypatch)

    from cloud_posture.tools.aws_kms import KmsKey

    # The identity listing must be present so identity writes HAS_ACCESS_TO
    # against the kms-key CLOUD_RESOURCE node.  The admin role covers all
    # CLOUD_RESOURCE nodes via the wildcard-expand in _write_access_edges.
    listing = _admin_identity_listing()

    sources = ScanSources(
        identity_listing=listing,
        cloud_kms_keys=(
            KmsKey(
                key_arn=_KMS_ARN,
                is_public=False,  # not about public exposure; about access to data-protecting key
            ),
        ),
        cloud_kms_protected_data=((_KMS_ARN, "pii"),),
    )

    res = await scan_run(
        session_factory=session_factory,
        tenant=_TENANT,
        sources=sources,
        workspace_root=tmp_path / "ws",
    )

    failed = [f for f in res.feeders if not f.ok]
    assert not failed, f"feeder(s) failed: {failed}"

    feeder_names = {f.agent for f in res.feeders}
    assert "cloud-posture" in feeder_names, f"cloud-posture missing from {feeder_names}"
    assert "identity" in feeder_names, f"identity missing from {feeder_names}"

    path_types = [p.path_type for p in res.confirmed]
    assert "kms_key_access" in path_types, (
        f"kms_key_access path not confirmed; got path_types={path_types}. "
        f"Check join keys: cloud-posture record_kms_keys external_id={_KMS_ARN!r}; "
        f"cloud-posture record_kms_protected_data first tuple element={_KMS_ARN!r}; "
        f"identity admin role {_ADMIN_ROLE_ARN!r} expands HAS_ACCESS_TO all CLOUD_RESOURCE nodes."
    )


# ---------------------------------------------------------------------------
# Task 1 (Tier-3): multi-cloud-posture seam → cross-cloud exposed_kms_key +
# exposed_database detectors fire via the mc_* injectable sources
# ---------------------------------------------------------------------------

_AZURE_KV_KEY_ID = "https://my-vault.vault.azure.net/keys/my-key/abc123"
_GCP_SQL_INSTANCE_ID = "projects/my-project/instances/my-sql-instance"


@pytest.mark.asyncio
async def test_scan_run_multicloud_exposed_kms_and_db_fire(
    tmp_path: Path,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Injected Azure KMS key + GCP SQL instance (both public) → exposed_kms_key + exposed_database.

    multi-cloud-posture feeder receives:
      - mc_kms_keys: one public Azure Key Vault key →
          record_kms_keys writes CLOUD_RESOURCE{kind=kms-key, is_public=True}
      - mc_sql_instances: one public GCP Cloud SQL instance →
          record_sql_instances writes CLOUD_RESOURCE{kind=rds-instance, is_public=True}

    analyze → find_exposed_kms_key → confirmed path_type == "exposed_kms_key"
    analyze → find_exposed_database → confirmed path_type == "exposed_database"

    This proves the cross-cloud seam: the same cloud-agnostic detectors that fire
    for AWS (cloud-posture) now fire for Azure/GCP via multi-cloud-posture.
    """
    from multi_cloud_posture.tools.kg_writer import KmsKeyRecord, SqlInstanceRecord

    sources = ScanSources(
        mc_kms_keys=(
            KmsKeyRecord(
                key_id=_AZURE_KV_KEY_ID,
                is_public=True,
            ),
        ),
        mc_sql_instances=(
            SqlInstanceRecord(
                instance_id=_GCP_SQL_INSTANCE_ID,
                is_public=True,
                engine="postgres",
            ),
        ),
    )

    res = await scan_run(
        session_factory=session_factory,
        tenant="t-mc",
        sources=sources,
        workspace_root=tmp_path / "ws",
    )

    assert all(f.ok for f in res.feeders), [f for f in res.feeders if not f.ok]

    feeder_names = {f.agent for f in res.feeders}
    assert "multi-cloud-posture" in feeder_names, (
        f"multi-cloud-posture feeder missing from {feeder_names}"
    )

    types = {p.path_type for p in res.confirmed}
    assert "exposed_kms_key" in types, (
        f"exposed_kms_key not confirmed; got path_types={types}. "
        f"Check multi-cloud-posture wrote CLOUD_RESOURCE{{kind=kms-key, is_public=True}} "
        f"for {_AZURE_KV_KEY_ID!r} and find_exposed_kms_key picked it up."
    )
    assert "exposed_database" in types, (
        f"exposed_database not confirmed; got path_types={types}. "
        f"Check multi-cloud-posture wrote CLOUD_RESOURCE{{kind=rds-instance, is_public=True}} "
        f"for {_GCP_SQL_INSTANCE_ID!r} and find_exposed_database picked it up."
    )


# ---------------------------------------------------------------------------
# Task 4 (Tier-3): expected-loss ordering — crown-jewel outranks single-store
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_crown_jewel_outranks_single_store_by_expected_loss(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Task 4 (B3): analyze returns confirmed paths ordered by expected loss, not flat severity.

    Two ``fine_grained_data`` paths (severity=60, count=1) are inserted into a shared graph:
      - crown-jewel principal "zzz-crown" reaches 5 data stores  → blast=5, higher expected loss
      - single-store principal "aaa-single" reaches 1 data store → blast=1, lower expected loss

    Titles are chosen so that alphabetically "aaa-single" PRECEDES "zzz-crown": the old
    flat-severity sort (``-severity, -count, title``) resolves the tie by title and puts
    single-store FIRST.  After wiring ``rank_by_expected_loss`` into ``analyze``, the
    crown-jewel path's higher blast radius should put it FIRST instead.

    This test proves the wire: it FAILS on the pre-wiring flat sort and PASSES after.
    """
    from charter.memory import SemanticStore
    from charter.memory.graph_types import EdgeType, NodeCategory
    from meta_harness.scan import analyze

    _T4 = "t-crown-jewel-rank"
    store = SemanticStore(session_factory)

    _R = NodeCategory.CLOUD_RESOURCE.value
    _ID = NodeCategory.IDENTITY.value
    _DC = NodeCategory.DATA_CLASSIFICATION.value

    # --- Single-store principal inserted FIRST so it appears first in the flat-sort groups dict ---
    # Under the old flat-severity sort (stable, equal keys), insertion order is preserved and
    # single-store comes first.  After wiring rank_by_expected_loss, crown-jewel (blast=5) wins.
    ss_principal = await store.upsert_entity(
        tenant_id=_T4,
        entity_type=_ID,
        external_id="arn:aws:iam::1:role/aaa-single",
        properties={},
    )
    ss_res = await store.upsert_entity(
        tenant_id=_T4,
        entity_type=_R,
        external_id="arn:aws:s3:::single-bucket",
        properties={"is_public": True},
    )
    ss_dc = await store.upsert_entity(
        tenant_id=_T4,
        entity_type=_DC,
        external_id="arn:aws:s3:::single-bucket/pii",
        properties={"data_type": "ssn"},
    )
    await store.add_relationship(
        tenant_id=_T4,
        src_entity_id=ss_principal,
        dst_entity_id=ss_res,
        relationship_type=EdgeType.HAS_ACCESS_TO.value,
        properties={},
    )
    await store.add_relationship(
        tenant_id=_T4,
        src_entity_id=ss_res,
        dst_entity_id=ss_dc,
        relationship_type=EdgeType.EXPOSES_DATA.value,
        properties={},
    )

    # --- Crown-jewel principal inserted SECOND, so it appears LAST under the old flat-sort ---
    # Both paths: fine_grained_data, sev=60, count=1, same title — equal flat-sort keys.
    # Old stable sort preserves insertion order → single-store (inserted first) wins flat-sort.
    # rank_by_expected_loss gives crown-jewel blast=5 vs single-store blast=1, so crown-jewel wins.
    cj_principal = await store.upsert_entity(
        tenant_id=_T4,
        entity_type=_ID,
        external_id="arn:aws:iam::1:role/zzz-crown",
        properties={},
    )
    for i in range(5):
        cj_res = await store.upsert_entity(
            tenant_id=_T4,
            entity_type=_R,
            external_id=f"arn:aws:s3:::crown-bucket-{i}",
            properties={"is_public": True},
        )
        cj_dc = await store.upsert_entity(
            tenant_id=_T4,
            entity_type=_DC,
            external_id=f"arn:aws:s3:::crown-bucket-{i}/pii",
            properties={"data_type": "ssn"},
        )
        await store.add_relationship(
            tenant_id=_T4,
            src_entity_id=cj_principal,
            dst_entity_id=cj_res,
            relationship_type=EdgeType.HAS_ACCESS_TO.value,
            properties={},
        )
        await store.add_relationship(
            tenant_id=_T4,
            src_entity_id=cj_res,
            dst_entity_id=cj_dc,
            relationship_type=EdgeType.EXPOSES_DATA.value,
            properties={},
        )

    # --- Run analyze and check ordering ---
    result = await analyze(store, _T4)

    assert result.confirmed, "expected at least two confirmed attack paths"
    assert len(result.confirmed) >= 2, (
        f"expected at least 2 confirmed paths; got {[p.title for p in result.confirmed]}"
    )

    # Both path types are fine_grained_data (sev=60, count=1).
    # All titles are identical ("Principal has access to public ssn data") — ties on severity+count+title.
    # Under the OLD flat-severity sort: single-store (ss_principal, inserted first) wins stable tie.
    # Under rank_by_expected_loss: crown-jewel (blast=5 via 5 data stores) outranks single-store
    # (blast=1 via 1 data store).  Crown-jewel path must be confirmed[0].
    first = result.confirmed[0]
    assert cj_principal in first.entities, (
        f"crown-jewel path (entity={cj_principal!r}, blast=5) must be confirmed[0] under "
        f"expected-loss ordering. Got confirmed[0]: entities={first.entities!r}. "
        f"All confirmed paths: {[(p.entities,) for p in result.confirmed]}. "
        "If this fails, analyze() is still using flat-severity sort instead of rank_by_expected_loss."
    )


# ---------------------------------------------------------------------------
# Task 4 (Cycle 1): injectable kev/epss maps → KEV flag reaches confirmed path
# ---------------------------------------------------------------------------

# CVE id produced by the existing _patch_trivy stub (Log4Shell) — verbatim, no typos.
_KEV_CVE_ID = "CVE-2021-44228"

# Tenant isolated from other e2e tests (no cross-contamination via shared SQLite).
_KEV_TENANT = "t-kev-e2e"

# ECS workload ARN — distinct from _ECS_ARN used in Task 11 to avoid tenant bleed.
_KEV_ECS_ARN = "arn:aws:ecs:us-east-1:123456789012:service/cluster/kev-svc"


@pytest.mark.asyncio
async def test_scan_run_kev_reaches_confirmed_path(
    tmp_path: Path,
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Task 4 (Cycle 1): vuln_kev_cve_ids injected through ScanSources reaches a KEV-flagged
    confirmed attack path.

    Seeding pattern mirrors test_scan_run_stored_secret_to_data_fires (Task 11):
      - cloud-posture ECS workload (is_public=True, image_ref=_IMAGE_REF)
          writes CLOUD_RESOURCE{is_public} --RUNS_IMAGE--> image-node
      - vulnerability trivy stub (image_ref=_IMAGE_REF, _patch_trivy)
          writes image-node --VULNERABLE_TO--> CVE-2021-44228

    With vuln_kev_cve_ids=frozenset({_KEV_CVE_ID}), the vulnerability kg_writer
    stamps kev=True on the VULNERABLE_TO edge for CVE-2021-44228.

    analyze → find_supply_chain_sbom subsumes find_internet_exposed_vulnerable_workload
    (the trivy stub also writes the SBOM package chain) → AttackPath.kev is True on the
    subsuming supply_chain_sbom path.

    This proves the injectable seam is wired end-to-end: without the ScanSources fields
    (Task 4 Step 2), this test fails with AttributeError; with the fields but without
    passing them through the feeder, p.kev stays False.
    """
    _patch_cloud_posture_tools(monkeypatch)
    _patch_trivy(monkeypatch)

    from cloud_posture.tools.aws_ecs import EcsWorkload

    sources = ScanSources(
        cloud_ecs_workloads=(
            EcsWorkload(
                service_arn=_KEV_ECS_ARN,
                image_ref=_IMAGE_REF,
                is_public=True,
                task_role_arn="",
                env_values=(),
            ),
        ),
        vuln_image_refs=(_IMAGE_REF,),
        vuln_kev_cve_ids=frozenset({_KEV_CVE_ID}),
        vuln_epss_scores={_KEV_CVE_ID: 0.95},
    )

    res = await scan_run(
        session_factory=session_factory,
        tenant=_KEV_TENANT,
        sources=sources,
        workspace_root=tmp_path / "ws",
    )

    # Guard: both feeders must have completed without error.
    assert all(f.ok for f in res.feeders), [f for f in res.feeders if not f.ok]

    feeder_names = {f.agent for f in res.feeders}
    assert "cloud-posture" in feeder_names, f"cloud-posture feeder missing from {feeder_names}"
    assert "vulnerability" in feeder_names, f"vulnerability feeder missing from {feeder_names}"

    # Core assertion: at least one confirmed path must carry kev=True.
    kev_paths = [p for p in res.confirmed if p.kev]
    assert kev_paths, (
        f"a KEV-flagged confirmed path must exist after injecting vuln_kev_cve_ids={{{_KEV_CVE_ID!r}}}; "
        f"got confirmed paths: {[(p.path_type, p.kev) for p in res.confirmed]}. "
        "Check that ScanSources.vuln_kev_cve_ids is wired through vulnerability_run(kev_cve_ids=...)."
    )

    # Sanity + regression guard: the vulnerability agent writes both an image-level CVE and the
    # SBOM package chain, so find_supply_chain_sbom (Cycle 2, #802) subsumes the bare
    # internet_exposed_vulnerable workload (finer, package-level attribution). KEV/EPSS must
    # survive that subsumption — attack_paths must thread cve_kev/cve_epss onto the SBOM group,
    # else a known-exploited path silently loses its top prioritization signal.
    assert any(p.path_type == "supply_chain_sbom" for p in kev_paths), (
        f"expected supply_chain_sbom (subsumes internet_exposed_vulnerable) among KEV paths; "
        f"got {[p.path_type for p in kev_paths]}"
    )


# ---------------------------------------------------------------------------
# Cycle 3 Task 3: cross-scan e2e + guard — ATTACK_PATH durability proof
# ---------------------------------------------------------------------------

_C3_TENANT = "t-c3-attack-path-durability"


@pytest.mark.asyncio
async def test_scan_run_persists_attack_path_node_and_emits_ocsf(
    tmp_path: Path,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Cycle 3 P3 cross-scan e2e: scan_run persists ATTACK_PATH nodes + emits OCSF 2005 findings.

    Scene: fine_grained_data / stored_secret (public PII bucket + admin identity) — the
    same scene as test_scan_run_yields_ranked_public_data_path.

    Run 1 assertions:
      (a) res.ocsf_findings is non-empty; every entry has class_uid == 2005.
      (b) At least one ATTACK_PATH node exists in the store for the tenant.
      (c) The ATTACK_PATH node carries path_type, expected_loss, first_seen, last_seen.

    Run 2 (same store, same sources) assertions — cross-scan dedup proof:
      (d) STILL exactly one ATTACK_PATH node per path (no duplicate).
      (e) first_seen is UNCHANGED from Run 1.
      (f) last_seen is bumped (Run 2 timestamp > Run 1 timestamp).
    """
    from charter.memory import SemanticStore
    from charter.memory.graph_types import NodeCategory

    feeds_dir = tmp_path / "feeds"
    inv, obj = _write_public_pii_inventory(feeds_dir)
    listing = _admin_identity_listing()

    sources = ScanSources(
        ds_inventory_feed=inv,
        ds_objects_feed=obj,
        identity_listing=listing,
    )

    # ---- Run 1 ----
    _now1 = datetime(2026, 7, 6, 10, 0, 0, tzinfo=UTC)

    # Patch datetime.now in scan_pipeline so Run 1 uses _now1.
    from unittest.mock import patch

    import nexus_runtime.scan_pipeline as _sp_mod

    with patch.object(_sp_mod, "datetime") as mock_dt:
        mock_dt.now.return_value = _now1
        mock_dt.side_effect = lambda *a, **kw: datetime(*a, **kw)
        res1 = await scan_run(
            session_factory=session_factory,
            tenant=_C3_TENANT,
            sources=sources,
            workspace_root=tmp_path / "ws1",
        )

    # (a) OCSF findings present + all class_uid == 2005
    assert res1.ocsf_findings, (
        "expected non-empty ocsf_findings from scan_run — persist=True should emit OCSF 2005 findings"
    )
    for finding in res1.ocsf_findings:
        # findings are wrapped in NexusEnvelope; the payload is in finding["payload"]
        payload = finding.get("payload", finding)
        assert payload.get("class_uid") == 2005, (
            f"each finding must have class_uid==2005 (OCSF Incident Finding); got {payload.get('class_uid')}"
        )

    # (b) ATTACK_PATH node exists in the store
    store = SemanticStore(session_factory)
    nodes_after_run1 = await store.list_entities_by_type(
        tenant_id=_C3_TENANT,
        entity_type=NodeCategory.ATTACK_PATH.value,
    )
    assert nodes_after_run1, (
        "expected at least one ATTACK_PATH node in the store after scan_run with persist=True"
    )

    # (c) Each node carries the expected properties
    for node in nodes_after_run1:
        props = node.properties
        assert "path_type" in props, f"ATTACK_PATH node missing path_type; props={props}"
        assert "expected_loss" in props, f"ATTACK_PATH node missing expected_loss; props={props}"
        assert "first_seen" in props, f"ATTACK_PATH node missing first_seen; props={props}"
        assert "last_seen" in props, f"ATTACK_PATH node missing last_seen; props={props}"

    # Record first_seen values from Run 1 for cross-scan comparison.
    first_seen_by_id = {node.entity_id: node.properties["first_seen"] for node in nodes_after_run1}
    last_seen_by_id_run1 = {
        node.entity_id: node.properties["last_seen"] for node in nodes_after_run1
    }

    # ---- Run 2 (same store, same sources, later timestamp) ----
    _now2 = datetime(2026, 7, 6, 11, 0, 0, tzinfo=UTC)  # 1 hour later

    with patch.object(_sp_mod, "datetime") as mock_dt2:
        mock_dt2.now.return_value = _now2
        mock_dt2.side_effect = lambda *a, **kw: datetime(*a, **kw)
        res2 = await scan_run(
            session_factory=session_factory,
            tenant=_C3_TENANT,
            sources=sources,
            workspace_root=tmp_path / "ws2",
        )

    nodes_after_run2 = await store.list_entities_by_type(
        tenant_id=_C3_TENANT,
        entity_type=NodeCategory.ATTACK_PATH.value,
    )

    # (d) No duplicate nodes: same count (or equal node ids)
    assert len(nodes_after_run2) == len(nodes_after_run1), (
        f"cross-scan dedup failed: Run 1 had {len(nodes_after_run1)} ATTACK_PATH node(s), "
        f"Run 2 has {len(nodes_after_run2)} — expected no new duplicates."
    )
    ids_run2 = {node.entity_id for node in nodes_after_run2}
    ids_run1 = {node.entity_id for node in nodes_after_run1}
    assert ids_run2 == ids_run1, (
        f"cross-scan dedup failed: node ids changed between runs. "
        f"Run 1 ids={ids_run1}, Run 2 ids={ids_run2}"
    )

    # (e) first_seen unchanged
    for node in nodes_after_run2:
        orig_first_seen = first_seen_by_id.get(node.entity_id)
        assert node.properties["first_seen"] == orig_first_seen, (
            f"first_seen was mutated on second scan for node {node.entity_id!r}: "
            f"expected {orig_first_seen!r}, got {node.properties['first_seen']!r}"
        )

    # (f) last_seen bumped
    for node in nodes_after_run2:
        run1_last = last_seen_by_id_run1.get(node.entity_id)
        run2_last = node.properties.get("last_seen")
        assert run2_last is not None, f"last_seen missing on node {node.entity_id!r} after Run 2"
        assert run2_last > run1_last, (  # type: ignore[operator]
            f"last_seen not bumped for node {node.entity_id!r}: "
            f"Run 1 last_seen={run1_last!r}, Run 2 last_seen={run2_last!r}"
        )

    # Run 2 also emits findings.
    assert res2.ocsf_findings, "expected non-empty ocsf_findings from second scan_run"


@pytest.mark.asyncio
async def test_analyze_default_persist_false_writes_no_attack_path_nodes(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Cycle 3 P3 guard: analyze() with default persist=False writes NO ATTACK_PATH nodes.

    Proves that every existing caller is byte-unaffected — the default is the safe no-op path.
    """
    from charter.memory import SemanticStore
    from charter.memory.graph_types import EdgeType, NodeCategory
    from meta_harness.scan import analyze

    _GUARD_TENANT = "t-c3-guard-no-persist"
    store = SemanticStore(session_factory)

    # Seed a minimal graph that forms a confirmed path (fine_grained_data).
    _R = NodeCategory.CLOUD_RESOURCE.value
    _ID = NodeCategory.IDENTITY.value
    _DC = NodeCategory.DATA_CLASSIFICATION.value

    principal = await store.upsert_entity(
        tenant_id=_GUARD_TENANT,
        entity_type=_ID,
        external_id="arn:aws:iam::1:role/GuardRole",
        properties={},
    )
    resource = await store.upsert_entity(
        tenant_id=_GUARD_TENANT,
        entity_type=_R,
        external_id="arn:aws:s3:::guard-bucket",
        properties={"is_public": True},
    )
    dc = await store.upsert_entity(
        tenant_id=_GUARD_TENANT,
        entity_type=_DC,
        external_id="arn:aws:s3:::guard-bucket/pii",
        properties={"data_type": "ssn"},
    )
    await store.add_relationship(
        tenant_id=_GUARD_TENANT,
        src_entity_id=principal,
        dst_entity_id=resource,
        relationship_type=EdgeType.HAS_ACCESS_TO.value,
        properties={},
    )
    await store.add_relationship(
        tenant_id=_GUARD_TENANT,
        src_entity_id=resource,
        dst_entity_id=dc,
        relationship_type=EdgeType.EXPOSES_DATA.value,
        properties={},
    )

    # Call analyze() with the DEFAULT (persist=False).
    result = await analyze(store, _GUARD_TENANT)

    # The path must still be confirmed (analyze returns it) — we are only checking side-effects.
    assert result.confirmed, "expected at least one confirmed path (scene is fine_grained_data)"

    # Guard: ocsf_findings must be empty (persist=False → no emission).
    assert result.ocsf_findings == [], (
        f"persist=False must produce ocsf_findings=[] but got {result.ocsf_findings!r}"
    )

    # Guard: NO ATTACK_PATH nodes must have been written.
    nodes = await store.list_entities_by_type(
        tenant_id=_GUARD_TENANT,
        entity_type=NodeCategory.ATTACK_PATH.value,
    )
    assert len(nodes) == 0, (
        f"persist=False (default) must write 0 ATTACK_PATH nodes, but found {len(nodes)}: "
        f"{[n.entity_id for n in nodes]}"
    )


# ---------------------------------------------------------------------------
# Task 4 (cycle3-moat-productization): rbac_escalation_to_cloud_data fires
# + subsumes bare rbac_privilege_escalation for the same SA.
# ---------------------------------------------------------------------------

_DEEP_RBAC_SA = "deep-admin-sa"
_DEEP_RBAC_NAMESPACE = "prod"
_DEEP_RBAC_ROLE = "cluster-admin"
_DEEP_RBAC_IRSA_ROLE_ARN = "arn:aws:iam::123456789012:role/deep-rbac-cloud-role"


class _AdminAndIrsaClusterReader:
    """A ClusterReader whose SA 'deep-admin-sa' is both cluster-admin AND IRSA-mapped.

    The same SA has:
      - A BINDS edge to a ClusterRole with wildcard rules (is_admin=True)
      - An IRSA annotation ``eks.amazonaws.com/role-arn`` pointing to _DEEP_RBAC_IRSA_ROLE_ARN

    k8s-posture record_inventory writes both edges from the real inventory parser:
      K8S_OBJECT(SA) --BINDS--> K8S_OBJECT{is_admin=True}
      K8S_OBJECT(SA) --IRSA_MAPPING--> IDENTITY(_DEEP_RBAC_IRSA_ROLE_ARN)

    identity's AdministratorAccess then writes:
      IDENTITY(deep-rbac-cloud-role) --HAS_ACCESS_TO--> CLOUD_RESOURCE(acme-pii)

    data-security writes:
      CLOUD_RESOURCE(acme-pii) --EXPOSES_DATA--> DATA_CLASSIFICATION(pii)

    Full chain for find_rbac_escalation_to_cloud_data:
      K8S_OBJECT(SA) --BINDS--> K8S_OBJECT{is_admin=True}
      K8S_OBJECT(SA) --IRSA_MAPPING--> IDENTITY(deep-rbac-cloud-role)
        --HAS_ACCESS_TO--> CLOUD_RESOURCE(acme-pii)
        --EXPOSES_DATA--> DATA_CLASSIFICATION(pii)
    """

    def list_namespaces(self) -> list[dict]:  # type: ignore[type-arg]
        return [{"metadata": {"name": _DEEP_RBAC_NAMESPACE}}]

    def list_service_accounts(self) -> list[dict]:  # type: ignore[type-arg]
        return [
            {
                "metadata": {
                    "name": _DEEP_RBAC_SA,
                    "namespace": _DEEP_RBAC_NAMESPACE,
                    "annotations": {
                        "eks.amazonaws.com/role-arn": _DEEP_RBAC_IRSA_ROLE_ARN,
                    },
                }
            }
        ]

    def list_roles(self) -> list[dict]:  # type: ignore[type-arg]
        return [
            {
                "kind": "ClusterRole",
                "metadata": {"name": _DEEP_RBAC_ROLE},
                "rules": [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}],
            }
        ]

    def list_role_bindings(self) -> list[dict]:  # type: ignore[type-arg]
        return [
            {
                "kind": "ClusterRoleBinding",
                "metadata": {"name": f"{_DEEP_RBAC_ROLE}-binding"},
                "roleRef": {"kind": "ClusterRole", "name": _DEEP_RBAC_ROLE},
                "subjects": [
                    {
                        "kind": "ServiceAccount",
                        "name": _DEEP_RBAC_SA,
                        "namespace": _DEEP_RBAC_NAMESPACE,
                    }
                ],
            }
        ]


def _deep_rbac_identity_listing() -> IdentityListing:
    """An IAM role at _DEEP_RBAC_IRSA_ROLE_ARN with AdministratorAccess.

    identity's _synthesize_admin_grants detects AdministratorAccess and writes
    HAS_ACCESS_TO every CLOUD_RESOURCE — including acme-pii from data-security.
    """
    role = IamRole(
        arn=_DEEP_RBAC_IRSA_ROLE_ARN,
        name="deep-rbac-cloud-role",
        role_id="AROA-DEEPRBAC",
        create_date=_NOW,
        last_used_at=_NOW,
        assume_role_policy_document={},
        attached_policy_arns=(_ADMIN_POLICY_ARN,),
    )
    return IdentityListing(users=(), roles=(role,), groups=())


@pytest.mark.asyncio
async def test_scan_run_rbac_escalation_to_cloud_data_fires_and_subsumes(
    tmp_path: Path,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """P4a: SA that is both cluster-admin AND IRSA→data fires the deep combo + subsumes bare rbac.

    Four feeders cooperate in the shared SemanticStore:
      1. data-security writes CLOUD_RESOURCE(acme-pii, is_public=True)
                              --EXPOSES_DATA--> DATA_CLASSIFICATION(pii)
      2. identity writes IDENTITY(deep-rbac-cloud-role)
                         --HAS_ACCESS_TO--> CLOUD_RESOURCE(acme-pii)
         (AdministratorAccess expands to all resources)
      3. k8s-posture (cluster_reader=_AdminAndIrsaClusterReader) writes:
           K8S_OBJECT(SA:prod/deep-admin-sa) --BINDS--> K8S_OBJECT{cluster-admin, is_admin=True}
           K8S_OBJECT(SA:prod/deep-admin-sa) --IRSA_MAPPING--> IDENTITY(deep-rbac-cloud-role)

    Assertions:
      - rbac_escalation_to_cloud_data path IS present (the deep combo fired)
      - rbac_privilege_escalation path IS NOT present (subsumed by the deep combo for this SA)
    """
    feeds_dir = tmp_path / "feeds"
    inv, obj = _write_public_pii_inventory(feeds_dir)

    sources = ScanSources(
        ds_inventory_feed=inv,
        ds_objects_feed=obj,
        identity_listing=_deep_rbac_identity_listing(),
        k8s_cluster_reader=_AdminAndIrsaClusterReader(),
    )

    res = await scan_run(
        session_factory=session_factory,
        tenant="t-deep-rbac",
        sources=sources,
        workspace_root=tmp_path / "ws",
    )

    failed = [f for f in res.feeders if not f.ok]
    assert not failed, f"feeder(s) failed: {failed}"

    feeder_names = {f.agent for f in res.feeders}
    assert "k8s-posture" in feeder_names, f"k8s-posture missing from {feeder_names}"
    assert "data-security" in feeder_names, f"data-security missing from {feeder_names}"
    assert "identity" in feeder_names, f"identity missing from {feeder_names}"

    path_types = [p.path_type for p in res.confirmed]

    # The deep combo must be present.
    assert "rbac_escalation_to_cloud_data" in path_types, (
        f"rbac_escalation_to_cloud_data not confirmed; got path_types={path_types}. "
        f"Check: SA {_DEEP_RBAC_SA!r} in namespace {_DEEP_RBAC_NAMESPACE!r} must have "
        f"BOTH a BINDS edge to an is_admin role AND an IRSA_MAPPING to "
        f"{_DEEP_RBAC_IRSA_ROLE_ARN!r} which has HAS_ACCESS_TO acme-pii."
    )

    # Subject-scoped subsume proof: the combo SA must NOT also appear as a bare
    # rbac_privilege_escalation row.  Checking by entity id (not global path_type)
    # keeps this assertion correct when a second admin-only SA is added to the scene —
    # a bare rbac_privilege_escalation for a DIFFERENT SA must not block this assertion.
    from charter.memory import SemanticStore
    from charter.memory.graph_types import NodeCategory

    _sa_external_id = f"offline/namespace/{_DEEP_RBAC_NAMESPACE}/serviceaccount/{_DEEP_RBAC_SA}"
    store = SemanticStore(session_factory)
    sa_nodes = await store.list_entities_by_type(
        tenant_id="t-deep-rbac",
        entity_type=NodeCategory.K8S_OBJECT.value,
    )
    combo_sa_ids = {n.entity_id for n in sa_nodes if n.external_id == _sa_external_id}
    assert combo_sa_ids, (
        f"could not find K8S_OBJECT node with external_id={_sa_external_id!r} in store — "
        "the SA was not written; check k8s-posture record_inventory cluster_id='offline'"
    )
    bare_rbac = [
        p
        for p in res.confirmed
        if p.path_type == "rbac_privilege_escalation" and combo_sa_ids.intersection(p.entities)
    ]
    assert not bare_rbac, (
        f"combo SA {_DEEP_RBAC_SA!r} (entity ids={combo_sa_ids!r}) must be subsumed — "
        f"it must not also appear as a bare rbac_privilege_escalation path; "
        f"got bare_rbac={bare_rbac!r}. "
        "Check the subsume guard in attack_paths.find_all."
    )


# ---------------------------------------------------------------------------
# Task 5 (cycle3-moat-productization): exposed_kms_key_over_data fires
# + subsumes bare exposed_kms_key for the same key (P4b).
# ---------------------------------------------------------------------------

# Use a distinct KMS ARN to avoid tenant bleed with the G-3 / G-4 tests above.
_P4B_KMS_ARN = "arn:aws:kms:us-east-1:999988887777:key/p4b-key"
_P4B_TENANT = "t-p4b-kms-over-data"


@pytest.mark.asyncio
async def test_scan_run_exposed_kms_key_over_data_fires_and_subsumes(
    tmp_path: Path,
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """P4b: public KMS key that protects classified data fires exposed_kms_key_over_data
    and the same key is NOT also emitted as a bare exposed_kms_key (subject-scoped subsume).

    Two cloud-posture legs cooperate in the shared SemanticStore:
      1. record_kms_keys writes
             CLOUD_RESOURCE{kind=kms-key, is_public=True, external_id=_P4B_KMS_ARN}
      2. record_kms_protected_data writes
             CLOUD_RESOURCE(kms-key) --EXPOSES_DATA--> DATA_CLASSIFICATION

    The detector walk for find_exposed_kms_key_over_data (path P4b):
      CLOUD_RESOURCE{kind=kms-key, is_public=True} --EXPOSES_DATA--> DATA_CLASSIFICATION
    → path_type == "exposed_kms_key_over_data"

    Subsume assertion: the same kms-key node must NOT appear in any confirmed
    "exposed_kms_key" path (the deeper combo subsumed it).  This is checked
    subject-scoped (by the key's entity_id) — not with a global path_type assertion —
    so a second bare-public key added to the same scene would not falsely fail.

    Join keys:
      - record_kms_keys: external_id == _P4B_KMS_ARN (key_arn, written by cloud-posture)
      - record_kms_protected_data: first tuple element == _P4B_KMS_ARN (same key node upserted)
    """
    _patch_cloud_posture_tools(monkeypatch)

    from cloud_posture.tools.aws_kms import KmsKey

    sources = ScanSources(
        cloud_kms_keys=(
            KmsKey(
                key_arn=_P4B_KMS_ARN,
                is_public=True,
            ),
        ),
        cloud_kms_protected_data=((_P4B_KMS_ARN, "pii"),),
    )

    res = await scan_run(
        session_factory=session_factory,
        tenant=_P4B_TENANT,
        sources=sources,
        workspace_root=tmp_path / "ws",
    )

    failed = [f for f in res.feeders if not f.ok]
    assert not failed, f"feeder(s) failed: {failed}"

    feeder_names = {f.agent for f in res.feeders}
    assert "cloud-posture" in feeder_names, f"cloud-posture missing from {feeder_names}"

    path_types = [p.path_type for p in res.confirmed]

    # The deep combo must fire.
    assert "exposed_kms_key_over_data" in path_types, (
        f"exposed_kms_key_over_data path not confirmed; got path_types={path_types}. "
        f"Check: cloud-posture record_kms_keys wrote CLOUD_RESOURCE{{kind=kms-key, "
        f"is_public=True}} for {_P4B_KMS_ARN!r}; record_kms_protected_data wrote "
        f"CLOUD_RESOURCE(_P4B_KMS_ARN) --EXPOSES_DATA--> DATA_CLASSIFICATION; "
        "find_exposed_kms_key_over_data must find the intersection."
    )

    assert all(f.ok for f in res.feeders), [f for f in res.feeders if not f.ok]

    # Subject-scoped subsume proof: resolve the key node entity_id from the store,
    # then assert no confirmed exposed_kms_key path contains that entity_id in .entities.
    # Using subject-scoped check (not global "exposed_kms_key not in path_types") so that
    # a second bare-public key in the same scene would not break this assertion.
    from charter.memory import SemanticStore
    from charter.memory.graph_types import NodeCategory

    store = SemanticStore(session_factory)
    kms_nodes = await store.list_entities_by_type(
        tenant_id=_P4B_TENANT,
        entity_type=NodeCategory.CLOUD_RESOURCE.value,
    )
    combo_key_ids = {n.entity_id for n in kms_nodes if n.external_id == _P4B_KMS_ARN}
    assert combo_key_ids, (
        f"could not find CLOUD_RESOURCE node with external_id={_P4B_KMS_ARN!r} in store — "
        "the kms-key was not written by cloud-posture record_kms_keys"
    )

    bare_exposed = [
        p
        for p in res.confirmed
        if p.path_type == "exposed_kms_key" and combo_key_ids.intersection(p.entities)
    ]
    assert not bare_exposed, (
        f"combo kms-key {_P4B_KMS_ARN!r} (entity ids={combo_key_ids!r}) must be subsumed — "
        f"it must not also appear as a bare exposed_kms_key path; "
        f"got bare_exposed={bare_exposed!r}. "
        "Check the subsumed_kms_keys guard in attack_paths.find_all."
    )


# ---------------------------------------------------------------------------
# Cycle 2 Task 2: pipeline seam — ScanSources topology fields → CAN_REACH lands
# ---------------------------------------------------------------------------

_NET_FOOTHOLD = "arn:aws:ec2:us-east-1:111122223333:instance/i-foothold"
_NET_TARGET = "arn:aws:ec2:us-east-1:111122223333:instance/i-target"
_NET_TENANT = "t-net-topology"


@pytest.mark.asyncio
async def test_scan_run_network_topology_lands_can_reach(
    tmp_path: Path,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Cycle 2 Task 2: ScanSources topology fields → network-threat feeder fires → CAN_REACH lands.

    Two injected NetworkInstances with an SG-allowed reach:
      foothold (sg-A) → target (sg-B, ingress allows sg-A on TCP:443)

    After scan_run:
      - all feeders ok=True (no feeder exception)
      - the network-threat feeder executed
      - a CAN_REACH relationship exists in the store from foothold → target

    This is the pipeline-seam proof (Task 2). The full lateral-movement detector
    that traverses CAN_REACH → VULNERABLE_TO is Task 4.
    """
    from charter.memory.graph_types import NodeCategory
    from network_threat.tools.reachability import IngressRule, NetworkInstance, SecurityGroup

    foothold = NetworkInstance(resource_id=_NET_FOOTHOLD, security_group_ids=("sg-A",))
    target = NetworkInstance(resource_id=_NET_TARGET, security_group_ids=("sg-B",))
    sg_a = SecurityGroup(group_id="sg-A", ingress=())
    sg_b = SecurityGroup(
        group_id="sg-B",
        ingress=(IngressRule(protocol="tcp", from_port=443, to_port=443, source_sgs=("sg-A",)),),
    )

    sources = ScanSources(
        network_instances=[foothold, target],
        network_security_groups=[sg_a, sg_b],
    )

    res = await scan_run(
        session_factory=session_factory,
        tenant=_NET_TENANT,
        sources=sources,
        workspace_root=tmp_path / "ws",
    )

    # All executed feeders must have completed without exception.
    assert all(f.ok for f in res.feeders), [f for f in res.feeders if not f.ok]

    # The network-threat feeder must have executed (topology seam fires it).
    feeder_names = {f.agent for f in res.feeders}
    assert "network-threat" in feeder_names, (
        f"network-threat feeder missing from {feeder_names}; "
        "the 'needed' predicate must fire on network_instances is not None"
    )

    # A CAN_REACH edge must exist from foothold → target in the store.
    from charter.memory import SemanticStore

    store = SemanticStore(session_factory)
    endpoints = await store.list_entities_by_type(
        tenant_id=_NET_TENANT, entity_type=NodeCategory.CLOUD_RESOURCE.value
    )
    ext_ids = {e.external_id for e in endpoints}
    assert _NET_FOOTHOLD in ext_ids, (
        f"foothold node {_NET_FOOTHOLD!r} not found in store; got {ext_ids}"
    )
    assert _NET_TARGET in ext_ids, f"target node {_NET_TARGET!r} not found in store; got {ext_ids}"

    foothold_node = next(e for e in endpoints if e.external_id == _NET_FOOTHOLD)
    neighbors = await store.neighbors(
        tenant_id=_NET_TENANT,
        entity_id=foothold_node.entity_id,
        depth=1,
        edge_types=("CAN_REACH",),
    )
    neighbor_ext_ids = [n.external_id for n in neighbors]
    assert _NET_TARGET in neighbor_ext_ids, (
        f"Expected CAN_REACH edge foothold→target in the store; "
        f"foothold={_NET_FOOTHOLD!r}, neighbors={neighbor_ext_ids}. "
        "Check that network_threat.run() writes record_reachability when "
        "network_instances + security_groups are injected and semantic_store is set."
    )


# ---------------------------------------------------------------------------
# Cycle 2 Task 3: find_lateral_movement_via_reachability (derived CAN_REACH/PEERED_WITH)
# ---------------------------------------------------------------------------

# ARNs used across the three lateral-reachable e2e tests.
_LR_FOOTHOLD = "arn:aws:ec2:us-east-1:222233334444:instance/i-lr-foothold"
_LR_TARGET_HOST = "arn:aws:ec2:us-east-1:222233334444:instance/i-lr-target-host"
_LR_RDS = "arn:aws:rds:us-east-1:222233334444:db:lr-internal-db"
_LR_TENANT = "t-lateral-reachable-e2e"


@pytest.mark.asyncio
async def test_scan_run_lateral_reachable_vuln_host_fires(
    tmp_path: Path,
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Task 3a: CAN_REACH foothold → vulnerable host → lateral_reachable path.

    Three feeders cooperate via the shared SemanticStore:

      1. cloud-posture (record_ec2_workloads) writes
             CLOUD_RESOURCE{external_id=_LR_FOOTHOLD, is_public=True}
      2. vulnerability (trivy host scan, relabelled to _LR_TARGET_HOST) writes
             CLOUD_RESOURCE{external_id=_LR_TARGET_HOST} --VULNERABLE_TO--> CVE
      3. network-threat (reach_grants) writes
             CAN_REACH{method=lateral_sg}  _LR_FOOTHOLD → _LR_TARGET_HOST

    The e2e join key: NetworkInstance.resource_id == instance_arn for BOTH nodes.
    cloud-posture keys on instance_arn (Ec2Workload.instance_arn).
    vulnerability keys on vuln_host_target_arn (agent relabels _artifact_name).
    network-threat keys on NetworkInstance.resource_id.
    All three use the SAME ARN string → nodes converge.

    analyze → find_lateral_movement_via_reachability → confirmed path_type=="lateral_reachable"
    with impact=="vulnerable_host".
    """
    _patch_cloud_posture_tools(monkeypatch)
    _patch_trivy_host_scan(monkeypatch)

    from cloud_posture.tools.aws_ec2 import Ec2Workload
    from network_threat.tools.reachability import IngressRule, NetworkInstance, SecurityGroup

    foothold_inst = Ec2Workload(instance_arn=_LR_FOOTHOLD, is_public=True)

    # SG topology: foothold is in sg-lr-A; target is in sg-lr-B which allows sg-lr-A → CAN_REACH.
    sg_a = SecurityGroup(group_id="sg-lr-A", ingress=())
    sg_b = SecurityGroup(
        group_id="sg-lr-B",
        ingress=(IngressRule(protocol="tcp", from_port=443, to_port=443, source_sgs=("sg-lr-A",)),),
    )
    foothold_net = NetworkInstance(resource_id=_LR_FOOTHOLD, security_group_ids=("sg-lr-A",))
    target_net = NetworkInstance(resource_id=_LR_TARGET_HOST, security_group_ids=("sg-lr-B",))

    sources = ScanSources(
        cloud_ec2_workloads=(foothold_inst,),
        vuln_host_target="/mnt/rootfs",
        vuln_host_target_arn=_LR_TARGET_HOST,
        network_instances=[foothold_net, target_net],
        network_security_groups=[sg_a, sg_b],
    )

    res = await scan_run(
        session_factory=session_factory,
        tenant=_LR_TENANT,
        sources=sources,
        workspace_root=tmp_path / "ws",
    )

    failed = [f for f in res.feeders if not f.ok]
    assert not failed, f"feeder(s) failed: {failed}"

    feeder_names = {f.agent for f in res.feeders}
    assert "cloud-posture" in feeder_names, f"cloud-posture missing from {feeder_names}"
    assert "vulnerability" in feeder_names, f"vulnerability missing from {feeder_names}"
    assert "network-threat" in feeder_names, f"network-threat missing from {feeder_names}"

    path_types = [p.path_type for p in res.confirmed]
    assert "lateral_reachable" in path_types, (
        f"lateral_reachable path not confirmed; got path_types={path_types}. "
        f"Join-key check: cloud-posture Ec2Workload.instance_arn={_LR_FOOTHOLD!r} (is_public=True); "
        f"vuln_host_target_arn={_LR_TARGET_HOST!r} (VULNERABLE_TO node keyed on same ARN); "
        f"NetworkInstance.resource_id matches both ARNs so CAN_REACH edges land on the same nodes."
    )

    # Verify the hit carries the right impact.
    lr_paths = [p for p in res.confirmed if p.path_type == "lateral_reachable"]
    assert any("vulnerable_host" in p.title for p in lr_paths), (
        f"expected 'vulnerable_host' in lateral_reachable title; "
        f"got titles: {[p.title for p in lr_paths]}"
    )


@pytest.mark.asyncio
async def test_scan_run_lateral_reachable_rds_datastore_fires(
    tmp_path: Path,
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Task 3b: CAN_REACH foothold → RDS instance → lateral_reachable sensitive_resource.

    Two cloud-posture legs cooperate with the network-threat feeder:

      1. cloud-posture (record_ec2_workloads) writes
             CLOUD_RESOURCE{external_id=_LR_FOOTHOLD, is_public=True}
      2. cloud-posture (record_rds_instances) writes
             CLOUD_RESOURCE{external_id=_LR_RDS, kind=rds-instance}
      3. network-threat (reach_grants) writes
             CAN_REACH{method=lateral_sg}  _LR_FOOTHOLD → _LR_RDS

    The e2e join key: NetworkInstance.resource_id == RdsInstance.instance_arn == _LR_RDS.
    record_rds_instances keys on instance_arn; network-threat keys on resource_id.
    Same string → the CAN_REACH edge lands ON the rds-instance node cloud-posture wrote.

    analyze → find_lateral_movement_via_reachability → confirmed path_type=="lateral_reachable"
    with impact=="sensitive_resource" (target kind in {"rds-instance", "kms-key"}).
    """
    _patch_cloud_posture_tools(monkeypatch)

    from cloud_posture.tools.aws_ec2 import Ec2Workload
    from cloud_posture.tools.aws_rds import RdsInstance
    from network_threat.tools.reachability import IngressRule, NetworkInstance, SecurityGroup

    foothold_inst = Ec2Workload(instance_arn=_LR_FOOTHOLD, is_public=True)
    rds_inst = RdsInstance(instance_arn=_LR_RDS, is_public=False, engine="mysql")

    # SG topology: foothold sg-lr-C → target sg-lr-D allows it.
    sg_c = SecurityGroup(group_id="sg-lr-C", ingress=())
    sg_d = SecurityGroup(
        group_id="sg-lr-D",
        ingress=(
            IngressRule(protocol="tcp", from_port=3306, to_port=3306, source_sgs=("sg-lr-C",)),
        ),
    )
    foothold_net = NetworkInstance(resource_id=_LR_FOOTHOLD, security_group_ids=("sg-lr-C",))
    rds_net = NetworkInstance(resource_id=_LR_RDS, security_group_ids=("sg-lr-D",))

    sources = ScanSources(
        cloud_ec2_workloads=(foothold_inst,),
        cloud_rds_instances=(rds_inst,),
        network_instances=[foothold_net, rds_net],
        network_security_groups=[sg_c, sg_d],
    )

    res = await scan_run(
        session_factory=session_factory,
        tenant=_LR_TENANT + "-rds",
        sources=sources,
        workspace_root=tmp_path / "ws",
    )

    failed = [f for f in res.feeders if not f.ok]
    assert not failed, f"feeder(s) failed: {failed}"

    feeder_names = {f.agent for f in res.feeders}
    assert "cloud-posture" in feeder_names, f"cloud-posture missing from {feeder_names}"
    assert "network-threat" in feeder_names, f"network-threat missing from {feeder_names}"

    path_types = [p.path_type for p in res.confirmed]
    assert "lateral_reachable" in path_types, (
        f"lateral_reachable path not confirmed; got path_types={path_types}. "
        f"Join-key check: cloud-posture Ec2Workload.instance_arn={_LR_FOOTHOLD!r} (is_public=True); "
        f"cloud-posture RdsInstance.instance_arn={_LR_RDS!r} (kind=rds-instance); "
        f"NetworkInstance.resource_id must equal both ARNs so CAN_REACH lands on the same nodes "
        f"that record_ec2_workloads and record_rds_instances wrote."
    )

    lr_paths = [p for p in res.confirmed if p.path_type == "lateral_reachable"]
    assert any("sensitive_resource" in p.title for p in lr_paths), (
        f"expected 'sensitive_resource' in lateral_reachable title; "
        f"got titles: {[p.title for p in lr_paths]}"
    )


@pytest.mark.asyncio
async def test_scan_run_lateral_reachable_peering_fires(
    tmp_path: Path,
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Task 3c: PEERED_WITH foothold → vulnerable host → lateral_reachable via vpc_peering.

    Two feeders cooperate:

      1. cloud-posture (record_ec2_workloads) writes
             CLOUD_RESOURCE{external_id=_LR_FOOTHOLD, is_public=True}
      2. vulnerability (trivy host scan) writes
             CLOUD_RESOURCE{external_id=_LR_TARGET_HOST} --VULNERABLE_TO--> CVE
      3. network-threat (peering_reach_grants) writes
             PEERED_WITH{method=vpc_peering}  _LR_FOOTHOLD → _LR_TARGET_HOST

    The e2e join key: VpcInstance.resource_id == instance_arn for both nodes.

    analyze → find_lateral_movement_via_reachability → confirmed path_type=="lateral_reachable"
    with reach_kind="vpc_peering" in the title.
    """
    _patch_cloud_posture_tools(monkeypatch)
    _patch_trivy_host_scan(monkeypatch)

    from cloud_posture.tools.aws_ec2 import Ec2Workload
    from network_threat.tools.reachability import VpcInstance

    foothold_inst = Ec2Workload(instance_arn=_LR_FOOTHOLD, is_public=True)

    vpc_foothold = VpcInstance(resource_id=_LR_FOOTHOLD, vpc_id="vpc-lr-1")
    vpc_target = VpcInstance(resource_id=_LR_TARGET_HOST, vpc_id="vpc-lr-2")

    sources = ScanSources(
        cloud_ec2_workloads=(foothold_inst,),
        vuln_host_target="/mnt/rootfs",
        vuln_host_target_arn=_LR_TARGET_HOST,
        network_vpc_instances=[vpc_foothold, vpc_target],
        network_vpc_peerings=frozenset({frozenset({"vpc-lr-1", "vpc-lr-2"})}),
    )

    res = await scan_run(
        session_factory=session_factory,
        tenant=_LR_TENANT + "-peering",
        sources=sources,
        workspace_root=tmp_path / "ws",
    )

    failed = [f for f in res.feeders if not f.ok]
    assert not failed, f"feeder(s) failed: {failed}"

    feeder_names = {f.agent for f in res.feeders}
    assert "cloud-posture" in feeder_names, f"cloud-posture missing from {feeder_names}"
    assert "network-threat" in feeder_names, f"network-threat missing from {feeder_names}"
    assert "vulnerability" in feeder_names, f"vulnerability missing from {feeder_names}"

    path_types = [p.path_type for p in res.confirmed]
    assert "lateral_reachable" in path_types, (
        f"lateral_reachable path not confirmed; got path_types={path_types}. "
        f"Join-key check: VpcInstance.resource_id={_LR_FOOTHOLD!r} and {_LR_TARGET_HOST!r} must "
        f"match Ec2Workload.instance_arn and vuln_host_target_arn respectively so PEERED_WITH "
        f"edges land on the same nodes that cloud-posture and vulnerability wrote."
    )

    lr_paths = [p for p in res.confirmed if p.path_type == "lateral_reachable"]
    assert any("vpc_peering" in p.title for p in lr_paths), (
        f"expected 'vpc_peering' in lateral_reachable title; "
        f"got titles: {[p.title for p in lr_paths]}"
    )


# ---------------------------------------------------------------------------
# Cycle 2 Task 4: supply_chain_sbom fires + subsumed internet_exposed_vulnerable
# ---------------------------------------------------------------------------

_SBOM_ECS_ARN = "arn:aws:ecs:us-east-1:111122223333:service/cluster/sbom-svc"
_SBOM_IMG = "myreg/sbom-app:v2.0.0"
_SBOM_TENANT = "t-supply-chain-sbom"


@pytest.mark.asyncio
async def test_scan_run_supply_chain_sbom_fires_and_subsumed(
    tmp_path: Path,
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Cycle 2 Task 4: supply_chain_sbom fires through scan_run and subsumed the image-level path.

    Two feeders cooperate in the shared SemanticStore:
      1. cloud-posture (record_workloads) writes
             CLOUD_RESOURCE{external_id=_SBOM_ECS_ARN, is_public=True}
             --RUNS_IMAGE--> CLOUD_RESOURCE{external_id=_SBOM_IMG}
      2. vulnerability (trivy image scan) writes (for _SBOM_IMG):
             CLOUD_RESOURCE{external_id=_SBOM_IMG} --VULNERABLE_TO--> CVE  (record_scan_results)
             CLOUD_RESOURCE{external_id=_SBOM_IMG}
               --CONTAINS_PACKAGE--> SBOM_PACKAGE{name=log4j-core}
               --VULNERABLE_TO--> CVE  (record_sbom_packages)

    The detector chain:
      CLOUD_RESOURCE(ecs, is_public=True)
        --RUNS_IMAGE--> CLOUD_RESOURCE(image)
        --CONTAINS_PACKAGE--> SBOM_PACKAGE{name=log4j-core}
        --VULNERABLE_TO--> CVE(CVE-2021-44228)
    → path_type == "supply_chain_sbom", title contains "log4j-core"

    Subsume: the same workload's internet_exposed_vulnerable path (image-level CVE via
    RUNS_IMAGE → VULNERABLE_TO) must NOT appear as a separate confirmed path.

    Join key: cloud-posture record_workloads keys the image node on image_ref;
    vulnerability trivy_scan sets _artifact_name to image_ref — same external_id.
    """
    _patch_cloud_posture_tools(monkeypatch)

    # Trivy stub: emits one CRITICAL CVE with a PkgName so record_sbom_packages fires.
    async def fake_trivy_sbom(image_ref: str, **_kw: Any) -> trivy_module.TrivyResult:
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

    monkeypatch.setattr(trivy_module, "trivy_image_scan", fake_trivy_sbom)

    from cloud_posture.tools.aws_ecs import EcsWorkload

    sources = ScanSources(
        cloud_ecs_workloads=(
            EcsWorkload(
                service_arn=_SBOM_ECS_ARN,
                image_ref=_SBOM_IMG,
                is_public=True,
                task_role_arn="",
                env_values=(),
            ),
        ),
        vuln_image_refs=(_SBOM_IMG,),
    )

    res = await scan_run(
        session_factory=session_factory,
        tenant=_SBOM_TENANT,
        sources=sources,
        workspace_root=tmp_path / "ws",
    )

    # All feeders must complete without exception.
    failed = [f for f in res.feeders if not f.ok]
    assert not failed, f"feeder(s) failed: {failed}"

    feeder_names = {f.agent for f in res.feeders}
    assert "cloud-posture" in feeder_names, f"cloud-posture missing from {feeder_names}"
    assert "vulnerability" in feeder_names, f"vulnerability missing from {feeder_names}"

    path_types = [p.path_type for p in res.confirmed]

    # supply_chain_sbom must fire — the named SBOM dependency.
    assert "supply_chain_sbom" in path_types, (
        f"supply_chain_sbom path not confirmed; got path_types={path_types}. "
        f"Check: cloud-posture wrote CLOUD_RESOURCE(is_public=True) --RUNS_IMAGE--> image; "
        f"vulnerability wrote CONTAINS_PACKAGE --> SBOM_PACKAGE(log4j-core) --VULNERABLE_TO--> CVE."
    )

    # The supply_chain_sbom title must name the vulnerable package.
    sbom_paths = [p for p in res.confirmed if p.path_type == "supply_chain_sbom"]
    assert any("log4j-core" in p.title for p in sbom_paths), (
        f"supply_chain_sbom title must mention the package name 'log4j-core'; "
        f"got titles: {[p.title for p in sbom_paths]}"
    )

    # internet_exposed_vulnerable must NOT appear — subsumed by the SBOM path.
    assert "internet_exposed_vulnerable" not in path_types, (
        f"internet_exposed_vulnerable must be subsumed by supply_chain_sbom for the same "
        f"workload ({_SBOM_ECS_ARN!r}); got path_types={path_types}. "
        "Check that find_all skips workloads already in subsumed_sbom_workloads."
    )


# ---------------------------------------------------------------------------
# Cycle 5 Task 1: IMDS credential theft — public EC2 + IMDSv1 + role → data
# ---------------------------------------------------------------------------

_IMDS_INSTANCE_ARN = "arn:aws:ec2:us-east-1:123456789012:instance/i-imds-e2e"
_IMDS_ROLE_ARN = "arn:aws:iam::123456789012:role/imds-e2e-role"
_IMDS_TENANT_POS = "t-imds-e2e-pos"
_IMDS_TENANT_NEG = "t-imds-e2e-neg"


@pytest.mark.asyncio
async def test_scan_run_imds_credential_theft_fires(
    tmp_path: Path,
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Cycle 5 Task 1: imds_credential_theft fires through scan_run.

    Three feeders cooperate in the shared SemanticStore:
      1. cloud-posture receives a public Ec2Workload(imdsv1_enabled=True, role_arn=...)
         via ScanSources.cloud_ec2_workloads.  record_ec2_workloads writes
             CLOUD_RESOURCE{instance_arn, is_public=True, imdsv1_enabled=True}
             --ASSUMES--> IDENTITY(imds-e2e-role)
      2. identity (AdministratorAccess on _IMDS_ROLE_ARN) writes
             IDENTITY(imds-e2e-role) --HAS_ACCESS_TO--> CLOUD_RESOURCE(acme-pii)
      3. data-security writes
             CLOUD_RESOURCE(acme-pii, is_public=True) --EXPOSES_DATA--> DATA_CLASSIFICATION

    The full IMDS cred-theft chain:
      CLOUD_RESOURCE(ec2, is_public=True, imdsv1_enabled=True)
        --ASSUMES--> IDENTITY(role)
        --HAS_ACCESS_TO--> CLOUD_RESOURCE(acme-pii)
        --EXPOSES_DATA--> DATA_CLASSIFICATION
    → path_type == "imds_credential_theft"

    Join keys: role_arn (Ec2Workload ↔ identity role); bucket (identity ↔ data-security).
    """
    _patch_cloud_posture_tools(monkeypatch)

    feeds_dir = tmp_path / "feeds"
    inv, obj = _write_public_pii_inventory(feeds_dir)

    imds_role = IamRole(
        arn=_IMDS_ROLE_ARN,
        name="imds-e2e-role",
        role_id="AROA-IMDSROLE",
        create_date=_NOW,
        last_used_at=_NOW,
        assume_role_policy_document={},
        attached_policy_arns=(_ADMIN_POLICY_ARN,),
    )
    listing = IdentityListing(users=(), roles=(imds_role,), groups=())

    from cloud_posture.tools.aws_ec2 import Ec2Workload

    sources = ScanSources(
        ds_inventory_feed=inv,
        ds_objects_feed=obj,
        identity_listing=listing,
        cloud_ec2_workloads=(
            Ec2Workload(
                instance_arn=_IMDS_INSTANCE_ARN,
                is_public=True,
                role_arn=_IMDS_ROLE_ARN,
                imdsv1_enabled=True,
            ),
        ),
    )

    res = await scan_run(
        session_factory=session_factory,
        tenant=_IMDS_TENANT_POS,
        sources=sources,
        workspace_root=tmp_path / "ws",
    )

    failed = [f for f in res.feeders if not f.ok]
    assert not failed, f"feeder(s) failed: {failed}"

    feeder_names = {f.agent for f in res.feeders}
    assert "cloud-posture" in feeder_names, f"cloud-posture missing from {feeder_names}"
    assert "data-security" in feeder_names, f"data-security missing from {feeder_names}"
    assert "identity" in feeder_names, f"identity missing from {feeder_names}"

    path_types = [p.path_type for p in res.confirmed]
    assert "imds_credential_theft" in path_types, (
        f"imds_credential_theft path not confirmed; got path_types={path_types}. "
        f"Join-key check: instance_arn={_IMDS_INSTANCE_ARN!r} (is_public=True, imdsv1_enabled=True); "
        f"role_arn={_IMDS_ROLE_ARN!r} (Ec2Workload.role_arn must equal identity role ARN); "
        f"bucket={_BUCKET_NAME!r} (identity HAS_ACCESS_TO must reach data-security EXPOSES_DATA bucket). "
        "Check record_ec2_workloads writes imdsv1_enabled property on the CLOUD_RESOURCE node."
    )


@pytest.mark.asyncio
async def test_scan_run_imds_credential_theft_imdsv2_stays_dark(
    tmp_path: Path,
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Cycle 5 Task 1 negative: IMDSv2-only instance does NOT fire imds_credential_theft.

    Same scene as the positive test but with imdsv1_enabled=False (HttpTokens=required).
    The ASSUMES + HAS_ACCESS_TO + EXPOSES_DATA chain is still present — only the
    imdsv1_enabled discriminator is False — so the detector must stay dark.
    fine_grained_data may still fire (the role has direct HAS_ACCESS_TO); that is
    expected and acceptable. Only imds_credential_theft must be absent.
    """
    _patch_cloud_posture_tools(monkeypatch)

    feeds_dir = tmp_path / "feeds-neg"
    inv, obj = _write_public_pii_inventory(feeds_dir)

    imds_role = IamRole(
        arn=_IMDS_ROLE_ARN,
        name="imds-e2e-role",
        role_id="AROA-IMDSROLE2",
        create_date=_NOW,
        last_used_at=_NOW,
        assume_role_policy_document={},
        attached_policy_arns=(_ADMIN_POLICY_ARN,),
    )
    listing = IdentityListing(users=(), roles=(imds_role,), groups=())

    from cloud_posture.tools.aws_ec2 import Ec2Workload

    sources = ScanSources(
        ds_inventory_feed=inv,
        ds_objects_feed=obj,
        identity_listing=listing,
        cloud_ec2_workloads=(
            Ec2Workload(
                instance_arn=_IMDS_INSTANCE_ARN,
                is_public=True,
                role_arn=_IMDS_ROLE_ARN,
                imdsv1_enabled=False,
            ),
        ),
    )

    res = await scan_run(
        session_factory=session_factory,
        tenant=_IMDS_TENANT_NEG,
        sources=sources,
        workspace_root=tmp_path / "ws-neg",
    )

    failed = [f for f in res.feeders if not f.ok]
    assert not failed, f"feeder(s) failed: {failed}"

    path_types = [p.path_type for p in res.confirmed]
    assert "imds_credential_theft" not in path_types, (
        f"imds_credential_theft must NOT fire for IMDSv2 instance (imdsv1_enabled=False); "
        f"got path_types={path_types}. "
        "The imdsv1_enabled=False property on the node must gate the detector dark."
    )


# ---------------------------------------------------------------------------
# Cycle 6: serverless Lambda exposure — public Lambda + execution role → data
# ---------------------------------------------------------------------------

_LAMBDA_FN_ARN = "arn:aws:lambda:us-east-1:123456789012:function/public-handler"
_LAMBDA_ROLE_ARN = "arn:aws:iam::123456789012:role/lambda-exec-e2e-role"
_LAMBDA_TENANT_POS = "t-lambda-e2e-pos"
_LAMBDA_TENANT_NEG = "t-lambda-e2e-neg"


@pytest.mark.asyncio
async def test_scan_run_serverless_lambda_exposure_fires(
    tmp_path: Path,
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Cycle 6: serverless_lambda_exposure fires through scan_run.

    Three feeders cooperate in the shared SemanticStore:
      1. cloud-posture receives a public LambdaWorkload(is_public=True, role_arn=...)
         via ScanSources.cloud_lambda_workloads.  record_lambda_workloads writes
             CLOUD_RESOURCE{function_arn, kind=lambda-function, is_public=True}
             --ASSUMES--> IDENTITY(lambda-exec-e2e-role)
      2. identity (AdministratorAccess on _LAMBDA_ROLE_ARN) writes
             IDENTITY(lambda-exec-e2e-role) --HAS_ACCESS_TO--> CLOUD_RESOURCE(acme-pii)
      3. data-security writes
             CLOUD_RESOURCE(acme-pii, is_public=True) --EXPOSES_DATA--> DATA_CLASSIFICATION

    The full serverless Lambda exposure chain:
      CLOUD_RESOURCE(lambda, kind=lambda-function, is_public=True)
        --ASSUMES--> IDENTITY(role)
        --HAS_ACCESS_TO--> CLOUD_RESOURCE(acme-pii)
        --EXPOSES_DATA--> DATA_CLASSIFICATION
    → path_type == "serverless_lambda_exposure"

    Join keys: role_arn (LambdaWorkload ↔ identity role); bucket (identity ↔ data-security).
    """
    from cloud_posture.tools.aws_lambda import LambdaWorkload

    _patch_cloud_posture_tools(monkeypatch)

    feeds_dir = tmp_path / "feeds"
    inv, obj = _write_public_pii_inventory(feeds_dir)

    lambda_role = IamRole(
        arn=_LAMBDA_ROLE_ARN,
        name="lambda-exec-e2e-role",
        role_id="AROA-LAMBDAROLE",
        create_date=_NOW,
        last_used_at=_NOW,
        assume_role_policy_document={},
        attached_policy_arns=(_ADMIN_POLICY_ARN,),
    )
    listing = IdentityListing(users=(), roles=(lambda_role,), groups=())

    sources = ScanSources(
        ds_inventory_feed=inv,
        ds_objects_feed=obj,
        identity_listing=listing,
        cloud_lambda_workloads=(
            LambdaWorkload(
                function_arn=_LAMBDA_FN_ARN,
                is_public=True,
                role_arn=_LAMBDA_ROLE_ARN,
            ),
        ),
    )

    res = await scan_run(
        session_factory=session_factory,
        tenant=_LAMBDA_TENANT_POS,
        sources=sources,
        workspace_root=tmp_path / "ws",
    )

    failed = [f for f in res.feeders if not f.ok]
    assert not failed, f"feeder(s) failed: {failed}"

    feeder_names = {f.agent for f in res.feeders}
    assert "cloud-posture" in feeder_names, f"cloud-posture missing from {feeder_names}"
    assert "data-security" in feeder_names, f"data-security missing from {feeder_names}"
    assert "identity" in feeder_names, f"identity missing from {feeder_names}"

    path_types = [p.path_type for p in res.confirmed]
    assert "serverless_lambda_exposure" in path_types, (
        f"serverless_lambda_exposure path not confirmed; got path_types={path_types}. "
        f"Join-key check: function_arn={_LAMBDA_FN_ARN!r} (is_public=True, kind=lambda-function); "
        f"role_arn={_LAMBDA_ROLE_ARN!r} (LambdaWorkload.role_arn must equal identity role ARN); "
        f"bucket={_BUCKET_NAME!r} (identity HAS_ACCESS_TO must reach data-security EXPOSES_DATA bucket). "
        "Check record_lambda_workloads writes kind=lambda-function and is_public on the node."
    )


@pytest.mark.asyncio
async def test_scan_run_serverless_lambda_exposure_private_stays_dark(
    tmp_path: Path,
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Cycle 6 negative: private Lambda (is_public=False) does NOT fire serverless_lambda_exposure.

    Same scene as the positive test but with is_public=False.
    The ASSUMES + HAS_ACCESS_TO + EXPOSES_DATA chain is still present — only the
    is_public flag is False — so the detector must stay dark.
    fine_grained_data may still fire (the role has direct HAS_ACCESS_TO); that is
    expected and acceptable. Only serverless_lambda_exposure must be absent.
    """
    from cloud_posture.tools.aws_lambda import LambdaWorkload

    _patch_cloud_posture_tools(monkeypatch)

    feeds_dir = tmp_path / "feeds-neg"
    inv, obj = _write_public_pii_inventory(feeds_dir)

    lambda_role = IamRole(
        arn=_LAMBDA_ROLE_ARN,
        name="lambda-exec-e2e-role",
        role_id="AROA-LAMBDAROLE2",
        create_date=_NOW,
        last_used_at=_NOW,
        assume_role_policy_document={},
        attached_policy_arns=(_ADMIN_POLICY_ARN,),
    )
    listing = IdentityListing(users=(), roles=(lambda_role,), groups=())

    sources = ScanSources(
        ds_inventory_feed=inv,
        ds_objects_feed=obj,
        identity_listing=listing,
        cloud_lambda_workloads=(
            LambdaWorkload(
                function_arn=_LAMBDA_FN_ARN,
                is_public=False,
                role_arn=_LAMBDA_ROLE_ARN,
            ),
        ),
    )

    res = await scan_run(
        session_factory=session_factory,
        tenant=_LAMBDA_TENANT_NEG,
        sources=sources,
        workspace_root=tmp_path / "ws-neg",
    )

    failed = [f for f in res.feeders if not f.ok]
    assert not failed, f"feeder(s) failed: {failed}"

    path_types = [p.path_type for p in res.confirmed]
    assert "serverless_lambda_exposure" not in path_types, (
        f"serverless_lambda_exposure must NOT fire for private Lambda (is_public=False); "
        f"got path_types={path_types}. "
        "The is_public=False property on the node must gate the detector dark."
    )
