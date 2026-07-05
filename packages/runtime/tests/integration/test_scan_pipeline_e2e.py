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
