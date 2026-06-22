"""Path 5 (the crown jewel) committed e2e — the full 4-hop REAL chain.

The single most dangerous pattern, assembled from EVERY feeder verified tonight, all through
the agents' own code on one moto session (+ real trivy):

- data-security's real S3 path → public PII bucket node + EXPOSES_DATA.
- cloud-posture's real ECS reader → internet-exposed workload (real 0.0.0.0/0 SG) +
  RUNS_IMAGE → image + ASSUMES → the task role.
- identity's real `_fine_grained_grants` → the task role's concrete s3:GetObject on that
  bucket → record_access → HAS_ACCESS_TO.
- vulnerability's real `record_scan_results` (real trivy fs) → CVEs on the SAME image node.
- `KgQuery.find_crown_jewel_exposure` lights up the exposed→vulnerable→assumes→reaches-data chain.

No hand-faked findings anywhere. ECS/IAM/S3 legs hermetic (moto); vuln leg trivy-gated.
"""

import json

import pytest
from identity.agent import _fine_grained_grants
from identity.kg_writer import KnowledgeGraphWriter as IdentityKgWriter
from identity.tools.aws_iam import (
    IdentityListing,
    _list_groups,
    _list_policies,
    _list_roles,
    _list_users,
)
from meta_harness.kg_query import KgQuery

from fleet_testkit import MotoBucket, drive_data_security, in_memory_semantic_store
from fleet_testkit.moto_aws import (
    drive_cloud_workloads,
    moto_all_clients,
    setup_ecs_workload,
)
from fleet_testkit.vuln_scan import drive_vulnerability, trivy_available

pytestmark = pytest.mark.skipif(not trivy_available, reason="trivy binary not installed")

_TENANT = "tenant-path5"
_SSN = b"patient ssn 123-45-6789 on file\n"
_BUCKET = "acme-pii"
_IMAGE_REF = "myreg/app:1.0"
_READ_DOC = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "s3:GetObject", "Resource": f"arn:aws:s3:::{_BUCKET}/*"}
        ],
    }
)


def _list_identities(iam: object) -> IdentityListing:
    degraded: list[dict[str, str]] = []
    return IdentityListing(
        users=tuple(_list_users(iam, degraded)),
        roles=tuple(_list_roles(iam, degraded)),
        groups=tuple(_list_groups(iam, degraded)),
        policies=tuple(_list_policies(iam, degraded)),
        degraded=tuple(degraded),
    )


def _seed_task_role(iam: object) -> str:
    policy_arn = iam.create_policy(  # type: ignore[attr-defined]
        PolicyName="ReadAcmePii", PolicyDocument=_READ_DOC
    )["Policy"]["Arn"]
    role_arn = iam.create_role(  # type: ignore[attr-defined]
        RoleName="task-role",
        AssumeRolePolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": []}),
    )["Role"]["Arn"]
    iam.attach_role_policy(RoleName="task-role", PolicyArn=policy_arn)  # type: ignore[attr-defined]
    return role_arn


@pytest.mark.asyncio
async def test_crown_jewel_full_chain_lights_up(tmp_path) -> None:
    (tmp_path / "requirements.txt").write_text("Django==2.0.0\n")
    buckets = (MotoBucket(_BUCKET, public=True, objects={"records.txt": _SSN}),)
    async with in_memory_semantic_store() as store:
        with moto_all_clients(buckets) as (s3, iam, ecs, ec2):
            # data leg
            await drive_data_security(store, tenant_id=_TENANT, buckets=buckets, s3_client=s3)
            # identity leg — the task role + its fine-grained grant
            role_arn = _seed_task_role(iam)
            fine = _fine_grained_grants(_list_identities(iam))
            await IdentityKgWriter(store, _TENANT).record_access(fine)
            # workload leg — exposed ECS service running the image AS the task role
            setup_ecs_workload(ecs, ec2, image_ref=_IMAGE_REF, public=True, task_role_arn=role_arn)
            await drive_cloud_workloads(store, tenant_id=_TENANT, ecs_client=ecs, ec2_client=ec2)
        # vuln leg — real trivy CVEs on the same image node
        await drive_vulnerability(
            store, tenant_id=_TENANT, fixture_dir=tmp_path, image_ref=_IMAGE_REF
        )

        assert fine and fine[0][0] == role_arn, "real fine-grained grant for the task role"
        hits = await KgQuery(store, _TENANT).find_crown_jewel_exposure()
        assert hits, "the full exposed→vulnerable→assumes→reaches-data chain surfaces"
        h = hits[0]
        assert h.cve_id.startswith("CVE-")
        assert h.data_type == "ssn"


@pytest.mark.asyncio
async def test_private_workload_breaks_the_crown_jewel(tmp_path) -> None:
    # Every other leg present, but the workload is NOT internet-exposed → no crown jewel.
    (tmp_path / "requirements.txt").write_text("Django==2.0.0\n")
    buckets = (MotoBucket(_BUCKET, public=True, objects={"records.txt": _SSN}),)
    async with in_memory_semantic_store() as store:
        with moto_all_clients(buckets) as (s3, iam, ecs, ec2):
            await drive_data_security(store, tenant_id=_TENANT, buckets=buckets, s3_client=s3)
            role_arn = _seed_task_role(iam)
            await IdentityKgWriter(store, _TENANT).record_access(
                _fine_grained_grants(_list_identities(iam))
            )
            setup_ecs_workload(ecs, ec2, image_ref=_IMAGE_REF, public=False, task_role_arn=role_arn)
            await drive_cloud_workloads(store, tenant_id=_TENANT, ecs_client=ecs, ec2_client=ec2)
        await drive_vulnerability(
            store, tenant_id=_TENANT, fixture_dir=tmp_path, image_ref=_IMAGE_REF
        )
        assert await KgQuery(store, _TENANT).find_crown_jewel_exposure() == []
