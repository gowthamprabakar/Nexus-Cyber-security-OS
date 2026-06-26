"""Known detection gaps — characterization tests that document where the detectors MISS.

The capability banks measure precision/recall on cases the detectors handle. This file does the
opposite: it pins the *boundaries* — realistic inputs we currently miss — so a gap is visible and
tracked, not hidden behind a green bank. Each assertion documents a real limitation; if a gap is
ever closed (a detector starts catching the input), the matching assertion fails on purpose,
prompting an update to docs/strategy/detection-gaps.md.

These are honest counter-evidence to the banks' 1.000 scores: the scores are 1.000 *on the bank*,
with the documented out-of-bank gaps below.
"""

import base64
import gzip
import json
from datetime import UTC, datetime

import boto3
import pytest
from data_security.classifiers import classify
from data_security.schemas import ClassifierLabel
from identity.agent import _externally_trusted_arns, _fine_grained_grants
from identity.tools.aws_iam import (
    IamRole,
    IdentityListing,
    _list_groups,
    _list_policies,
    _list_roles,
    _list_users,
)
from meta_harness.kg_query import KgQuery
from moto import mock_aws

from fleet_testkit import MotoBucket, drive_data_security, in_memory_semantic_store
from fleet_testkit.moto_aws import moto_s3

_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"  # noqa: S105  AWS docs example secret

_KEY = b"aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n"
_SSN = b"patient ssn 123-45-6789\n"
_TENANT = "limits"


async def _secret_hits(body: bytes) -> int:
    async with in_memory_semantic_store() as store:
        buckets = (MotoBucket("acme-blob", public=True, objects={"o": body}),)
        with moto_s3(buckets) as s3:
            await drive_data_security(store, tenant_id=_TENANT, buckets=buckets, s3_client=s3)
        return len(await KgQuery(store, _TENANT).find_public_secret_exposure())


async def _unencrypted_hits(body: bytes) -> int:
    async with in_memory_semantic_store() as store:
        buckets = (MotoBucket("acme-blob", public=True, objects={"o": body}),)
        with moto_s3(buckets) as s3:
            await drive_data_security(store, tenant_id=_TENANT, buckets=buckets, s3_client=s3)
        return len(await KgQuery(store, _TENANT).find_public_unencrypted_exposure())


@pytest.mark.asyncio
async def test_boundary_decoded_text_is_detected() -> None:
    # The classifier matches patterns in decoded UTF-8 text — including inside structured text.
    assert await _secret_hits(_KEY) == 1
    assert await _secret_hits(b'{"aws_key": "AKIAIOSFODNN7EXAMPLE"}') == 1


@pytest.mark.asyncio
async def test_gap_gzipped_secret_is_missed() -> None:
    # GAP: archives are not decompressed before classification. Wiz/Macie scan inside .gz/.zip.
    assert await _secret_hits(gzip.compress(_KEY)) == 0, (
        "gzipped-secret gap closed — update docs/strategy/detection-gaps.md"
    )


@pytest.mark.asyncio
async def test_gap_base64_secret_is_missed() -> None:
    # GAP: encoded blobs are not decoded before classification.
    assert await _secret_hits(base64.b64encode(_KEY)) == 0, (
        "base64-secret gap closed — update docs/strategy/detection-gaps.md"
    )


@pytest.mark.asyncio
async def test_gap_gzipped_pii_is_missed() -> None:
    # GAP: same archive blind spot applies to PII (path 7 and every EXPOSES_DATA consumer).
    assert await _unencrypted_hits(gzip.compress(_SSN)) == 0, (
        "gzipped-PII gap closed — update docs/strategy/detection-gaps.md"
    )


def test_fixed_aws_secret_access_key_is_detected() -> None:
    # FIXED (gap #4): a dedicated AWS-secret-key pattern matches the standard labels (any
    # separator / camelCase) + a 40-char value, classified as an AWS credential.
    assert classify(f"aws_secret_access_key = {_SECRET_KEY}") is ClassifierLabel.AWS_ACCESS_KEY
    assert classify(f"SecretAccessKey: {_SECRET_KEY}") is ClassifierLabel.AWS_ACCESS_KEY
    # Precision: the label is required — a bare 40-char string is not flagged.
    assert classify(_SECRET_KEY) is ClassifierLabel.NONE


def _listing_from_moto(iam: object) -> IdentityListing:
    deg: list[dict[str, str]] = []
    return IdentityListing(
        users=tuple(_list_users(iam, deg)),
        roles=tuple(_list_roles(iam, deg)),
        groups=tuple(_list_groups(iam, deg)),
        policies=tuple(_list_policies(iam, deg)),
    )


def test_fixed_group_inherited_access_is_detected() -> None:
    # FIXED (gap #5): _fine_grained_grants now follows a user's group memberships and resolves
    # the group's attached + inline policies, so a user whose only S3 access is via a group is
    # caught (paths 4/8).
    doc = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::acme-pii/*"}
            ],
        }
    )
    with mock_aws():
        iam = boto3.client("iam", region_name="us-east-1")
        policy_arn = iam.create_policy(PolicyName="read", PolicyDocument=doc)["Policy"]["Arn"]
        iam.create_group(GroupName="readers")
        iam.attach_group_policy(GroupName="readers", PolicyArn=policy_arn)
        iam.create_user(UserName="alice")
        iam.add_user_to_group(GroupName="readers", UserName="alice")
        listing = _listing_from_moto(iam)
    assert listing.users[0].group_memberships == ("readers",), "group membership is read"
    assert _fine_grained_grants(listing) == [
        ("arn:aws:iam::123456789012:user/alice", "arn:aws:s3:::acme-pii")
    ], "group-inherited access should now be resolved"


def _federated_role(name: str, provider_arn: str) -> IamRole:
    return IamRole(
        arn=f"arn:aws:iam::123456789012:role/{name}",
        name=name,
        role_id=f"AROA{name}",
        create_date=datetime(2026, 6, 26, tzinfo=UTC),
        last_used_at=None,
        assume_role_policy_document={
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Federated": provider_arn},
                    "Action": "sts:AssumeRoleWithWebIdentity",
                }
            ],
        },
    )


def test_fixed_federated_external_trust_is_detected() -> None:
    # FIXED (gap #6): _externally_trusted_arns now flags roles assumable via an external OIDC/SAML
    # provider (Principal.Federated), e.g. GitHub Actions OIDC, alongside cross-account trust.
    oidc = _federated_role(
        "gha", "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
    )
    saml = _federated_role("sso", "arn:aws:iam::123456789012:saml-provider/Okta")
    listing = IdentityListing(users=(), roles=(oidc, saml), groups=())
    assert sorted(_externally_trusted_arns(listing)) == [oidc.arn, saml.arn]


async def _secret_hits_custom(setup: object) -> int:
    """Run the real data-security path against a moto S3 the caller seeds; count secret hits."""
    async with in_memory_semantic_store() as store:
        with mock_aws():
            s3 = boto3.client("s3", region_name="us-east-1")
            setup(s3)
            await drive_data_security(store, tenant_id=_TENANT, buckets=(), s3_client=s3)
        return len(await KgQuery(store, _TENANT).find_public_secret_exposure())


@pytest.mark.asyncio
async def test_fixed_bucket_policy_public_is_detected() -> None:
    # FIXED (gap #1): a bucket made public via a BUCKET POLICY (Principal:*) is now flagged
    # public (kg_writer._bucket_is_public evaluates the policy, respecting Block-Public-Access),
    # so the secret in it surfaces. (AWS disables ACLs by default → policy is the common case.)
    def setup(s3: object) -> None:
        s3.create_bucket(Bucket="policy-public")  # type: ignore[attr-defined]
        s3.put_bucket_policy(  # type: ignore[attr-defined]
            Bucket="policy-public",
            Policy=json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": "*",
                            "Action": "s3:GetObject",
                            "Resource": "arn:aws:s3:::policy-public/*",
                        }
                    ],
                }
            ),
        )
        s3.put_object(Bucket="policy-public", Key="c", Body=_KEY)  # type: ignore[attr-defined]

    assert await _secret_hits_custom(setup) == 1, "bucket-policy public should now be detected"


@pytest.mark.asyncio
async def test_block_public_access_neutralizes_policy() -> None:
    # Precision: a wildcard policy is NOT public when Block-Public-Access restricts public buckets.
    def setup(s3: object) -> None:
        s3.create_bucket(Bucket="pab-bucket")  # type: ignore[attr-defined]
        s3.put_public_access_block(  # type: ignore[attr-defined]
            Bucket="pab-bucket",
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
        )
        s3.put_bucket_policy(  # type: ignore[attr-defined]
            Bucket="pab-bucket",
            Policy=json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": "*",
                            "Action": "s3:GetObject",
                            "Resource": "arn:aws:s3:::pab-bucket/*",
                        }
                    ],
                }
            ),
        )
        s3.put_object(Bucket="pab-bucket", Key="c", Body=_KEY)  # type: ignore[attr-defined]

    assert await _secret_hits_custom(setup) == 0, "Block-Public-Access must neutralize the policy"


@pytest.mark.asyncio
async def test_gap_object_acl_public_is_missed() -> None:
    # GAP: public is derived at the BUCKET level. A private bucket with an individual object made
    # public via OBJECT ACL exposes that object, but the bucket reads private → missed.
    def setup(s3: object) -> None:
        s3.create_bucket(Bucket="obj-public")  # type: ignore[attr-defined]
        s3.put_object(Bucket="obj-public", Key="c", Body=_KEY, ACL="public-read")  # type: ignore[attr-defined]

    assert await _secret_hits_custom(setup) == 0, "object-ACL public now detected — update gaps doc"


async def _resource_based_hits(setup: object) -> list:
    """Run the real data-security path against a moto S3 the caller seeds; return path-7-gap hits."""
    async with in_memory_semantic_store() as store:
        with mock_aws():
            s3 = boto3.client("s3", region_name="us-east-1")
            setup(s3)
            await drive_data_security(store, tenant_id=_TENANT, buckets=(), s3_client=s3)
        return await KgQuery(store, _TENANT).find_resource_based_data_exposure()


def _grant_policy(bucket: str, principal_arn: str) -> str:
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": principal_arn},
                    "Action": "s3:GetObject",
                    "Resource": f"arn:aws:s3:::{bucket}/*",
                }
            ],
        }
    )


@pytest.mark.asyncio
async def test_fixed_resource_based_access_is_detected() -> None:
    # FIXED (gap #7): a bucket policy granting a SPECIFIC principal S3 read is recorded as
    # policy_readers on the bucket node (data-security), and find_resource_based_data_exposure
    # joins it to the sensitive data — access IAM-side grant resolution can't see.
    reader = "arn:aws:iam::999999999999:role/partner"

    def setup(s3: object) -> None:
        s3.create_bucket(Bucket="rb-bucket")  # type: ignore[attr-defined]
        s3.put_bucket_policy(Bucket="rb-bucket", Policy=_grant_policy("rb-bucket", reader))  # type: ignore[attr-defined]
        s3.put_object(Bucket="rb-bucket", Key="c", Body=_SSN)  # type: ignore[attr-defined]

    hits = await _resource_based_hits(setup)
    assert len(hits) == 1
    assert hits[0].principal_arn == reader
    assert hits[0].data_type == "ssn"


@pytest.mark.asyncio
async def test_resource_based_precision_wildcard_and_private() -> None:
    # Precision: a wildcard principal is public (gap #1), NOT a named resource-based grant; and a
    # named grant on a PRIVATE bucket (no EXPOSES_DATA) yields nothing.
    def wildcard(s3: object) -> None:
        s3.create_bucket(Bucket="wc-bucket")  # type: ignore[attr-defined]
        s3.put_bucket_policy(Bucket="wc-bucket", Policy=_grant_policy("wc-bucket", "*"))  # type: ignore[attr-defined]
        s3.put_object(Bucket="wc-bucket", Key="c", Body=_SSN)  # type: ignore[attr-defined]

    assert await _resource_based_hits(wildcard) == [], "wildcard is public, not a named grant"


def _vpc_subnet(ec2: object) -> tuple[str, str]:
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]  # type: ignore[attr-defined]
    subnet = ec2.create_subnet(VpcId=vpc, CidrBlock="10.0.1.0/24")["Subnet"]["SubnetId"]  # type: ignore[attr-defined]
    return vpc, subnet


def _open_sg(ec2: object, vpc: str) -> str:
    sg = ec2.create_security_group(GroupName="open", Description="d", VpcId=vpc)["GroupId"]  # type: ignore[attr-defined]
    ec2.authorize_security_group_ingress(  # type: ignore[attr-defined]
        GroupId=sg,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 443,
                "ToPort": 443,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }
        ],
    )
    return sg


def test_gap_ec2_compute_not_inventoried() -> None:
    # GAP: cloud-posture's workload reader enumerates ECS services only. An exposed EC2 instance
    # (or EKS node, Lightsail, ...) running a workload is not inventoried at all.
    from cloud_posture.tools.aws_ecs import read_ecs_workloads

    with mock_aws():
        ec2 = boto3.client("ec2", region_name="us-east-1")
        ecs = boto3.client("ecs", region_name="us-east-1")
        vpc, subnet = _vpc_subnet(ec2)
        sg = _open_sg(ec2, vpc)
        ec2.run_instances(
            ImageId="ami-12345678", MinCount=1, MaxCount=1, SecurityGroupIds=[sg], SubnetId=subnet
        )
        assert read_ecs_workloads(ecs, ec2) == [], "EC2 compute now inventoried — update gaps doc"


def test_gap_load_balancer_exposure_is_missed() -> None:
    # GAP: a workload is flagged public only when assignPublicIp=ENABLED AND a 0.0.0.0/0 SG. A
    # service behind a public ALB/NLB (open SG, NO public IP) — the common production pattern — is
    # internet-reachable but reads is_public=False.
    from cloud_posture.tools.aws_ecs import read_ecs_workloads

    with mock_aws():
        ec2 = boto3.client("ec2", region_name="us-east-1")
        ecs = boto3.client("ecs", region_name="us-east-1")
        vpc, subnet = _vpc_subnet(ec2)
        sg = _open_sg(ec2, vpc)
        ecs.create_cluster(clusterName="c")
        ecs.register_task_definition(
            family="app",
            networkMode="awsvpc",
            containerDefinitions=[{"name": "a", "image": "img:1", "memory": 128}],
        )
        ecs.create_service(
            cluster="c",
            serviceName="lb-svc",
            taskDefinition="app",
            desiredCount=1,
            networkConfiguration={
                "awsvpcConfiguration": {
                    "subnets": [subnet],
                    "securityGroups": [sg],
                    "assignPublicIp": "DISABLED",
                }
            },
        )
        workloads = read_ecs_workloads(ecs, ec2)
        assert workloads and all(w.is_public is False for w in workloads), (
            "load-balancer / no-public-IP exposure now detected — update gaps doc"
        )
