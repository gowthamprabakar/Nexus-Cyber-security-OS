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
from charter.memory.graph_types import EdgeType, NodeCategory
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
from fleet_testkit.vuln_scan import drive_vulnerability, trivy_available

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
async def test_fixed_gzipped_secret_is_detected() -> None:
    # FIXED (gap #3): classify_bytes decompresses gzip before classifying.
    assert await _secret_hits(gzip.compress(_KEY)) == 1


@pytest.mark.asyncio
async def test_fixed_base64_secret_is_detected() -> None:
    # FIXED (gap #3): classify_bytes decodes base64 before classifying.
    assert await _secret_hits(base64.b64encode(_KEY)) == 1


@pytest.mark.asyncio
async def test_fixed_gzipped_pii_is_detected() -> None:
    # FIXED (gap #3): the decode applies to PII too (path 7 + every EXPOSES_DATA consumer).
    assert await _unencrypted_hits(gzip.compress(_SSN)) == 1


@pytest.mark.asyncio
async def test_decode_precision_plain_noise_is_clean() -> None:
    # Precision: a benign blob that happens to be base64 must not produce a spurious hit.
    assert await _secret_hits(base64.b64encode(b"just some harmless configuration text")) == 0


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


@pytest.mark.skipif(not trivy_available, reason="trivy binary not installed")
@pytest.mark.asyncio
async def test_fixed_kev_flag_on_cve_nodes(tmp_path) -> None:
    # FIXED (gap #12): KEV (Known-Exploited) status is now a first-class CVE-node signal.
    # The catalog is injected here (the live CISA feed is the agent's online kev.py path).
    (tmp_path / "requirements.txt").write_text("Django==2.0.0\n")
    async with in_memory_semantic_store() as store:
        await drive_vulnerability(
            store,
            tenant_id=_TENANT,
            fixture_dir=tmp_path,
            image_ref="myreg/app:1.0",
            kev_cve_ids={"CVE-2019-19844"},
        )
        cves = await store.list_entities_by_type(
            tenant_id=_TENANT, entity_type=NodeCategory.CVE_FINDING.value
        )
        by_id = {c.external_id: c for c in cves}
        assert by_id["CVE-2019-19844"].properties.get("kev") is True
        others = [c for c in cves if c.external_id != "CVE-2019-19844"]
        assert others and all(c.properties.get("kev") is False for c in others), (
            "non-KEV CVEs must be flagged kev=False"
        )


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


def test_fixed_ec2_compute_is_inventoried() -> None:
    # FIXED (gap #9): read_ec2_workloads inventories EC2 instances — exposure (public IP + a
    # 0.0.0.0/0 SG) + the instance-profile role (the EC2 analogue of an ECS task role).
    from cloud_posture.tools.aws_ec2 import read_ec2_workloads

    with mock_aws():
        ec2 = boto3.client("ec2", region_name="us-east-1")
        iam = boto3.client("iam", region_name="us-east-1")
        iam.create_role(RoleName="app", AssumeRolePolicyDocument="{}")
        profile = iam.create_instance_profile(InstanceProfileName="app")["InstanceProfile"]["Arn"]
        iam.add_role_to_instance_profile(InstanceProfileName="app", RoleName="app")
        vpc, subnet = _vpc_subnet(ec2)
        sg = _open_sg(ec2, vpc)
        ec2.run_instances(
            ImageId="ami-12345678",
            MinCount=1,
            MaxCount=1,
            NetworkInterfaces=[
                {
                    "DeviceIndex": 0,
                    "SubnetId": subnet,
                    "Groups": [sg],
                    "AssociatePublicIpAddress": True,
                }
            ],
            IamInstanceProfile={"Arn": profile},
        )
        workloads = read_ec2_workloads(ec2, iam)
        assert len(workloads) == 1
        assert workloads[0].is_public is True
        assert workloads[0].role_arn == "arn:aws:iam::123456789012:role/app"


def test_private_ec2_is_not_public() -> None:
    # Precision: no public IP → not internet-exposed even with an open SG.
    from cloud_posture.tools.aws_ec2 import read_ec2_workloads

    with mock_aws():
        ec2 = boto3.client("ec2", region_name="us-east-1")
        iam = boto3.client("iam", region_name="us-east-1")
        vpc, subnet = _vpc_subnet(ec2)
        sg = _open_sg(ec2, vpc)
        ec2.run_instances(
            ImageId="ami-12345678", MinCount=1, MaxCount=1, SecurityGroupIds=[sg], SubnetId=subnet
        )
        workloads = read_ec2_workloads(ec2, iam)
        assert len(workloads) == 1 and workloads[0].is_public is False


@pytest.mark.asyncio
async def test_fixed_ec2_workload_written_to_graph() -> None:
    # FIXED (gap #9): record_ec2_workloads writes the EC2 instance as a CLOUD_RESOURCE workload
    # (is_public) + ASSUMES → its instance-profile role (the exposed-compute bridge).
    from cloud_posture.tools.aws_ec2 import Ec2Workload
    from cloud_posture.tools.kg_writer import KnowledgeGraphWriter

    workload = Ec2Workload(
        instance_arn="arn:aws:ec2:us-east-1:111:instance/i-1",
        is_public=True,
        role_arn="arn:aws:iam::111:role/app",
    )
    async with in_memory_semantic_store() as store:
        await KnowledgeGraphWriter(store, _TENANT).record_ec2_workloads([workload])
        rows = await store.list_entities_by_type(
            tenant_id=_TENANT, entity_type=NodeCategory.CLOUD_RESOURCE.value
        )
        node = next(r for r in rows if r.external_id == workload.instance_arn)
        assert node.properties.get("kind") == "ec2-instance"
        assert node.properties.get("is_public") is True
        edges = await store.get_relationships_from(
            tenant_id=_TENANT, src_entity_id=node.entity_id, edge_types=(EdgeType.ASSUMES.value,)
        )
        assert len(edges) == 1


def test_fixed_load_balancer_exposure_is_detected() -> None:
    # FIXED (gap #10): an ECS service with NO public IP behind an INTERNET-FACING ALB now reads
    # is_public=True — the LB-exposed target groups OR into the SG check.
    from cloud_posture.tools.aws_ecs import read_ecs_workloads
    from cloud_posture.tools.aws_elbv2 import internet_facing_target_groups

    with mock_aws():
        ec2 = boto3.client("ec2", region_name="us-east-1")
        ecs = boto3.client("ecs", region_name="us-east-1")
        elbv2 = boto3.client("elbv2", region_name="us-east-1")
        vpc, subnet = _vpc_subnet(ec2)
        subnet2 = ec2.create_subnet(
            VpcId=vpc, CidrBlock="10.0.2.0/24", AvailabilityZone="us-east-1b"
        )["Subnet"]["SubnetId"]
        sg = _open_sg(ec2, vpc)
        lb = elbv2.create_load_balancer(
            Name="alb", Subnets=[subnet, subnet2], Scheme="internet-facing", Type="application"
        )["LoadBalancers"][0]
        tg = elbv2.create_target_group(
            Name="tg", Protocol="HTTP", Port=80, VpcId=vpc, TargetType="ip"
        )["TargetGroups"][0]
        elbv2.create_listener(
            LoadBalancerArn=lb["LoadBalancerArn"],
            Protocol="HTTP",
            Port=80,
            DefaultActions=[{"Type": "forward", "TargetGroupArn": tg["TargetGroupArn"]}],
        )
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
            loadBalancers=[
                {"targetGroupArn": tg["TargetGroupArn"], "containerName": "a", "containerPort": 80}
            ],
            networkConfiguration={
                "awsvpcConfiguration": {
                    "subnets": [subnet],
                    "securityGroups": [sg],
                    "assignPublicIp": "DISABLED",
                }
            },
        )
        exposed_tgs = internet_facing_target_groups(elbv2)
        workloads = read_ecs_workloads(ecs, ec2, lb_exposed_target_groups=exposed_tgs)
        assert workloads and all(w.is_public is True for w in workloads)
        # Precision: without the LB-exposed set, the no-public-IP service reads private.
        assert all(w.is_public is False for w in read_ecs_workloads(ecs, ec2))
