"""Reusable moto-backed AWS harness for fleet-test attack-path e2e (L2).

Stands up an in-process **moto** S3 (and optionally IAM) and drives the *real*
agent code — data-security's live S3 inventory reader + object sampler + the real
classifier + the real ``kg_writer.record`` — into a provided ``SemanticStore``. No
``s3_inventory_feed`` fixtures, no ``_FakeS3``, no hand-supplied classifier hits: the
classifier runs on the actual bytes a real boto3 ``get_object`` returns from moto, and
the public/private posture is derived from a real S3 ACL the reader parses.

This is the shared harness the attack-path e2e tests reuse (path 3 / path 1). moto is
in-process, so these run unskipped in normal CI (no ``NEXUS_LIVE_*`` gate).
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import boto3
from cloud_posture.tools.aws_ecs import EcsWorkload, read_ecs_workloads
from cloud_posture.tools.kg_writer import KnowledgeGraphWriter as CloudPostureKgWriter
from data_security.canonical import s3_bucket_arn
from data_security.classifiers import classify
from data_security.kg_writer import KnowledgeGraphWriter as DataSecurityKgWriter
from data_security.schemas import ClassifierLabel
from data_security.tools.s3_inventory_live import S3LiveInventoryReader
from data_security.tools.s3_objects_live import S3LiveObjectSampler
from moto import mock_aws

if TYPE_CHECKING:
    from collections.abc import Iterator

    from charter.memory.semantic import SemanticStore

_DEFAULT_ACCOUNT_ID = "123456789012"  # moto's fixed account id
_DEFAULT_REGION = "us-east-1"


@dataclass(frozen=True, slots=True)
class MotoBucket:
    """A bucket to seed into moto: name, public posture, and object bodies (key -> bytes)."""

    name: str
    public: bool
    objects: dict[str, bytes] = field(default_factory=dict)


def _seed_buckets(s3: object, buckets: tuple[MotoBucket, ...]) -> None:
    """Create each bucket in moto, set a real public-read ACL when public, put objects."""
    for spec in buckets:
        s3.create_bucket(Bucket=spec.name)  # type: ignore[attr-defined]
        if spec.public:
            # A real S3 grant to AllUsers — the live inventory reader parses this ACL and
            # marks the bucket public (no fixture flag).
            s3.put_bucket_acl(Bucket=spec.name, ACL="public-read")  # type: ignore[attr-defined]
        for key, body in spec.objects.items():
            s3.put_object(Bucket=spec.name, Key=key, Body=body)  # type: ignore[attr-defined]


async def drive_data_security(
    store: SemanticStore,
    *,
    tenant_id: str,
    buckets: tuple[MotoBucket, ...],
    s3_client: object,
    account_id: str = _DEFAULT_ACCOUNT_ID,
) -> dict[str, str]:
    """Run data-security's REAL readers + classifier + kg_writer against ``s3_client``.

    Reads live S3 posture (``S3LiveInventoryReader``), samples every object
    (``S3LiveObjectSampler`` at rate 1.0), runs the real ``classify`` over the real bytes,
    and persists via the real ``KnowledgeGraphWriter.record`` — the same call data-security's
    ``agent.run`` makes. Returns a mapping of bucket name -> canonical S3 ARN.
    """
    inventory = S3LiveInventoryReader(s3_client, account_id=account_id).read()  # type: ignore[arg-type]
    sampler = S3LiveObjectSampler(s3_client, sample_rate=1.0)  # type: ignore[arg-type]

    hits_by_bucket: dict[str, list[ClassifierLabel]] = {}
    for bucket in inventory:
        samples, _basis = sampler.sample(bucket.name)
        for sample in samples:
            label = classify(sample.decoded_text())
            if label is not ClassifierLabel.NONE:
                hits_by_bucket.setdefault(bucket.name, []).append(label)

    await DataSecurityKgWriter(store, tenant_id).record(inventory, hits_by_bucket)
    return {b.name: s3_bucket_arn(b.name) for b in inventory}


@contextmanager
def moto_s3(
    buckets: tuple[MotoBucket, ...],
    *,
    region: str = _DEFAULT_REGION,
) -> Iterator[object]:
    """Context manager: a live moto-backed boto3 S3 client with ``buckets`` seeded.

    Yields the real boto3 client (the injectable ``S3Client`` the live reader/sampler
    consume). Use with :func:`drive_data_security` to run the real data-security path.
    """
    with mock_aws():
        s3 = boto3.client("s3", region_name=region)
        _seed_buckets(s3, buckets)
        yield s3


@contextmanager
def moto_ecs_clients(*, region: str = _DEFAULT_REGION) -> Iterator[tuple[object, object]]:
    """Context manager yielding ``(ecs_client, ec2_client)`` under one moto mock.

    Path-2 needs ECS (workloads) and EC2 (security groups) live together. Both are bare;
    the caller seeds workloads via :func:`setup_ecs_workload`.
    """
    with mock_aws():
        ecs = boto3.client("ecs", region_name=region)
        ec2 = boto3.client("ec2", region_name=region)
        yield ecs, ec2


def setup_ecs_workload(
    ecs: object,
    ec2: object,
    *,
    image_ref: str,
    public: bool,
    name: str = "websvc",
) -> str:
    """Seed a moto ECS service running ``image_ref``; returns its service ARN.

    Builds a real VPC/subnet/security-group + cluster + awsvpc task definition + service.
    When ``public`` the security group gets a real ``0.0.0.0/0`` ingress and the service
    assigns a public IP — the exact posture :func:`cloud_posture.tools.aws_ecs` flags as
    internet-exposed. When not public, the SG is closed and no public IP is assigned.
    """
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]  # type: ignore[attr-defined]
    subnet = ec2.create_subnet(VpcId=vpc, CidrBlock="10.0.1.0/24")["Subnet"]["SubnetId"]  # type: ignore[attr-defined]
    sg = ec2.create_security_group(GroupName=f"{name}-sg", Description="sg", VpcId=vpc)[  # type: ignore[attr-defined]
        "GroupId"
    ]
    if public:
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
    ecs.create_cluster(clusterName=f"{name}-cluster")  # type: ignore[attr-defined]
    ecs.register_task_definition(  # type: ignore[attr-defined]
        family=f"{name}-td",
        networkMode="awsvpc",
        containerDefinitions=[{"name": "app", "image": image_ref, "memory": 128}],
    )
    service = ecs.create_service(  # type: ignore[attr-defined]
        cluster=f"{name}-cluster",
        serviceName=name,
        taskDefinition=f"{name}-td",
        desiredCount=1,
        networkConfiguration={
            "awsvpcConfiguration": {
                "subnets": [subnet],
                "securityGroups": [sg],
                "assignPublicIp": "ENABLED" if public else "DISABLED",
            }
        },
    )
    return str(service["service"]["serviceArn"])


async def drive_cloud_workloads(
    store: SemanticStore,
    *,
    tenant_id: str,
    ecs_client: object,
    ec2_client: object,
) -> list[EcsWorkload]:
    """Run cloud-posture's REAL ECS reader + ``record_workloads`` against the clients.

    Reads ECS workloads (``read_ecs_workloads``), persists the workload nodes +
    ``RUNS_IMAGE`` bridge edges via the real ``KnowledgeGraphWriter.record_workloads``.
    Returns the read ``EcsWorkload`` rows.
    """
    workloads = read_ecs_workloads(ecs_client, ec2_client)
    await CloudPostureKgWriter(store, tenant_id).record_workloads(workloads)
    return workloads


@contextmanager
def moto_aws_clients(
    buckets: tuple[MotoBucket, ...],
    *,
    region: str = _DEFAULT_REGION,
) -> Iterator[tuple[object, object]]:
    """Context manager yielding ``(s3_client, iam_client)`` under one moto mock.

    Path-1 needs S3 *and* IAM live under the same moto session. S3 buckets are seeded;
    the IAM client is bare for the caller to populate (roles/policies) via the real readers.
    """
    with mock_aws():
        s3 = boto3.client("s3", region_name=region)
        iam = boto3.client("iam", region_name=region)
        _seed_buckets(s3, buckets)
        yield s3, iam


__all__ = [
    "EcsWorkload",
    "MotoBucket",
    "drive_cloud_workloads",
    "drive_data_security",
    "moto_aws_clients",
    "moto_ecs_clients",
    "moto_s3",
    "setup_ecs_workload",
]
