"""EC2 instance inventory + internet-exposure reader (gap #9 — non-ECS compute).

cloud-posture's workload reader only enumerated ECS services, so an exposed EC2 instance running
a workload was invisible to the fleet graph. This reads EC2 instances, flags internet exposure
(a public IP **and** a ``0.0.0.0/0`` security group), and resolves the instance-profile IAM role
— the EC2 analogue of an ECS task role, so an exposed instance whose role reaches sensitive data
is a reachable path (the ``ASSUMES`` bridge).

Honest limit: an EC2 instance runs an **AMI / host packages**, not a container image, so the
``RUNS_IMAGE`` → CVE join does not apply — host-vuln (trivy ``rootfs``/``vm``) is a separate slice.

Plain boto3 reader (same shape as ``aws_ecs``): inject ``ec2`` + ``iam`` clients, so it runs
against real AWS or in-process moto identically.
"""

from __future__ import annotations

from dataclasses import dataclass

from cloud_posture.tools.aws_ecs import _sg_allows_public

_ACTIVE_STATES = frozenset({"running", "pending"})


@dataclass(frozen=True, slots=True)
class Ec2Workload:
    """An EC2 instance resolved to its ARN, internet-exposure, and instance-profile role."""

    instance_arn: str
    is_public: bool
    role_arn: str = ""


def _instance_arn(instance_id: str, *, account_id: str, region: str) -> str:
    return f"arn:aws:ec2:{region}:{account_id}:instance/{instance_id}"


def _instance_sg_ids(instance: dict) -> list[str]:
    """All security-group ids on an instance — top-level + per-network-interface."""
    ids = [g["GroupId"] for g in instance.get("SecurityGroups", []) if g.get("GroupId")]
    for eni in instance.get("NetworkInterfaces", []):
        ids += [g["GroupId"] for g in eni.get("Groups", []) if g.get("GroupId")]
    return list(dict.fromkeys(ids))  # dedupe, order-preserving


def _profile_role_arn(iam: object, profile: dict | None) -> str:
    """Resolve an instance profile to the ARN of the role it carries ("" if none)."""
    arn = (profile or {}).get("Arn", "")
    if not arn or "/" not in arn:
        return ""
    name = arn.rsplit("/", 1)[-1]
    try:
        roles = iam.get_instance_profile(InstanceProfileName=name)["InstanceProfile"]["Roles"]  # type: ignore[attr-defined]
    except Exception:
        return ""
    return str(roles[0]["Arn"]) if roles else ""


def read_ec2_workloads(
    ec2: object, iam: object, *, account_id: str = "123456789012", region: str = "us-east-1"
) -> list[Ec2Workload]:
    """Enumerate running/pending EC2 instances as ``Ec2Workload`` rows (exposure + role)."""
    workloads: list[Ec2Workload] = []
    reservations = ec2.describe_instances().get("Reservations", [])  # type: ignore[attr-defined]
    for reservation in reservations:
        for instance in reservation.get("Instances", []):
            if instance.get("State", {}).get("Name") not in _ACTIVE_STATES:
                continue
            is_public = bool(instance.get("PublicIpAddress")) and _sg_allows_public(
                ec2, _instance_sg_ids(instance)
            )
            workloads.append(
                Ec2Workload(
                    instance_arn=_instance_arn(
                        instance["InstanceId"], account_id=account_id, region=region
                    ),
                    is_public=is_public,
                    role_arn=_profile_role_arn(iam, instance.get("IamInstanceProfile")),
                )
            )
    return workloads


__all__ = ["Ec2Workload", "read_ec2_workloads"]
