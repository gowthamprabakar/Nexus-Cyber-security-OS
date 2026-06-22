"""ECS workload inventory + internet-exposure reader (path-2 ``RUNS_IMAGE`` bridge).

Reads ECS services and resolves each to (a) its container **image ref** — the same key
vulnerability writes CVEs under — and (b) whether it is **internet-exposed**: an awsvpc
service with ``assignPublicIp=ENABLED`` *and* a security group permitting ``0.0.0.0/0``
(or ``::/0``) ingress.

This is the mechanism-② bridge (ADR-023): vulnerability keys images by ref, the cloud
spine keys workloads by ARN, and they never converge on a canonical key. ``RUNS_IMAGE``
(written by :meth:`cloud_posture.tools.kg_writer.KnowledgeGraphWriter.record_workloads`)
joins the workload to the image node so a graph query can reach an exposed workload's CVEs.

Plain boto3 reader (same shape as ``aws_s3`` / ``aws_iam``): the caller injects the ``ecs``
and ``ec2`` clients, so it runs against real AWS or against in-process moto identically.
"""

from __future__ import annotations

from dataclasses import dataclass

_PUBLIC_CIDRS = frozenset({"0.0.0.0/0", "::/0"})
# describe_services accepts at most 10 services per call.
_DESCRIBE_BATCH = 10


@dataclass(frozen=True, slots=True)
class EcsWorkload:
    """An ECS service resolved to its image ref + internet-exposure posture + task role."""

    service_arn: str
    image_ref: str
    is_public: bool
    task_role_arn: str = ""


def _sg_allows_public(ec2: object, sg_ids: list[str]) -> bool:
    """True if any of ``sg_ids`` has an ingress rule open to the whole internet."""
    if not sg_ids:
        return False
    groups = ec2.describe_security_groups(GroupIds=sg_ids)["SecurityGroups"]  # type: ignore[attr-defined]
    for group in groups:
        for perm in group.get("IpPermissions", []):
            for rng in perm.get("IpRanges", []):
                if rng.get("CidrIp") in _PUBLIC_CIDRS:
                    return True
            for rng in perm.get("Ipv6Ranges", []):
                if rng.get("CidrIpv6") in _PUBLIC_CIDRS:
                    return True
    return False


def _task_def_image_and_role(ecs: object, task_def_arn: str) -> tuple[str, str]:
    """A service's task definition → (first container image ref, taskRoleArn). "" when absent."""
    task_def = ecs.describe_task_definition(taskDefinition=task_def_arn)["taskDefinition"]  # type: ignore[attr-defined]
    containers = task_def.get("containerDefinitions") or []
    image = str(containers[0].get("image", "")) if containers else ""
    return image, str(task_def.get("taskRoleArn", ""))


def _service_is_public(ec2: object, service: dict) -> bool:
    """Internet-exposed = awsvpc public IP assigned AND a 0.0.0.0/0 security group."""
    awsvpc = (service.get("networkConfiguration") or {}).get("awsvpcConfiguration") or {}
    if awsvpc.get("assignPublicIp") != "ENABLED":
        return False
    return _sg_allows_public(ec2, list(awsvpc.get("securityGroups") or []))


def _batched(items: list[str], size: int) -> list[list[str]]:
    return [items[i : i + size] for i in range(0, len(items), size)]


def read_ecs_workloads(ecs: object, ec2: object) -> list[EcsWorkload]:
    """Enumerate ECS services across all clusters as ``EcsWorkload`` rows.

    Skips services whose task definition has no resolvable container image. ``ecs`` and
    ``ec2`` are injected boto3 clients (real AWS or moto).
    """
    workloads: list[EcsWorkload] = []
    cluster_arns = ecs.list_clusters().get("clusterArns", [])  # type: ignore[attr-defined]
    for cluster in cluster_arns:
        service_arns = ecs.list_services(cluster=cluster).get("serviceArns", [])  # type: ignore[attr-defined]
        for batch in _batched(list(service_arns), _DESCRIBE_BATCH):
            services = ecs.describe_services(cluster=cluster, services=batch).get(  # type: ignore[attr-defined]
                "services", []
            )
            for svc in services:
                image_ref, task_role_arn = _task_def_image_and_role(ecs, svc["taskDefinition"])
                if not image_ref:
                    continue
                workloads.append(
                    EcsWorkload(
                        service_arn=svc["serviceArn"],
                        image_ref=image_ref,
                        is_public=_service_is_public(ec2, svc),
                        task_role_arn=task_role_arn,
                    )
                )
    return workloads


__all__ = ["EcsWorkload", "read_ecs_workloads"]
