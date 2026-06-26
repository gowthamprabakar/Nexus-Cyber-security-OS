"""Capability-bank runner — measures a data-security path detector's precision / recall / FP.

Loads a §3.2 YAML case (validated by :func:`fleet_testkit.capability.load_test_case`), builds
the moto buckets from its inline ``environment.buckets``, drives data-security's REAL detection
path, and scores the emitted hits against the case's ground truth via the shared evaluator. The
output is a real ``CapabilityResult`` (precision/recall/FP/time) — the measured number.

The data-security paths (3 public-secret, 7 public-unencrypted, …) differ only in *which*
``KgQuery`` detector runs; every hit carries ``resource_id`` + ``data_type``, so one runner +
one ``match`` covers them. ``detect`` selects the path.
"""

from __future__ import annotations

import json
import subprocess
import uuid
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

import yaml
from identity.agent import _externally_trusted_arns, _fine_grained_grants
from identity.kg_writer import KnowledgeGraphWriter as IdentityKgWriter
from identity.tools.aws_iam import (
    IdentityListing,
    _list_groups,
    _list_policies,
    _list_roles,
    _list_users,
)
from k8s_posture.kg_writer import KnowledgeGraphWriter as K8sKgWriter
from k8s_posture.tools.privileged_pods import kubectl_available, read_privileged_workloads
from meta_harness.kg_query import KgQuery

from fleet_testkit.capability import (
    CapabilityResult,
    GroundTruth,
    TestCase,
    detection_timer,
    load_test_case,
    score,
)
from fleet_testkit.moto_aws import (
    MotoBucket,
    drive_aispm,
    drive_cloud_workloads,
    drive_data_security,
    moto_ai_clients,
    moto_all_clients,
    moto_aws_clients,
    moto_ecs_clients,
    moto_s3,
    setup_ecs_workload,
    setup_sagemaker_endpoint,
)
from fleet_testkit.store import in_memory_semantic_store
from fleet_testkit.vuln_scan import drive_vulnerability

_TENANT = "bank-tenant"

#: A detector selector: given a tenant-scoped KgQuery, return the path's hits (each with
#: ``resource_id`` + ``data_type``).
Detect = Callable[[KgQuery], Awaitable[Sequence[Any]]]


@dataclass(frozen=True, slots=True)
class _Hit:
    """A detector hit resolved to its stable identity for scoring (entity_id → bucket ARN)."""

    bucket_arn: str
    data_type: str


def load_bank_case(path: Path | str) -> tuple[TestCase, tuple[MotoBucket, ...]]:
    """Parse + validate a §3.2 case AND build its moto buckets from ``environment.buckets``."""
    case = load_test_case(path)
    raw = yaml.safe_load(Path(path).read_text())
    specs = (raw.get("environment") or {}).get("buckets") or []
    buckets = tuple(
        MotoBucket(
            name=str(b["name"]),
            public=bool(b["public"]),
            encrypted=bool(b.get("encrypted", False)),
            objects={k: str(v).encode() for k, v in (b.get("objects") or {}).items()},
            policy=(
                _grant_policy(str(b["name"]), b["policy_readers"])
                if b.get("policy_readers")
                else None
            ),
        )
        for b in specs
    )
    return case, buckets


def _grant_policy(bucket: str, readers: list[str]) -> str:
    """A bucket policy granting the named principals ``s3:GetObject`` (resource-based access)."""
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": list(readers)},
                    "Action": "s3:GetObject",
                    "Resource": f"arn:aws:s3:::{bucket}/*",
                }
            ],
        }
    )


def _match(hit: _Hit, gt: GroundTruth) -> bool:
    """A hit matches a ground-truth violation iff same bucket ARN and same data type."""
    return hit.bucket_arn == gt.resource and hit.data_type == str(gt.extra.get("data_type", ""))


async def run_data_security_case(path: Path | str, *, detect: Detect) -> CapabilityResult:
    """Drive a REAL data-security path detection for a case and score it against ground truth."""
    case, buckets = load_bank_case(path)
    async with in_memory_semantic_store() as store:
        with detection_timer() as timer:
            with moto_s3(buckets) as s3:
                await drive_data_security(store, tenant_id=_TENANT, buckets=buckets, s3_client=s3)
            raw_hits = await detect(KgQuery(store, _TENANT))
            hits: list[_Hit] = []
            for h in raw_hits:
                entity = await store.get_entity(tenant_id=_TENANT, entity_id=h.resource_id)
                hits.append(
                    _Hit(bucket_arn=entity.external_id if entity else "", data_type=h.data_type)
                )
        return score(
            hits,
            case.ground_truth_violations,
            case.expected_non_detections,
            match=_match,
            label=lambda h: f"{h.bucket_arn}:{h.data_type}",
            detection_time_seconds=timer.seconds,
            test_case_id=case.test_case_id,
        )


async def run_public_secret_case(path: Path | str) -> CapabilityResult:
    """Path 3 — public-secret exposure."""
    return await run_data_security_case(path, detect=lambda kg: kg.find_public_secret_exposure())


async def run_public_unencrypted_case(path: Path | str) -> CapabilityResult:
    """Path 7 — public + unencrypted + sensitive."""
    return await run_data_security_case(
        path, detect=lambda kg: kg.find_public_unencrypted_exposure()
    )


async def run_resource_based_case(path: Path | str) -> CapabilityResult:
    """Gap #7 — a principal granted by the bucket policy (resource-based) reaches sensitive data.

    Drives the real data-security path (which records `policy_readers` from the bucket policy)
    and scores `find_resource_based_data_exposure` with a principal-aware match.
    """
    case, buckets = load_bank_case(path)
    async with in_memory_semantic_store() as store:
        with detection_timer() as timer:
            with moto_s3(buckets) as s3:
                await drive_data_security(store, tenant_id=_TENANT, buckets=buckets, s3_client=s3)
            raw_hits = await KgQuery(store, _TENANT).find_resource_based_data_exposure()
            hits: list[_PrincipalHit] = []
            for h in raw_hits:
                res = await store.get_entity(tenant_id=_TENANT, entity_id=h.resource_id)
                hits.append(
                    _PrincipalHit(
                        principal_arn=h.principal_arn,
                        resource_arn=res.external_id if res else "",
                        data_type=h.data_type,
                    )
                )
        return score(
            hits,
            case.ground_truth_violations,
            case.expected_non_detections,
            match=_match_principal,
            label=lambda h: f"{h.principal_arn}->{h.resource_arn}:{h.data_type}",
            detection_time_seconds=timer.seconds,
            test_case_id=case.test_case_id,
        )


# --- Path 4: fine-grained over-permission (identity + data-security) ----------------------


@dataclass(frozen=True, slots=True)
class _PrincipalHit:
    """A fine-grained hit resolved to (principal ARN, resource ARN, data type) for scoring."""

    principal_arn: str
    resource_arn: str
    data_type: str


def _match_principal(hit: _PrincipalHit, gt: GroundTruth) -> bool:
    """Match on principal + resource + data type — path 4 is about *which* principal reaches data."""
    return (
        hit.principal_arn == str(gt.extra.get("principal", ""))
        and hit.resource_arn == gt.resource
        and hit.data_type == str(gt.extra.get("data_type", ""))
    )


def _seed_reader_role(iam: object, name: str, grant_resource: str) -> None:
    """A moto IAM role with a customer-managed policy granting ``s3:GetObject`` on a resource."""
    doc = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "s3:GetObject", "Resource": grant_resource}
            ],
        }
    )
    policy_arn = iam.create_policy(PolicyName=f"{name}-read", PolicyDocument=doc)[  # type: ignore[attr-defined]
        "Policy"
    ]["Arn"]
    iam.create_role(  # type: ignore[attr-defined]
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": []}),
    )
    iam.attach_role_policy(RoleName=name, PolicyArn=policy_arn)  # type: ignore[attr-defined]


def _list_identities(iam: object) -> IdentityListing:
    degraded: list[dict[str, str]] = []
    return IdentityListing(
        users=tuple(_list_users(iam, degraded)),
        roles=tuple(_list_roles(iam, degraded)),
        groups=tuple(_list_groups(iam, degraded)),
        policies=tuple(_list_policies(iam, degraded)),
        degraded=tuple(degraded),
    )


async def run_fine_grained_case(path: Path | str) -> CapabilityResult:
    """Path 4 — a non-admin principal's concrete grant reaching public sensitive data.

    Drives BOTH feeders against one moto session: data-security writes the public bucket +
    EXPOSES_DATA; identity's real ``_fine_grained_grants`` extracts each role's concrete S3
    access and ``record_access`` writes HAS_ACCESS_TO. Scores ``find_fine_grained_data_exposure``.
    """
    case, buckets = load_bank_case(path)
    roles = (yaml.safe_load(Path(path).read_text()).get("environment") or {}).get("roles") or []
    async with in_memory_semantic_store() as store:
        with detection_timer() as timer:
            with moto_aws_clients(buckets) as (s3, iam):
                await drive_data_security(store, tenant_id=_TENANT, buckets=buckets, s3_client=s3)
                for role in roles:
                    _seed_reader_role(iam, str(role["name"]), str(role["grant_resource"]))
                grants = _fine_grained_grants(_list_identities(iam))
                await IdentityKgWriter(store, _TENANT).record_access(grants)
            raw_hits = await KgQuery(store, _TENANT).find_fine_grained_data_exposure()
            hits = await _resolve_principal_hits(store, raw_hits)
        return score(
            hits,
            case.ground_truth_violations,
            case.expected_non_detections,
            match=_match_principal,
            label=lambda h: f"{h.principal_arn}->{h.resource_arn}:{h.data_type}",
            detection_time_seconds=timer.seconds,
            test_case_id=case.test_case_id,
        )


# --- Path 8: external cross-account trust (identity + data-security) -----------------------

_FOREIGN_ACCOUNT = "999999999999"


def _seed_trust_role(iam: object, name: str, trust: str, grant_resource: str) -> None:
    """A moto IAM role with a trust policy (``external`` = foreign account, else service) AND a
    customer-managed policy granting ``s3:GetObject`` on ``grant_resource``."""
    if trust == "external":
        principal: dict[str, object] = {"AWS": f"arn:aws:iam::{_FOREIGN_ACCOUNT}:root"}
    else:
        principal = {"Service": "ec2.amazonaws.com"}
    trust_doc = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": principal, "Action": "sts:AssumeRole"}],
        }
    )
    access_doc = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "s3:GetObject", "Resource": grant_resource}
            ],
        }
    )
    policy_arn = iam.create_policy(PolicyName=f"{name}-read", PolicyDocument=access_doc)[  # type: ignore[attr-defined]
        "Policy"
    ]["Arn"]
    iam.create_role(RoleName=name, AssumeRolePolicyDocument=trust_doc)  # type: ignore[attr-defined]
    iam.attach_role_policy(RoleName=name, PolicyArn=policy_arn)  # type: ignore[attr-defined]


async def run_external_trust_case(path: Path | str) -> CapabilityResult:
    """Path 8 — an externally-trusted (cross-account) role that can reach public sensitive data.

    data-security writes the public bucket + EXPOSES_DATA; identity's real
    ``_externally_trusted_arns`` (offline trust-policy analysis) marks external trust and
    ``_fine_grained_grants`` writes the access edge. Scores ``find_external_trust_exposure``.
    """
    case, buckets = load_bank_case(path)
    roles = (yaml.safe_load(Path(path).read_text()).get("environment") or {}).get("roles") or []
    async with in_memory_semantic_store() as store:
        with detection_timer() as timer:
            with moto_aws_clients(buckets) as (s3, iam):
                await drive_data_security(store, tenant_id=_TENANT, buckets=buckets, s3_client=s3)
                for role in roles:
                    _seed_trust_role(
                        iam, str(role["name"]), str(role["trust"]), str(role["grant_resource"])
                    )
                listing = _list_identities(iam)
                writer = IdentityKgWriter(store, _TENANT)
                await writer.record_external_trust(_externally_trusted_arns(listing))
                await writer.record_access(_fine_grained_grants(listing))
            raw_hits = await KgQuery(store, _TENANT).find_external_trust_exposure()
            hits = await _resolve_principal_hits(store, raw_hits)
        return score(
            hits,
            case.ground_truth_violations,
            case.expected_non_detections,
            match=_match_principal,
            label=lambda h: f"{h.principal_arn}->{h.resource_arn}:{h.data_type}",
            detection_time_seconds=timer.seconds,
            test_case_id=case.test_case_id,
        )


async def _resolve_principal_hits(store: object, raw_hits: Sequence[Any]) -> list[_PrincipalHit]:
    """Resolve (principal_id, resource_id) entity ULIDs → ARNs for principal-based matching."""
    hits: list[_PrincipalHit] = []
    for h in raw_hits:
        principal = await store.get_entity(tenant_id=_TENANT, entity_id=h.principal_id)  # type: ignore[attr-defined]
        resource = await store.get_entity(tenant_id=_TENANT, entity_id=h.resource_id)  # type: ignore[attr-defined]
        hits.append(
            _PrincipalHit(
                principal_arn=principal.external_id if principal else "",
                resource_arn=resource.external_id if resource else "",
                data_type=h.data_type,
            )
        )
    return hits


# --- Path 10: exposed AI service + sensitive training data (aispm + data-security) ---------


@dataclass(frozen=True, slots=True)
class _ServiceHit:
    """An exposed-AI hit resolved to (service id, resource ARN, data type) for scoring."""

    service_id: str
    resource_arn: str
    data_type: str


def _match_service(hit: _ServiceHit, gt: GroundTruth) -> bool:
    """Match on AI service + resource + data type."""
    return (
        hit.service_id == str(gt.extra.get("service", ""))
        and hit.resource_arn == gt.resource
        and hit.data_type == str(gt.extra.get("data_type", ""))
    )


async def run_exposed_ai_case(path: Path | str) -> CapabilityResult:
    """Path 10 — an internet-exposed SageMaker endpoint whose training bucket is public + sensitive.

    data-security writes the public bucket + EXPOSES_DATA; aispm's real reader extracts the
    endpoint's exposure + model-data bucket and ``record_aws`` writes EXPOSES_MODEL +
    HAS_ACCESS_TO. Scores ``find_exposed_ai_with_sensitive_data``.
    """
    case, buckets = load_bank_case(path)
    endpoints = (yaml.safe_load(Path(path).read_text()).get("environment") or {}).get(
        "endpoints"
    ) or []
    async with in_memory_semantic_store() as store:
        with detection_timer() as timer:
            with moto_ai_clients(buckets) as (s3, sm):
                await drive_data_security(store, tenant_id=_TENANT, buckets=buckets, s3_client=s3)
                for ep in endpoints:
                    setup_sagemaker_endpoint(
                        sm,
                        name=str(ep["name"]),
                        model_data_bucket=str(ep["model_data_bucket"]),
                        network_isolated=bool(ep.get("network_isolated", False)),
                    )
                await drive_aispm(store, tenant_id=_TENANT, sm_client=sm)
            raw_hits = await KgQuery(store, _TENANT).find_exposed_ai_with_sensitive_data()
            hits: list[_ServiceHit] = []
            for h in raw_hits:
                svc = await store.get_entity(tenant_id=_TENANT, entity_id=h.service_id)
                res = await store.get_entity(tenant_id=_TENANT, entity_id=h.resource_id)
                hits.append(
                    _ServiceHit(
                        service_id=svc.external_id if svc else "",
                        resource_arn=res.external_id if res else "",
                        data_type=h.data_type,
                    )
                )
        return score(
            hits,
            case.ground_truth_violations,
            case.expected_non_detections,
            match=_match_service,
            label=lambda h: f"{h.service_id}->{h.resource_arn}:{h.data_type}",
            detection_time_seconds=timer.seconds,
            test_case_id=case.test_case_id,
        )


# --- Path 2: internet-exposed workload + vulnerable image (cloud-posture + vulnerability) ---
# TRIVY-GATED: drives the real trivy binary; tests gate on fleet_testkit.vuln_scan.trivy_available.


@dataclass(frozen=True, slots=True)
class _ImageHit:
    """A vuln-on-workload hit resolved to its image ref (the stable per-workload key)."""

    image_ref: str


def _match_image(hit: _ImageHit, gt: GroundTruth) -> bool:
    """Match on image ref — each fixture workload runs a distinct image, so the ref is its key.

    Real trivy emits many CVEs per image (many hits, same ref); score() collapses them to one
    matched ground truth, so CVE-count drift does not change precision/recall.
    """
    return hit.image_ref == gt.resource


async def _drive_vuln_for(store: object, image_ref: str, requirements: str) -> None:
    """Write a temp requirements fixture and drive REAL trivy → CVE graph for ``image_ref``."""
    with TemporaryDirectory() as fixture:
        (Path(fixture) / "requirements.txt").write_text(requirements)
        await drive_vulnerability(
            store, tenant_id=_TENANT, fixture_dir=fixture, image_ref=image_ref
        )


async def _resolve_image_hits(store: object, raw_hits: Sequence[Any]) -> list[_ImageHit]:
    out: list[_ImageHit] = []
    for h in raw_hits:
        image = await store.get_entity(tenant_id=_TENANT, entity_id=h.image_id)  # type: ignore[attr-defined]
        out.append(_ImageHit(image_ref=image.external_id if image else ""))
    return out


async def run_exposed_vuln_case(path: Path | str) -> CapabilityResult:
    """Path 2 — an internet-exposed ECS workload running an image with a known CVE.

    cloud-posture's real ECS reader writes the workload + RUNS_IMAGE; vulnerability's real
    trivy scan writes the CVEs onto the same image node. Scores
    ``find_internet_exposed_vulnerable_workload`` (TRIVY-GATED).
    """
    case, _ = load_bank_case(path)
    workloads = (yaml.safe_load(Path(path).read_text()).get("environment") or {}).get(
        "workloads"
    ) or []
    async with in_memory_semantic_store() as store:
        with detection_timer() as timer:
            with moto_ecs_clients() as (ecs, ec2):
                for w in workloads:
                    setup_ecs_workload(
                        ecs,
                        ec2,
                        image_ref=str(w["image"]),
                        public=bool(w["public"]),
                        name=str(w["name"]),
                    )
                await drive_cloud_workloads(
                    store, tenant_id=_TENANT, ecs_client=ecs, ec2_client=ec2
                )
            for w in workloads:
                if w.get("vulnerable_requirements"):
                    await _drive_vuln_for(store, str(w["image"]), str(w["vulnerable_requirements"]))
            raw_hits = await KgQuery(store, _TENANT).find_internet_exposed_vulnerable_workload()
            hits = await _resolve_image_hits(store, raw_hits)
        return score(
            hits,
            case.ground_truth_violations,
            case.expected_non_detections,
            match=_match_image,
            label=lambda h: h.image_ref,
            detection_time_seconds=timer.seconds,
            test_case_id=case.test_case_id,
        )


# --- Path 5: crown jewel — exposed + vulnerable + privileged + sensitive (all 4 feeders) ----
# TRIVY-GATED (moto ECS+IAM+S3 + real trivy; no kind).


async def _resolve_data_hits(store: object, raw_hits: Sequence[Any]) -> list[_Hit]:
    """Resolve a hit's ``resource_id`` (the reachable sensitive bucket) → ARN for data matching."""
    out: list[_Hit] = []
    for h in raw_hits:
        res = await store.get_entity(tenant_id=_TENANT, entity_id=h.resource_id)  # type: ignore[attr-defined]
        out.append(_Hit(bucket_arn=res.external_id if res else "", data_type=h.data_type))
    return out


async def run_crown_jewel_case(path: Path | str) -> CapabilityResult:
    """Path 5 — an internet-exposed ECS workload runs a vulnerable image AS a role that reaches
    public sensitive data. Drives ALL four feeders on one moto session + real trivy, scores
    ``find_crown_jewel_exposure`` on the reachable sensitive bucket (TRIVY-GATED).
    """
    case, buckets = load_bank_case(path)
    workloads = (yaml.safe_load(Path(path).read_text()).get("environment") or {}).get(
        "workloads"
    ) or []
    async with in_memory_semantic_store() as store:
        with detection_timer() as timer:
            with moto_all_clients(buckets) as (s3, iam, ecs, ec2):
                await drive_data_security(store, tenant_id=_TENANT, buckets=buckets, s3_client=s3)
                for w in workloads:
                    role_arn = ""
                    if w.get("task_role"):
                        _seed_reader_role(iam, str(w["task_role"]), str(w["role_grant_resource"]))
                        role_arn = f"arn:aws:iam::123456789012:role/{w['task_role']}"
                    setup_ecs_workload(
                        ecs,
                        ec2,
                        image_ref=str(w["image"]),
                        public=bool(w["public"]),
                        name=str(w["name"]),
                        task_role_arn=role_arn,
                    )
                await drive_cloud_workloads(
                    store, tenant_id=_TENANT, ecs_client=ecs, ec2_client=ec2
                )
                await IdentityKgWriter(store, _TENANT).record_access(
                    _fine_grained_grants(_list_identities(iam))
                )
            for w in workloads:
                if w.get("vulnerable_requirements"):
                    await _drive_vuln_for(store, str(w["image"]), str(w["vulnerable_requirements"]))
            raw_hits = await KgQuery(store, _TENANT).find_crown_jewel_exposure()
            hits = await _resolve_data_hits(store, raw_hits)
        return score(
            hits,
            case.ground_truth_violations,
            case.expected_non_detections,
            match=_match,
            label=lambda h: f"{h.bucket_arn}:{h.data_type}",
            detection_time_seconds=timer.seconds,
            test_case_id=case.test_case_id,
        )


# --- Path 6: privileged K8s pod + vulnerable image (k8s-posture + vulnerability) ------------
# KIND + TRIVY-GATED: applies real pods to a live kind cluster; tests gate on kind_context().


def kind_context() -> str | None:
    """The current kube context iff it is a kind cluster (throwaway). Else None → skip."""
    if not kubectl_available():
        return None
    try:
        ctx = subprocess.run(
            ["kubectl", "config", "current-context"],  # noqa: S607
            capture_output=True,
            text=True,
            timeout=10,
            check=True,
        ).stdout.strip()
    except (subprocess.SubprocessError, OSError):
        return None
    return ctx if ctx.startswith("kind-") else None


def _pod_manifest(namespace: str, pod: dict) -> str:
    # securityContext keys align with name/image (4 spaces under the container list item).
    sec_ctx = "\n    securityContext:\n      privileged: true" if pod.get("privileged") else ""
    return (
        "apiVersion: v1\nkind: Pod\n"
        f"metadata:\n  name: {pod['name']}\n  namespace: {namespace}\n"
        f"spec:\n  containers:\n  - name: app\n    image: {pod['image']}{sec_ctx}"
    )


def _kubectl(context: str, *args: str, stdin: str | None = None) -> None:
    subprocess.run(  # noqa: S603
        ["kubectl", "--context", context, *args],  # noqa: S607
        input=stdin,
        capture_output=True,
        text=True,
        timeout=60,
        check=True,
    )


async def run_privileged_vuln_case(path: Path | str, *, context: str) -> CapabilityResult:
    """Path 6 — a privileged K8s pod running an image with a known CVE.

    Applies the case's pods to a throwaway namespace on the live kind cluster, reads them with
    k8s-posture's real ``read_privileged_workloads``, drives real trivy for vulnerable images,
    and scores ``find_privileged_vulnerable_workload`` (KIND + TRIVY-GATED)."""
    case, _ = load_bank_case(path)
    pods = (yaml.safe_load(Path(path).read_text()).get("environment") or {}).get("pods") or []
    # Unique per run — the same case runs twice (per-case + aggregate) and the prior
    # --wait=false delete may still be terminating, so a fixed name would collide.
    namespace = f"path6-bank-{uuid.uuid4().hex[:8]}"
    _kubectl(context, "create", "namespace", namespace)
    try:
        _kubectl(
            context,
            "apply",
            "-f",
            "-",
            stdin="\n---\n".join(_pod_manifest(namespace, p) for p in pods),
        )
        async with in_memory_semantic_store() as store:
            with detection_timer() as timer:
                workloads = [
                    w
                    for w in read_privileged_workloads(context=context)
                    if w.namespace == namespace
                ]
                await K8sKgWriter(store, _TENANT).record_privileged_workloads(context, workloads)
                for p in pods:
                    if p.get("vulnerable_requirements"):
                        await _drive_vuln_for(
                            store, str(p["image"]), str(p["vulnerable_requirements"])
                        )
                raw_hits = await KgQuery(store, _TENANT).find_privileged_vulnerable_workload()
                hits = await _resolve_image_hits(store, raw_hits)
            return score(
                hits,
                case.ground_truth_violations,
                case.expected_non_detections,
                match=_match_image,
                label=lambda h: h.image_ref,
                detection_time_seconds=timer.seconds,
                test_case_id=case.test_case_id,
            )
    finally:
        _kubectl(context, "delete", "namespace", namespace, "--wait=false")


__all__ = [
    "kind_context",
    "load_bank_case",
    "run_crown_jewel_case",
    "run_data_security_case",
    "run_exposed_ai_case",
    "run_exposed_vuln_case",
    "run_external_trust_case",
    "run_fine_grained_case",
    "run_privileged_vuln_case",
    "run_public_secret_case",
    "run_public_unencrypted_case",
    "run_resource_based_case",
]
