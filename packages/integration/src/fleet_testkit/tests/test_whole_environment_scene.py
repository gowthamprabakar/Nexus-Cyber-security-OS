"""Whole-environment scene — the product-level "watched it work" test (North Star).

Every other path test validates ONE detector in isolation. This plants a realistic environment —
six distinct attack paths mixed with benign noise — into ONE moto AWS account, drives the REAL
feeders (data-security + identity + aispm), and runs the actual product surface
``AttackPathRanker.find_all()`` end-to-end. It asserts the ranker surfaces exactly the planted
paths, worst-first, with NO false positive from the noise. Hermetic (moto + injectable SageMaker;
the trivy/kind paths 2/5/6 are validated by their own e2es).

Planted (one bucket each, properties tuned so each lights exactly its intended path):
  - acme-creds   public + encrypted + AWS key      -> public_secret (90)
  - acme-logs    public + UNencrypted + SSN         -> public_unencrypted (75)
  - acme-exports public + encrypted + SSN + a cross-account-trusted role with access
                                                     -> external_trust (70) [+ fine_grained: the
                                                        external role is also a fine-grained grant]
  - acme-training public + encrypted + SSN + an internet-exposed SageMaker endpoint reading it
                                                     -> exposed_ai_sensitive_data (68)
  - acme-shared  PRIVATE + encrypted + SSN + bucket-policy grant to a named principal
                                                     -> resource_based_data (62)
  - acme-pii     public + encrypted + SSN + a non-admin role with s3:GetObject on it
                                                     -> fine_grained_data (60)
Noise (must produce NO path):
  - acme-archive PRIVATE + encrypted + SSN (sensitive but not exposed, no grant, no policy)
  - acme-web     public + encrypted + benign HTML (exposed but nothing sensitive)
"""

import json

import pytest
from charter.memory.graph_types import NodeCategory
from identity.agent import _externally_trusted_arns, _fine_grained_grants
from identity.kg_writer import KnowledgeGraphWriter as IdentityKgWriter
from meta_harness.attack_path_report import render_report
from meta_harness.attack_paths import AttackPathRanker
from meta_harness.kg_query import KgQuery

from fleet_testkit import MotoBucket, drive_data_security, in_memory_semantic_store
from fleet_testkit.azure_blob import AzureContainer, drive_azure_data_security
from fleet_testkit.gcs_blob import PUBLIC_MEMBER, GcsBucketSeed, drive_gcs_data_security
from fleet_testkit.k8s_workloads import drive_privileged_workloads, managed_cluster_pods
from fleet_testkit.moto_aws import (
    drive_aispm,
    drive_cloud_workloads,
    moto_full_clients,
    moto_scene_clients,
    setup_ecs_workload,
    setup_sagemaker_endpoint,
)
from fleet_testkit.moto_identity import list_moto_identities
from fleet_testkit.vuln_scan import drive_vulnerability, trivy_available

_TENANT = "tenant-scene"
_AWS_KEY = b"aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n"
_SSN = b"patient ssn 123-45-6789 on file\n"
_HTML = b"<html>public marketing page</html>\n"

_BUCKETS = (
    # planted
    MotoBucket("acme-creds", public=True, encrypted=True, objects={"key.txt": _AWS_KEY}),
    MotoBucket("acme-logs", public=True, encrypted=False, objects={"app.log": _SSN}),
    MotoBucket("acme-exports", public=True, encrypted=True, objects={"export.csv": _SSN}),
    MotoBucket("acme-training", public=True, encrypted=True, objects={"data.csv": _SSN}),
    MotoBucket("acme-pii", public=True, encrypted=True, objects={"records.txt": _SSN}),
    MotoBucket(
        "acme-shared",
        public=False,
        encrypted=True,
        objects={"shared.csv": _SSN},
        policy=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"AWS": "arn:aws:iam::999999999999:role/partner-read"},
                        "Action": "s3:GetObject",
                        "Resource": "arn:aws:s3:::acme-shared/*",
                    }
                ],
            }
        ),
    ),
    # noise — must produce NO path
    MotoBucket("acme-archive", public=False, encrypted=True, objects={"old.csv": _SSN}),
    MotoBucket("acme-web", public=True, encrypted=True, objects={"index.html": _HTML}),
)

_TRUST_EMPTY = json.dumps({"Version": "2012-10-17", "Statement": []})
_FOREIGN_TRUST = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::999999999999:root"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
)
_FINE_GRAINED_READ = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::acme-pii/*"}
        ],
    }
)
_CROWN_READ = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::acme-crown/*"}
        ],
    }
)
_ECS_IMAGE = "myreg/web:1.0"
_K8S_IMAGE = "myreg/k8s:1.0"


def _seed_fine_grained_role(iam: object) -> None:
    arn = iam.create_policy(  # type: ignore[attr-defined]
        PolicyName="ReadAcmePii", PolicyDocument=_FINE_GRAINED_READ
    )["Policy"]["Arn"]
    iam.create_role(RoleName="analyst", AssumeRolePolicyDocument=_TRUST_EMPTY)  # type: ignore[attr-defined]
    iam.attach_role_policy(RoleName="analyst", PolicyArn=arn)  # type: ignore[attr-defined]


async def _entity_id(store: object, external_id: str) -> str | None:
    for r in await store.list_entities_by_type(  # type: ignore[attr-defined]
        tenant_id=_TENANT, entity_type=NodeCategory.CLOUD_RESOURCE.value
    ):
        if r.external_id == external_id:
            return r.entity_id
    return None


@pytest.mark.asyncio
async def test_whole_environment_surfaces_planted_paths_and_no_noise() -> None:
    async with in_memory_semantic_store() as store:
        with moto_scene_clients(_BUCKETS) as (s3, iam, sm):
            # --- data leg: all buckets through data-security's real readers/classifier ---
            arns = await drive_data_security(
                store, tenant_id=_TENANT, buckets=_BUCKETS, s3_client=s3
            )

            # --- identity leg: a fine-grained role (path 4) + an external-trust role (path 8) ---
            _seed_fine_grained_role(iam)
            iam.create_role(RoleName="partner", AssumeRolePolicyDocument=_FOREIGN_TRUST)  # type: ignore[attr-defined]
            listing = list_moto_identities(iam)
            fine = _fine_grained_grants(listing)
            external = _externally_trusted_arns(listing)

            writer = IdentityKgWriter(store, _TENANT)
            await writer.record_access(fine)  # analyst -> acme-pii
            await writer.record_external_trust(external)
            await writer.record_access([(external[0], arns["acme-exports"])])  # partner -> exports

            # --- AI leg: one exposed endpoint reading the public training bucket (path 10) +
            #     one isolated endpoint reading a private bucket (noise) ---
            setup_sagemaker_endpoint(
                sm, name="fraud-model", model_data_bucket="acme-training", network_isolated=False
            )
            setup_sagemaker_endpoint(
                sm, name="internal-model", model_data_bucket="acme-archive", network_isolated=True
            )
            await drive_aispm(store, tenant_id=_TENANT, sm_client=sm)

        # --- the product surface: connect account -> ranked attack paths ---
        paths = await AttackPathRanker(KgQuery(store, _TENANT)).find_all()

        # Noise bucket entity ids — must appear in NO surfaced path (gathered before store closes).
        noise_ids = {
            nid
            for name in ("acme-archive", "acme-web")
            if (nid := await _entity_id(store, arns[name])) is not None
        }

    types = {p.path_type for p in paths}
    assert types == {
        "public_secret",
        "public_unencrypted",
        "external_trust",
        "exposed_ai_sensitive_data",
        "resource_based_data",
        "fine_grained_data",
    }, f"surfaced exactly the planted path types (got {sorted(types)})"

    # Worst-first: severities are non-increasing, top is the public secret.
    assert [p.severity for p in paths] == sorted((p.severity for p in paths), reverse=True)
    assert paths[0].path_type == "public_secret"

    # NO false positive: neither noise bucket appears in any surfaced path's entities.
    assert len(noise_ids) == 2, "both noise buckets were recorded"
    flagged = {e for p in paths for e in p.entities}
    assert noise_ids.isdisjoint(flagged), "a benign/noise bucket leaked into an attack path"

    # The front door: the real ranker output renders into a customer-facing report.
    report = render_report(paths, tenant_id=_TENANT)
    assert f"Top attack paths for tenant {_TENANT}" in report
    assert "[CRITICAL 90] Public secret" in report  # worst-first, banded, labeled
    assert "[MEDIUM 60] Over-permissioned access" in report


def _write_vulnerable_fixture(root) -> None:
    (root / "requirements.txt").write_text("Django==2.0.0\n")


async def _external_ids(store: object) -> dict[str, str]:
    """{entity_id: external_id} across the node types attack paths reference."""
    out: dict[str, str] = {}
    for cat in (NodeCategory.CLOUD_RESOURCE, NodeCategory.IDENTITY, NodeCategory.AI_SERVICE):
        for r in await store.list_entities_by_type(tenant_id=_TENANT, entity_type=cat.value):  # type: ignore[attr-defined]
            out[r.entity_id] = r.external_id
    return out


@pytest.mark.skipif(not trivy_available, reason="trivy binary not installed")
@pytest.mark.asyncio
async def test_full_fleet_scene_all_nine_archetypes_across_three_clouds(tmp_path) -> None:
    """The flagship: every one of the 9 detectors fires in ONE tenant, spanning AWS + Azure + GCP.

    Extends the hermetic scene with the trivy paths (2 internet-exposed-vuln, 5 crown jewel, 6
    privileged-pod) and a cross-cloud storage mix (Azure secret, GCS unencrypted), then asserts the
    single ranked list covers all 9 archetypes and references resources from all three clouds.
    """
    _write_vulnerable_fixture(tmp_path)
    buckets = (
        *_BUCKETS,
        MotoBucket("acme-crown", public=True, encrypted=True, objects={"c.csv": _SSN}),
    )
    async with in_memory_semantic_store() as store:
        with moto_full_clients(buckets) as (s3, iam, ecs, ec2, sm):
            await drive_data_security(store, tenant_id=_TENANT, buckets=buckets, s3_client=s3)

            # identity: fine-grained (path 4) + external trust (path 8) + crown task role (path 5)
            _seed_fine_grained_role(iam)
            iam.create_role(RoleName="partner", AssumeRolePolicyDocument=_FOREIGN_TRUST)  # type: ignore[attr-defined]
            crown_policy = iam.create_policy(  # type: ignore[attr-defined]
                PolicyName="ReadCrown", PolicyDocument=_CROWN_READ
            )["Policy"]["Arn"]
            crown_role = iam.create_role(  # type: ignore[attr-defined]
                RoleName="crown-task", AssumeRolePolicyDocument=_TRUST_EMPTY
            )["Role"]["Arn"]
            iam.attach_role_policy(RoleName="crown-task", PolicyArn=crown_policy)  # type: ignore[attr-defined]

            listing = list_moto_identities(iam)
            writer = IdentityKgWriter(store, _TENANT)
            await writer.record_access(_fine_grained_grants(listing))  # analyst + crown-task
            external = _externally_trusted_arns(listing)
            await writer.record_external_trust(external)
            await writer.record_access([(external[0], "arn:aws:s3:::acme-exports")])

            # AI (path 10): exposed endpoint reading the public training bucket + an isolated one
            setup_sagemaker_endpoint(
                sm, name="fraud-model", model_data_bucket="acme-training", network_isolated=False
            )
            await drive_aispm(store, tenant_id=_TENANT, sm_client=sm)

            # workload (path 5): exposed ECS running the vuln image, assuming the crown role.
            setup_ecs_workload(
                ecs, ec2, image_ref=_ECS_IMAGE, public=True, name="crown", task_role_arn=crown_role
            )
            # workload (path 2): a SEPARATE exposed + vulnerable workload with no data-reaching role,
            # so internet_exposed_vulnerable surfaces on its own (the crown workload's is subsumed).
            setup_ecs_workload(ecs, ec2, image_ref=_ECS_IMAGE, public=True, name="plain")
            await drive_cloud_workloads(store, tenant_id=_TENANT, ecs_client=ecs, ec2_client=ec2)

        # vulnerability (real trivy) — CVEs on the ECS image AND the K8s image
        await drive_vulnerability(
            store, tenant_id=_TENANT, fixture_dir=tmp_path, image_ref=_ECS_IMAGE
        )
        await drive_vulnerability(
            store, tenant_id=_TENANT, fixture_dir=tmp_path, image_ref=_K8S_IMAGE
        )

        # K8s (path 6): a privileged pod running the vuln image (managed-cluster payload, hermetic)
        await drive_privileged_workloads(
            store,
            tenant_id=_TENANT,
            cluster_id="aks-prod",
            pods_json=managed_cluster_pods(
                name="web",
                image=_K8S_IMAGE,
                privileged=True,
                node_name="aks-nodepool1-vmss000000",
                node_labels={"kubernetes.azure.com/cluster": "mc"},
            ),
        )

        # cross-cloud mix: an Azure public-secret container + a GCS public-unencrypted bucket
        await drive_azure_data_security(
            store,
            tenant_id=_TENANT,
            containers=(
                AzureContainer("az-creds", public_access="container", blobs={"k": _AWS_KEY}),
            ),
        )
        await drive_gcs_data_security(
            store,
            tenant_id=_TENANT,
            buckets=(
                GcsBucketSeed(
                    "gcs-logs", iam_members=(PUBLIC_MEMBER,), encrypted=False, blobs={"l": _SSN}
                ),
            ),
        )

        paths = await AttackPathRanker(KgQuery(store, _TENANT)).find_all()
        ext = await _external_ids(store)

    # All NINE archetypes fire in one tenant.
    assert {p.path_type for p in paths} == {
        "crown_jewel",
        "public_secret",
        "internet_exposed_vulnerable",
        "privileged_vulnerable",
        "public_unencrypted",
        "external_trust",
        "exposed_ai_sensitive_data",
        "resource_based_data",
        "fine_grained_data",
    }, f"got {sorted({p.path_type for p in paths})}"

    # Worst-first: severity desc, then evidence count desc (sort key (-severity, -count)).
    order = [(-p.severity, -p.count) for p in paths]
    assert order == sorted(order)
    assert paths[0].path_type == "crown_jewel"

    # Grouping: the vuln-bearing paths roll up ALL the workload's CVEs into ONE path each, not one
    # row per CVE — the "top ~10 prioritized" promise. The Django==2.0.0 image carries several CVEs.
    by_type = {p.path_type: p for p in paths}
    cve_count = by_type["internet_exposed_vulnerable"].count
    assert cve_count > 1, "the vulnerable image has multiple CVEs rolled into one path"
    assert by_type["crown_jewel"].count == cve_count
    assert by_type["privileged_vulnerable"].count == cve_count
    # Ungrouped, those three paths alone would be 3 * cve_count rows; grouped they are 3.
    vuln_rows = [
        p for p in paths if p.path_type.endswith("vulnerable") or p.path_type == "crown_jewel"
    ]
    assert len(vuln_rows) == 3, "each vuln-bearing archetype collapses to a single ranked path"

    # ONE ranked list spans all three clouds — flagged resources include an AWS ARN, an Azure
    # blob URI, and a GCS URI.
    flagged_ext = {ext[e] for p in paths for e in p.entities if e in ext}
    assert any(x.startswith("arn:aws:") for x in flagged_ext), "AWS resource in the ranked list"
    assert any("blob.core.windows.net" in x for x in flagged_ext), (
        "Azure resource in the ranked list"
    )
    assert any(x.startswith("gs://") for x in flagged_ext), "GCP resource in the ranked list"
