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
from meta_harness.attack_paths import AttackPathRanker
from meta_harness.kg_query import KgQuery

from fleet_testkit import MotoBucket, drive_data_security, in_memory_semantic_store
from fleet_testkit.moto_aws import drive_aispm, moto_scene_clients, setup_sagemaker_endpoint
from fleet_testkit.moto_identity import list_moto_identities

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
