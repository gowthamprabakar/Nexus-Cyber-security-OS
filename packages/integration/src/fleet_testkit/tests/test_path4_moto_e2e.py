"""Path 4 (fine-grained over-permission → sensitive data) committed moto e2e.

Proves the identity-DEPTH chain REAL — and DISTINCT from path 1 (admin) — through the agents'
own code:

- data-security's *real* S3 path writes the public-PII bucket node + EXPOSES_DATA edge.
- a moto IAM role gets a customer-managed policy granting ``s3:GetObject`` on JUST that bucket
  (NOT admin). identity's *real* readers build the listing; the *real* ``_fine_grained_grants``
  extracts the concrete (role, bucket) grant OFFLINE, while the *real* ``_synthesize_admin_grants``
  returns nothing — proving this is the new fine-grained path the admin-only seed (1) misses.
- ``record_access`` writes HAS_ACCESS_TO; ``KgQuery.find_fine_grained_data_exposure`` lights up.

No fixtures, no fake IAM/S3, no hand-supplied grants. moto is in-process → unskipped CI.
"""

import json

import pytest
from charter.memory.graph_types import NodeCategory
from identity.agent import _fine_grained_grants, _synthesize_admin_grants
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
from fleet_testkit.moto_aws import moto_aws_clients

_TENANT = "tenant-path4"
_SSN = b"patient ssn 123-45-6789 on file\n"
_BUCKET = "acme-pii"
_TRUST_DOC = json.dumps({"Version": "2012-10-17", "Statement": []})
# Fine-grained: read JUST this bucket's objects. NOT admin.
_READ_DOC = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": f"arn:aws:s3:::{_BUCKET}/*",
            }
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


def _seed_reader_role(iam: object, role_name: str) -> None:
    policy_arn = iam.create_policy(  # type: ignore[attr-defined]
        PolicyName="ReadAcmePii", PolicyDocument=_READ_DOC
    )["Policy"]["Arn"]
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=_TRUST_DOC)  # type: ignore[attr-defined]
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)  # type: ignore[attr-defined]


async def _identity_id(store: object, external_id: str) -> str | None:
    rows = await store.list_entities_by_type(  # type: ignore[attr-defined]
        tenant_id=_TENANT, entity_type=NodeCategory.IDENTITY.value
    )
    return next((r.entity_id for r in rows if r.external_id == external_id), None)


@pytest.mark.asyncio
async def test_non_admin_fine_grained_access_to_public_pii_lights_up() -> None:
    buckets = (MotoBucket(_BUCKET, public=True, objects={"records.txt": _SSN}),)
    async with in_memory_semantic_store() as store:
        with moto_aws_clients(buckets) as (s3, iam):
            arns = await drive_data_security(
                store, tenant_id=_TENANT, buckets=buckets, s3_client=s3
            )
            bucket_arn = arns[_BUCKET]

            _seed_reader_role(iam, "pii-reader")
            listing = _list_identities(iam)
            fine = _fine_grained_grants(listing)
            admin = _synthesize_admin_grants(listing)

        # The new path: fine-grained grant present, admin synthesis blind to it.
        assert admin == [], "the reader role is NOT admin — path 1 would miss it"
        assert len(fine) == 1
        role_arn, granted_arn = fine[0]
        assert granted_arn == bucket_arn

        await IdentityKgWriter(store, _TENANT).record_access(fine)
        role_id = await _identity_id(store, role_arn)
        assert role_id is not None

        hits = await KgQuery(store, _TENANT).find_fine_grained_data_exposure()
        assert len(hits) == 1
        assert hits[0].principal_id == role_id
        assert hits[0].data_type == "ssn"


@pytest.mark.asyncio
async def test_private_bucket_fine_grained_access_is_dark() -> None:
    # Same fine-grained grant, but a private bucket → no EXPOSES_DATA → dark.
    buckets = (MotoBucket(_BUCKET, public=False, objects={"records.txt": _SSN}),)
    async with in_memory_semantic_store() as store:
        with moto_aws_clients(buckets) as (s3, iam):
            arns = await drive_data_security(
                store, tenant_id=_TENANT, buckets=buckets, s3_client=s3
            )
            _seed_reader_role(iam, "pii-reader")
            fine = _fine_grained_grants(_list_identities(iam))

        assert fine and fine[0][1] == arns[_BUCKET]
        await IdentityKgWriter(store, _TENANT).record_access(fine)
        assert await KgQuery(store, _TENANT).find_fine_grained_data_exposure() == []
