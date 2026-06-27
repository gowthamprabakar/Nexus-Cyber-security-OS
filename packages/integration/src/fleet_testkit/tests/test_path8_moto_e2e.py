"""Path 8 (external/cross-account trust → sensitive data) committed moto e2e.

Proves the path-8 chain REAL through the agents' own code:

- data-security's *live* S3 reader + *real* classifier detect PII (SSN) in a *public* moto
  bucket and the *real* ``kg_writer.record`` writes the EXPOSES_DATA edge.
- a moto IAM role is created with a *cross-account* trust policy. identity's *real* readers
  build the listing, the *real* ``_externally_trusted_arns`` derives external trust OFFLINE
  (no Access-Analyzer call), and the *real* ``record_external_trust`` marks the principal
  node ``external_trust=True``. ``record_access`` writes HAS_ACCESS_TO to the same bucket.
- ``KgQuery.find_external_trust_exposure`` lights up exactly one ExternalTrustExposure.

No fixtures, no fake S3/IAM, no hand-supplied trust verdict or grants. moto is in-process,
so this runs unskipped in normal CI.
"""

import json

import pytest
from charter.memory.graph_types import NodeCategory
from identity.agent import _externally_trusted_arns
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

_TENANT = "tenant-path8"
_SSN = b"patient ssn 123-45-6789 on file\n"
# A trust policy that lets a *foreign* account assume the role (the path-8 risk).
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
# A same-account trust policy — internal, must NOT flag.
_INTERNAL_TRUST = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "ec2.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
)


def _list_identities(iam: object) -> IdentityListing:
    """Build an IdentityListing from a moto IAM via the REAL per-section readers."""
    degraded: list[dict[str, str]] = []
    return IdentityListing(
        users=tuple(_list_users(iam, degraded)),
        roles=tuple(_list_roles(iam, degraded)),
        groups=tuple(_list_groups(iam, degraded)),
        policies=tuple(_list_policies(iam, degraded)),
        degraded=tuple(degraded),
    )


def _seed_role(iam: object, role_name: str, trust_doc: str) -> None:
    iam.create_role(  # type: ignore[attr-defined]
        RoleName=role_name, AssumeRolePolicyDocument=trust_doc
    )


async def _entity_id_for(store: object, external_id: str) -> str | None:
    rows = await store.list_entities_by_type(  # type: ignore[attr-defined]
        tenant_id=_TENANT, entity_type=NodeCategory.IDENTITY.value
    )
    return next((r.entity_id for r in rows if r.external_id == external_id), None)


@pytest.mark.asyncio
async def test_cross_account_role_with_access_to_public_pii_lights_up() -> None:
    buckets = (MotoBucket("acme-pii", public=True, objects={"records.txt": _SSN}),)
    async with in_memory_semantic_store() as store:
        with moto_aws_clients(buckets) as (s3, iam):
            arns = await drive_data_security(
                store, tenant_id=_TENANT, buckets=buckets, s3_client=s3
            )
            bucket_arn = arns["acme-pii"]

            _seed_role(iam, "partner-access", _FOREIGN_TRUST)
            listing = _list_identities(iam)
            external = _externally_trusted_arns(listing)

        assert len(external) == 1, "real offline analysis flagged exactly one external role"
        role_arn = external[0]

        writer = IdentityKgWriter(store, _TENANT)
        await writer.record_external_trust(external)
        await writer.record_access([(role_arn, bucket_arn)])

        role_id = await _entity_id_for(store, role_arn)
        assert role_id is not None
        bucket_rows = await store.list_entities_by_type(
            tenant_id=_TENANT, entity_type=NodeCategory.CLOUD_RESOURCE.value
        )
        bucket_id = next(r.entity_id for r in bucket_rows if r.external_id == bucket_arn)

        hits = await KgQuery(store, _TENANT).find_external_trust_exposure()
        assert len(hits) == 1
        assert hits[0].principal_id == role_id
        assert hits[0].resource_id == bucket_id
        assert hits[0].data_type == "ssn"


@pytest.mark.asyncio
async def test_internal_role_is_dark() -> None:
    # Same public PII + access, but a service-trust (internal) role → no external_trust → dark.
    buckets = (MotoBucket("acme-pii", public=True, objects={"records.txt": _SSN}),)
    async with in_memory_semantic_store() as store:
        with moto_aws_clients(buckets) as (s3, iam):
            arns = await drive_data_security(
                store, tenant_id=_TENANT, buckets=buckets, s3_client=s3
            )
            _seed_role(iam, "internal", _INTERNAL_TRUST)
            external = _externally_trusted_arns(_list_identities(iam))

        assert external == []
        # Even if access exists, no external_trust mark → query stays dark.
        role_arn = "arn:aws:iam::123456789012:role/internal"
        await IdentityKgWriter(store, _TENANT).record_access([(role_arn, arns["acme-pii"])])
        assert await KgQuery(store, _TENANT).find_external_trust_exposure() == []
