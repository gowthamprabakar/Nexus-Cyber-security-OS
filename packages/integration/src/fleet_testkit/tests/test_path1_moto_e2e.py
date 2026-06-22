"""Path 1 (public-data-exposure / toxic combination) committed moto e2e.

Proves the moat's path-1 attack chain REAL end-to-end through both agents' own code:

- data-security's *live* S3 reader + *real* classifier detect a PII (SSN) body in a
  *public* moto bucket and the *real* ``kg_writer.record`` writes the EXPOSES_DATA edge.
- identity's *real* IAM readers (``_list_*``) enumerate an admin role from a moto IAM,
  the *real* ``_synthesize_admin_grants`` derives the admin ``EffectiveGrant`` from the
  moto-derived listing, and the *real* ``record_access`` writes HAS_ACCESS_TO to the
  SAME bucket ARN (mirroring ``_write_access_edges``: admin "*" expands over the tenant's
  concrete CLOUD_RESOURCE nodes).
- ``KgQuery.find_public_data_exposure`` lights up exactly one ToxicCombination.

No fixtures, no fake S3/IAM, no hand-supplied classifier hits or grants. moto is
in-process, so this runs unskipped in normal CI.
"""

import json

import pytest
from charter.memory.graph_types import NodeCategory
from identity.agent import _synthesize_admin_grants
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

_TENANT = "tenant-path1"
_SSN = b"patient ssn 123-45-6789 on file\n"
# moto has no AWS-managed policies, so create a customer-managed AdministratorAccess.
# data-security/identity admin detection matches ``*/AdministratorAccess``.
_ADMIN_DOC = json.dumps(
    {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
)
_TRUST_DOC = json.dumps({"Version": "2012-10-17", "Statement": []})


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


def _seed_admin_role(iam: object, role_name: str) -> None:
    policy_arn = iam.create_policy(  # type: ignore[attr-defined]
        PolicyName="AdministratorAccess", PolicyDocument=_ADMIN_DOC
    )["Policy"]["Arn"]
    iam.create_role(  # type: ignore[attr-defined]
        RoleName=role_name, AssumeRolePolicyDocument=_TRUST_DOC
    )
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)  # type: ignore[attr-defined]


async def _entity_id_for(store: object, external_id: str) -> str | None:
    rows = await store.list_entities_by_type(  # type: ignore[attr-defined]
        tenant_id=_TENANT, entity_type=NodeCategory.IDENTITY.value
    )
    return next((r.entity_id for r in rows if r.external_id == external_id), None)


@pytest.mark.asyncio
async def test_public_pii_plus_admin_role_lights_up_one_toxic_combination() -> None:
    buckets = (MotoBucket("acme-pii", public=True, objects={"records.txt": _SSN}),)
    async with in_memory_semantic_store() as store:
        with moto_aws_clients(buckets) as (s3, iam):
            # 1. REAL data-security path: public bucket + SSN → resource + EXPOSES_DATA.
            arns = await drive_data_security(
                store, tenant_id=_TENANT, buckets=buckets, s3_client=s3
            )
            bucket_arn = arns["acme-pii"]

            # 2. REAL identity path: admin role in moto → real readers → real synthesis.
            _seed_admin_role(iam, "app-admin")
            listing = _list_identities(iam)
            grants = _synthesize_admin_grants(listing)

        admins = [g for g in grants if g.is_admin]
        assert len(admins) == 1, "real synthesis derived exactly one admin grant"
        role_arn = admins[0].principal_arn

        # Mirror _write_access_edges: admin "*" expands over concrete CLOUD_RESOURCE nodes.
        await IdentityKgWriter(store, _TENANT).record_access([(role_arn, bucket_arn)])

        role_id = await _entity_id_for(store, role_arn)
        assert role_id is not None

        # Resolve the bucket's entity_id so we can assert the toxic combo's resource leg.
        bucket_rows = await store.list_entities_by_type(
            tenant_id=_TENANT, entity_type=NodeCategory.CLOUD_RESOURCE.value
        )
        bucket_id = next(r.entity_id for r in bucket_rows if r.external_id == bucket_arn)

        hits = await KgQuery(store, _TENANT).find_public_data_exposure(
            over_permissioned_principal_ids=[role_id]
        )
        assert len(hits) == 1
        assert hits[0].principal_id == role_id
        assert hits[0].resource_id == bucket_id


@pytest.mark.asyncio
async def test_private_pii_plus_admin_role_is_dark() -> None:
    # Private bucket → no EXPOSES_DATA → no toxic combination even with admin access.
    buckets = (MotoBucket("acme-pii", public=False, objects={"records.txt": _SSN}),)
    async with in_memory_semantic_store() as store:
        with moto_aws_clients(buckets) as (s3, iam):
            arns = await drive_data_security(
                store, tenant_id=_TENANT, buckets=buckets, s3_client=s3
            )
            _seed_admin_role(iam, "app-admin")
            grants = _synthesize_admin_grants(_list_identities(iam))

        role_arn = next(g.principal_arn for g in grants if g.is_admin)
        await IdentityKgWriter(store, _TENANT).record_access([(role_arn, arns["acme-pii"])])
        role_id = await _entity_id_for(store, role_arn)
        assert role_id is not None
        hits = await KgQuery(store, _TENANT).find_public_data_exposure(
            over_permissioned_principal_ids=[role_id]
        )
        assert hits == []
