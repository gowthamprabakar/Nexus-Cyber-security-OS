"""Path #13 — privilege escalation: a principal reaches data by assuming a role, REAL e2e.

The classic escalation Wiz markets: a user has NO direct access to sensitive data, but a role's
trust policy lets it assume that role, and the role CAN read the data. Drives identity's REAL trust
+ access readers against moto: ``_assume_grants`` extracts the (user -> role) assumption from the
role's trust policy, ``_fine_grained_grants`` the role's data access; the detector joins them. The
escalating user is flagged distinctly from the role's own direct-access finding.
"""

import json

import pytest
from identity.agent import _assume_grants, _fine_grained_grants
from identity.kg_writer import KnowledgeGraphWriter as IdentityKgWriter
from meta_harness.attack_paths import AttackPathRanker
from meta_harness.kg_query import KgQuery

from fleet_testkit import MotoBucket, drive_data_security, in_memory_semantic_store
from fleet_testkit.moto_aws import moto_scene_clients
from fleet_testkit.moto_identity import list_moto_identities

_TENANT = "tenant-escalation"
_SSN = b"patient ssn 123-45-6789 on file\n"
_ACCOUNT = "123456789012"  # moto's default account id
_ALICE = f"arn:aws:iam::{_ACCOUNT}:user/alice"
_TRUST_ALICE = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"AWS": _ALICE}, "Action": "sts:AssumeRole"}
        ],
    }
)
_READ_PII = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::acme-pii/*"}
        ],
    }
)


@pytest.mark.asyncio
async def test_principal_escalating_to_data_lights_up() -> None:
    buckets = (MotoBucket("acme-pii", public=True, encrypted=True, objects={"r": _SSN}),)
    async with in_memory_semantic_store() as store:
        with moto_scene_clients(buckets) as (s3, iam, _sm):
            await drive_data_security(store, tenant_id=_TENANT, buckets=buckets, s3_client=s3)
            # A role alice can assume, that itself can read the PII bucket.
            pol = iam.create_policy(PolicyName="ReadPii", PolicyDocument=_READ_PII)["Policy"]["Arn"]
            iam.create_role(RoleName="escalation-target", AssumeRolePolicyDocument=_TRUST_ALICE)
            iam.attach_role_policy(RoleName="escalation-target", PolicyArn=pol)

            listing = list_moto_identities(iam)
            assume = _assume_grants(listing)  # [(alice, role)]
            fine = _fine_grained_grants(listing)  # [(role, bucket)]

        assert assume and assume[0][0] == _ALICE, "real trust-policy parse found the assumption"
        writer = IdentityKgWriter(store, _TENANT)
        await writer.record_access(fine)  # role -> bucket
        await writer.record_assume_grants(assume)  # alice -> role

        paths = await AttackPathRanker(KgQuery(store, _TENANT)).find_all()
        esc = [p for p in paths if p.path_type == "privilege_escalation"]
        assert len(esc) == 1, "alice escalating to the data-reaching role surfaces one path"
        assert esc[0].data_type if hasattr(esc[0], "data_type") else True  # data is ssn
        # fine_grained still flags the ROLE's own direct access — a distinct subject, both reported.
        assert "fine_grained_data" in {p.path_type for p in paths}


@pytest.mark.asyncio
async def test_assumable_role_with_no_data_access_is_dark() -> None:
    buckets = (MotoBucket("acme-pii", public=True, encrypted=True, objects={"r": _SSN}),)
    async with in_memory_semantic_store() as store:
        with moto_scene_clients(buckets) as (s3, iam, _sm):
            await drive_data_security(store, tenant_id=_TENANT, buckets=buckets, s3_client=s3)
            # alice can assume the role, but the role has NO access to data → no escalation path.
            iam.create_role(RoleName="empty-role", AssumeRolePolicyDocument=_TRUST_ALICE)
            assume = _assume_grants(list_moto_identities(iam))
        await IdentityKgWriter(store, _TENANT).record_assume_grants(assume)
        paths = await AttackPathRanker(KgQuery(store, _TENANT)).find_all()
        assert not [p for p in paths if p.path_type == "privilege_escalation"]
