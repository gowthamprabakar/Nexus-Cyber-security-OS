"""Path #17 — secret-in-code is a live cloud credential reaching data, REAL e2e.

The cross-domain join (appsec + identity) over the AWS access key ID — the non-secret identifier:
- appsec's REAL gitleaks parser (``extract_leaked_key_ids``) pulls ONLY the ``AKIA…`` from a gitleaks
  match (never the secret half) and writes SECRET(key-id) --DEFINED_IN--> repo.
- identity's REAL reader lists the IAM user's access keys; ``record_credential_ownership`` writes
  the user --OWNS--> the SAME SECRET(key-id) node, and ``record_access`` its data access.
- the leaked credential and its owning identity converge on the key id; the detector joins them.

moto generates the access key; the gitleaks match carries that exact key id, so the join is real.
"""

import json

import pytest
from appsec.kg_writer import KnowledgeGraphWriter as AppSecKgWriter
from appsec.normalizers.gitleaks_secrets import extract_leaked_key_ids
from appsec.tools.gitleaks_runner import GitleaksResult
from identity.agent import _credential_grants, _fine_grained_grants
from identity.kg_writer import KnowledgeGraphWriter as IdentityKgWriter
from meta_harness.attack_paths import AttackPathRanker
from meta_harness.kg_query import KgQuery

from fleet_testkit import MotoBucket, drive_data_security, in_memory_semantic_store
from fleet_testkit.moto_aws import moto_scene_clients
from fleet_testkit.moto_identity import list_moto_identities

_TENANT = "tenant-leak"
_SSN = b"patient ssn 123-45-6789 on file\n"
_REPO = "github/acme/app"
_READ_PII = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::acme-pii/*"}
        ],
    }
)


def _seed_user_with_key(iam) -> str:
    """An IAM user with a data-reading policy + an access key; returns the access key id."""
    iam.create_user(UserName="deployer")
    pol = iam.create_policy(PolicyName="ReadPii", PolicyDocument=_READ_PII)["Policy"]["Arn"]
    iam.attach_user_policy(UserName="deployer", PolicyArn=pol)
    return str(iam.create_access_key(UserName="deployer")["AccessKey"]["AccessKeyId"])


async def _drive_appsec_leak(store, *, repo_slug: str, key_id: str, file: str) -> None:
    """Run appsec's REAL gitleaks parse (key-id only) + writer for a leaked credential."""
    result = GitleaksResult(payload=[{"File": file, "Secret": key_id, "RuleID": "aws-access-key"}])
    key_ids = [kid for _f, kid in extract_leaked_key_ids(result)]
    await AppSecKgWriter(store, repo_slug and _TENANT).record_leaked_credentials(repo_slug, key_ids)


@pytest.mark.asyncio
async def test_leaked_credential_reaching_data_lights_up() -> None:
    buckets = (MotoBucket("acme-pii", public=True, encrypted=True, objects={"r": _SSN}),)
    async with in_memory_semantic_store() as store:
        with moto_scene_clients(buckets) as (s3, iam, _sm):
            await drive_data_security(store, tenant_id=_TENANT, buckets=buckets, s3_client=s3)
            akia = _seed_user_with_key(iam)
            assert akia.startswith("AKIA"), "moto access key is an AKIA id"
            listing = list_moto_identities(iam)
            creds = _credential_grants(listing)  # (user, akia)
            fine = _fine_grained_grants(listing)  # (user, bucket)

        # appsec: the SAME key id leaked in the repo (key-id only, no secret material).
        await _drive_appsec_leak(store, repo_slug=_REPO, key_id=akia, file="config/prod.env")
        # identity: the user owns that key + can read the data.
        writer = IdentityKgWriter(store, _TENANT)
        await writer.record_credential_ownership(creds)
        await writer.record_access(fine)

        assert creds and creds[0][1] == akia, "real reader captured the user's access key"
        paths = await AttackPathRanker(KgQuery(store, _TENANT)).find_all()
        leak = [p for p in paths if p.path_type == "leaked_credential"]
        assert len(leak) == 1, "a leaked live credential that reaches data surfaces one path"
        assert leak[0].severity == 92


@pytest.mark.asyncio
async def test_owned_key_not_in_code_is_dark() -> None:
    buckets = (MotoBucket("acme-pii", public=True, encrypted=True, objects={"r": _SSN}),)
    async with in_memory_semantic_store() as store:
        with moto_scene_clients(buckets) as (s3, iam, _sm):
            await drive_data_security(store, tenant_id=_TENANT, buckets=buckets, s3_client=s3)
            _seed_user_with_key(iam)
            listing = list_moto_identities(iam)
            creds = _credential_grants(listing)
            fine = _fine_grained_grants(listing)
        # The key is owned + reaches data, but it was NEVER leaked in code → no DEFINED_IN → dark.
        writer = IdentityKgWriter(store, _TENANT)
        await writer.record_credential_ownership(creds)
        await writer.record_access(fine)
        paths = await AttackPathRanker(KgQuery(store, _TENANT)).find_all()
        assert not [p for p in paths if p.path_type == "leaked_credential"]
