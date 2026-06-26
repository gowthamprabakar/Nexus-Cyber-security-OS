"""Known detection gaps — characterization tests that document where the detectors MISS.

The capability banks measure precision/recall on cases the detectors handle. This file does the
opposite: it pins the *boundaries* — realistic inputs we currently miss — so a gap is visible and
tracked, not hidden behind a green bank. Each assertion documents a real limitation; if a gap is
ever closed (a detector starts catching the input), the matching assertion fails on purpose,
prompting an update to docs/strategy/detection-gaps.md.

These are honest counter-evidence to the banks' 1.000 scores: the scores are 1.000 *on the bank*,
with the documented out-of-bank gaps below.
"""

import base64
import gzip
import json
from datetime import UTC, datetime

import boto3
import pytest
from data_security.classifiers import classify
from data_security.schemas import ClassifierLabel
from identity.agent import _externally_trusted_arns, _fine_grained_grants
from identity.tools.aws_iam import (
    IamRole,
    IdentityListing,
    _list_groups,
    _list_policies,
    _list_roles,
    _list_users,
)
from meta_harness.kg_query import KgQuery
from moto import mock_aws

from fleet_testkit import MotoBucket, drive_data_security, in_memory_semantic_store
from fleet_testkit.moto_aws import moto_s3

_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"  # noqa: S105  AWS docs example secret

_KEY = b"aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n"
_SSN = b"patient ssn 123-45-6789\n"
_TENANT = "limits"


async def _secret_hits(body: bytes) -> int:
    async with in_memory_semantic_store() as store:
        buckets = (MotoBucket("acme-blob", public=True, objects={"o": body}),)
        with moto_s3(buckets) as s3:
            await drive_data_security(store, tenant_id=_TENANT, buckets=buckets, s3_client=s3)
        return len(await KgQuery(store, _TENANT).find_public_secret_exposure())


async def _unencrypted_hits(body: bytes) -> int:
    async with in_memory_semantic_store() as store:
        buckets = (MotoBucket("acme-blob", public=True, objects={"o": body}),)
        with moto_s3(buckets) as s3:
            await drive_data_security(store, tenant_id=_TENANT, buckets=buckets, s3_client=s3)
        return len(await KgQuery(store, _TENANT).find_public_unencrypted_exposure())


@pytest.mark.asyncio
async def test_boundary_decoded_text_is_detected() -> None:
    # The classifier matches patterns in decoded UTF-8 text — including inside structured text.
    assert await _secret_hits(_KEY) == 1
    assert await _secret_hits(b'{"aws_key": "AKIAIOSFODNN7EXAMPLE"}') == 1


@pytest.mark.asyncio
async def test_gap_gzipped_secret_is_missed() -> None:
    # GAP: archives are not decompressed before classification. Wiz/Macie scan inside .gz/.zip.
    assert await _secret_hits(gzip.compress(_KEY)) == 0, (
        "gzipped-secret gap closed — update docs/strategy/detection-gaps.md"
    )


@pytest.mark.asyncio
async def test_gap_base64_secret_is_missed() -> None:
    # GAP: encoded blobs are not decoded before classification.
    assert await _secret_hits(base64.b64encode(_KEY)) == 0, (
        "base64-secret gap closed — update docs/strategy/detection-gaps.md"
    )


@pytest.mark.asyncio
async def test_gap_gzipped_pii_is_missed() -> None:
    # GAP: same archive blind spot applies to PII (path 7 and every EXPOSES_DATA consumer).
    assert await _unencrypted_hits(gzip.compress(_SSN)) == 0, (
        "gzipped-PII gap closed — update docs/strategy/detection-gaps.md"
    )


def test_gap_aws_secret_access_key_is_missed() -> None:
    # GAP: the AKIA access-key *ID* is detected, but the AWS secret access key (the actual
    # credential) has no dedicated pattern; the generic-token rule needs the keyword to
    # IMMEDIATELY precede the value, so standard labels miss. Wiz/secret scanners use entropy.
    assert classify(f"aws_secret_access_key = {_SECRET_KEY}") is ClassifierLabel.NONE, (
        "aws_secret_access_key gap closed — update the gaps doc"
    )
    assert classify(f"SecretAccessKey: {_SECRET_KEY}") is ClassifierLabel.NONE
    # Boundary: with the keyword directly adjacent, the generic-token rule does fire.
    assert classify(f"secret = {_SECRET_KEY}") is ClassifierLabel.GENERIC_API_TOKEN


def _listing_from_moto(iam: object) -> IdentityListing:
    deg: list[dict[str, str]] = []
    return IdentityListing(
        users=tuple(_list_users(iam, deg)),
        roles=tuple(_list_roles(iam, deg)),
        groups=tuple(_list_groups(iam, deg)),
        policies=tuple(_list_policies(iam, deg)),
    )


def test_gap_group_inherited_access_is_missed() -> None:
    # GAP: _fine_grained_grants resolves a principal's attached + inline policies, but NOT
    # policies inherited via group membership. A user whose only S3 access is via a group is
    # invisible to path 4 (and path 8). Documented deferral; here it is measured.
    doc = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::acme-pii/*"}
            ],
        }
    )
    with mock_aws():
        iam = boto3.client("iam", region_name="us-east-1")
        policy_arn = iam.create_policy(PolicyName="read", PolicyDocument=doc)["Policy"]["Arn"]
        iam.create_group(GroupName="readers")
        iam.attach_group_policy(GroupName="readers", PolicyArn=policy_arn)
        iam.create_user(UserName="alice")
        iam.add_user_to_group(GroupName="readers", UserName="alice")
        listing = _listing_from_moto(iam)
    assert listing.users[0].group_memberships == ("readers",), "group membership is read"
    assert _fine_grained_grants(listing) == [], (
        "group-inherited access now resolved — update the gaps doc"
    )


def _federated_role(name: str, provider_arn: str) -> IamRole:
    return IamRole(
        arn=f"arn:aws:iam::123456789012:role/{name}",
        name=name,
        role_id=f"AROA{name}",
        create_date=datetime(2026, 6, 26, tzinfo=UTC),
        last_used_at=None,
        assume_role_policy_document={
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Federated": provider_arn},
                    "Action": "sts:AssumeRoleWithWebIdentity",
                }
            ],
        },
    )


def test_gap_federated_external_trust_is_missed() -> None:
    # GAP: _externally_trusted_arns inspects Principal.AWS (cross-account) only. A role assumable
    # via an external OIDC/SAML provider (e.g. GitHub Actions OIDC, an external IdP) is a real
    # external-access vector but is not flagged. Path 8 covers cross-ACCOUNT trust, not federation.
    oidc = _federated_role(
        "gha", "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
    )
    saml = _federated_role("sso", "arn:aws:iam::123456789012:saml-provider/Okta")
    listing = IdentityListing(users=(), roles=(oidc, saml), groups=())
    assert _externally_trusted_arns(listing) == [], (
        "federated external trust now detected — update the gaps doc"
    )
