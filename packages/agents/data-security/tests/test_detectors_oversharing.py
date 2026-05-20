"""Tests — ``data_security.detectors.oversharing``.

Task 8. Covers:

- Wildcard principal ``"*"`` → finding.
- ``{"AWS": "*"}`` → finding.
- Cross-account principal → finding.
- Same-account principal → no finding.
- Same-account but root principal → no finding (still same account).
- Bare account-id principal cross-account → finding.
- Action variants: ``"*"``, ``"s3:*"``, ``"s3:Get*"``, ``"s3:GetObject"``,
  ``"s3:ListBucket"``.
- Non-read action (e.g. ``"s3:PutObject"``) doesn't trigger.
- Effect=Deny doesn't trigger.
- MFA / IP / VPCE / OrgID condition guards suppress the finding.
- Severity MEDIUM (default) → HIGH (with classifier hit).
- Malformed policy JSON → no finding (forgiving).
- Missing policy_json → no finding.
- Single-Statement object (not list) → handled correctly.
- Finding-id shape + wire shape + discriminator.
- Determinism + purity.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest
from data_security.detectors.oversharing import detect_oversharing_iam
from data_security.schemas import (
    OCSF_CLASS_UID,
    ClassifierLabel,
    DataSecurityFindingType,
    Severity,
)
from data_security.tools.s3_inventory import (
    BucketAcl,
    BucketEncryption,
    BucketInventory,
    PublicAccessBlock,
)
from shared.fabric.envelope import NexusEnvelope


def _make_envelope() -> NexusEnvelope:
    return NexusEnvelope(
        correlation_id="00000000-0000-0000-0000-00000000d5d5",
        tenant_id="acme",
        agent_id="data-security",
        nlah_version="d5-v0.1",
        model_pin="deterministic",
        charter_invocation_id="00000000-0000-0000-0000-000000000001",
    )


def _make_bucket(
    *,
    name: str = "corp-data-lake",
    account_id: str = "123456789012",
    policy: dict | None = None,
) -> BucketInventory:
    return BucketInventory(
        name=name,
        region="us-east-1",
        account_id=account_id,
        acl=BucketAcl(),
        public_access_block=PublicAccessBlock(),
        encryption=BucketEncryption(algorithm="AES256"),
        policy_json=json.dumps(policy) if policy else None,
    )


def _policy_with_statement(stmt: dict) -> dict:
    return {"Version": "2012-10-17", "Statement": [stmt]}


_TS = datetime(2026, 5, 20, 12, 0, 0, tzinfo=UTC)


# ---------------------------------------------------------------------------
# Principal — cross-account detection
# ---------------------------------------------------------------------------


def test_wildcard_principal_flags() -> None:
    stmt = {"Sid": "allow-public", "Effect": "Allow", "Principal": "*", "Action": "s3:GetObject"}
    bucket = _make_bucket(policy=_policy_with_statement(stmt))
    out = detect_oversharing_iam(bucket, envelope=_make_envelope(), detected_at=_TS)
    assert len(out) == 1
    assert out[0].severity == Severity.MEDIUM


def test_aws_star_principal_flags() -> None:
    stmt = {
        "Sid": "allow-aws-anyone",
        "Effect": "Allow",
        "Principal": {"AWS": "*"},
        "Action": "s3:ListBucket",
    }
    bucket = _make_bucket(policy=_policy_with_statement(stmt))
    out = detect_oversharing_iam(bucket, envelope=_make_envelope(), detected_at=_TS)
    assert len(out) == 1


def test_cross_account_arn_principal_flags() -> None:
    stmt = {
        "Sid": "allow-other-acct",
        "Effect": "Allow",
        "Principal": {"AWS": "arn:aws:iam::999988887777:root"},
        "Action": "s3:GetObject",
    }
    bucket = _make_bucket(account_id="123456789012", policy=_policy_with_statement(stmt))
    out = detect_oversharing_iam(bucket, envelope=_make_envelope(), detected_at=_TS)
    assert len(out) == 1


def test_same_account_arn_principal_no_finding() -> None:
    stmt = {
        "Sid": "allow-same-acct",
        "Effect": "Allow",
        "Principal": {"AWS": "arn:aws:iam::123456789012:role/data-team"},
        "Action": "s3:GetObject",
    }
    bucket = _make_bucket(account_id="123456789012", policy=_policy_with_statement(stmt))
    assert detect_oversharing_iam(bucket, envelope=_make_envelope(), detected_at=_TS) == []


def test_same_account_root_principal_no_finding() -> None:
    stmt = {
        "Sid": "allow-self-root",
        "Effect": "Allow",
        "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
        "Action": "s3:GetObject",
    }
    bucket = _make_bucket(account_id="123456789012", policy=_policy_with_statement(stmt))
    assert detect_oversharing_iam(bucket, envelope=_make_envelope(), detected_at=_TS) == []


def test_bare_cross_account_id_string_flags() -> None:
    """Some policies use the bare 12-digit account id as principal."""
    stmt = {
        "Sid": "allow-bare-acct",
        "Effect": "Allow",
        "Principal": {"AWS": "999988887777"},
        "Action": "s3:GetObject",
    }
    bucket = _make_bucket(account_id="123456789012", policy=_policy_with_statement(stmt))
    out = detect_oversharing_iam(bucket, envelope=_make_envelope(), detected_at=_TS)
    assert len(out) == 1


def test_service_principal_no_finding() -> None:
    """``Service`` principals (CloudFront, etc.) are not flagged in v0.1."""
    stmt = {
        "Sid": "allow-cf",
        "Effect": "Allow",
        "Principal": {"Service": "cloudfront.amazonaws.com"},
        "Action": "s3:GetObject",
    }
    bucket = _make_bucket(policy=_policy_with_statement(stmt))
    assert detect_oversharing_iam(bucket, envelope=_make_envelope(), detected_at=_TS) == []


# ---------------------------------------------------------------------------
# Action — what counts as oversharing
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "action",
    ["*", "s3:*", "s3:Get*", "s3:GetObject", "s3:ListBucket", "s3:GetObjectAcl"],
)
def test_action_variants_trigger(action: str) -> None:
    stmt = {"Effect": "Allow", "Principal": "*", "Action": action}
    bucket = _make_bucket(policy=_policy_with_statement(stmt))
    assert len(detect_oversharing_iam(bucket, envelope=_make_envelope(), detected_at=_TS)) == 1


def test_non_read_action_no_finding() -> None:
    """Write-only action without read isn't an oversharing read risk."""
    stmt = {"Effect": "Allow", "Principal": "*", "Action": "s3:PutObject"}
    bucket = _make_bucket(policy=_policy_with_statement(stmt))
    assert detect_oversharing_iam(bucket, envelope=_make_envelope(), detected_at=_TS) == []


def test_deny_effect_no_finding() -> None:
    """Effect=Deny statements are not findings."""
    stmt = {"Effect": "Deny", "Principal": "*", "Action": "s3:GetObject"}
    bucket = _make_bucket(policy=_policy_with_statement(stmt))
    assert detect_oversharing_iam(bucket, envelope=_make_envelope(), detected_at=_TS) == []


def test_action_list_with_read_triggers() -> None:
    stmt = {"Effect": "Allow", "Principal": "*", "Action": ["s3:PutObject", "s3:GetObject"]}
    bucket = _make_bucket(policy=_policy_with_statement(stmt))
    assert len(detect_oversharing_iam(bucket, envelope=_make_envelope(), detected_at=_TS)) == 1


# ---------------------------------------------------------------------------
# Condition guards suppress finding
# ---------------------------------------------------------------------------


def test_mfa_condition_suppresses() -> None:
    stmt = {
        "Effect": "Allow",
        "Principal": "*",
        "Action": "s3:GetObject",
        "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}},
    }
    bucket = _make_bucket(policy=_policy_with_statement(stmt))
    assert detect_oversharing_iam(bucket, envelope=_make_envelope(), detected_at=_TS) == []


def test_ip_condition_suppresses() -> None:
    stmt = {
        "Effect": "Allow",
        "Principal": "*",
        "Action": "s3:GetObject",
        "Condition": {"IpAddress": {"aws:SourceIp": "10.0.0.0/8"}},
    }
    bucket = _make_bucket(policy=_policy_with_statement(stmt))
    assert detect_oversharing_iam(bucket, envelope=_make_envelope(), detected_at=_TS) == []


def test_vpce_condition_suppresses() -> None:
    stmt = {
        "Effect": "Allow",
        "Principal": "*",
        "Action": "s3:GetObject",
        "Condition": {"StringEquals": {"aws:SourceVpce": "vpce-1234567890abcdef0"}},
    }
    bucket = _make_bucket(policy=_policy_with_statement(stmt))
    assert detect_oversharing_iam(bucket, envelope=_make_envelope(), detected_at=_TS) == []


def test_org_id_condition_suppresses() -> None:
    stmt = {
        "Effect": "Allow",
        "Principal": "*",
        "Action": "s3:GetObject",
        "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-abc1234567"}},
    }
    bucket = _make_bucket(policy=_policy_with_statement(stmt))
    assert detect_oversharing_iam(bucket, envelope=_make_envelope(), detected_at=_TS) == []


def test_unrelated_condition_does_not_suppress() -> None:
    """A condition that doesn't reference any guard key is not protection."""
    stmt = {
        "Effect": "Allow",
        "Principal": "*",
        "Action": "s3:GetObject",
        "Condition": {"StringEquals": {"s3:prefix": "public/"}},
    }
    bucket = _make_bucket(policy=_policy_with_statement(stmt))
    out = detect_oversharing_iam(bucket, envelope=_make_envelope(), detected_at=_TS)
    assert len(out) == 1


# ---------------------------------------------------------------------------
# Severity uplift with classifier hits
# ---------------------------------------------------------------------------


def test_classifier_hit_uplifts_medium_to_high() -> None:
    stmt = {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject"}
    bucket = _make_bucket(policy=_policy_with_statement(stmt))
    out = detect_oversharing_iam(
        bucket,
        classifier_hits=[ClassifierLabel.SSN],
        envelope=_make_envelope(),
        detected_at=_TS,
    )
    assert len(out) == 1
    assert out[0].severity == Severity.HIGH


def test_classifier_none_only_stays_medium() -> None:
    stmt = {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject"}
    bucket = _make_bucket(policy=_policy_with_statement(stmt))
    out = detect_oversharing_iam(
        bucket,
        classifier_hits=[ClassifierLabel.NONE],
        envelope=_make_envelope(),
        detected_at=_TS,
    )
    assert out[0].severity == Severity.MEDIUM


# ---------------------------------------------------------------------------
# Malformed input → graceful empty list
# ---------------------------------------------------------------------------


def test_missing_policy_no_finding() -> None:
    bucket = _make_bucket(policy=None)
    assert detect_oversharing_iam(bucket, envelope=_make_envelope(), detected_at=_TS) == []


def test_malformed_json_no_finding() -> None:
    bucket = _make_bucket()
    bucket = bucket.model_copy(update={"policy_json": "{not-valid-json"})
    assert detect_oversharing_iam(bucket, envelope=_make_envelope(), detected_at=_TS) == []


def test_policy_top_level_not_dict_no_finding() -> None:
    bucket = _make_bucket()
    bucket = bucket.model_copy(update={"policy_json": "[1, 2, 3]"})
    assert detect_oversharing_iam(bucket, envelope=_make_envelope(), detected_at=_TS) == []


def test_statement_missing_no_finding() -> None:
    bucket = _make_bucket(policy={"Version": "2012-10-17"})
    assert detect_oversharing_iam(bucket, envelope=_make_envelope(), detected_at=_TS) == []


def test_statement_as_dict_handled() -> None:
    """Single-Statement policies sometimes serialize as a dict, not a list."""
    policy = {
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Allow",
            "Principal": "*",
            "Action": "s3:GetObject",
        },
    }
    bucket = _make_bucket(policy=policy)
    out = detect_oversharing_iam(bucket, envelope=_make_envelope(), detected_at=_TS)
    assert len(out) == 1


# ---------------------------------------------------------------------------
# Multiple overshare statements
# ---------------------------------------------------------------------------


def test_multiple_overshare_statements_counted() -> None:
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Sid": "s1", "Effect": "Allow", "Principal": "*", "Action": "s3:GetObject"},
            {
                "Sid": "s2",
                "Effect": "Allow",
                "Principal": {"AWS": "*"},
                "Action": "s3:ListBucket",
            },
            {
                "Sid": "s3-guarded",
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Condition": {"IpAddress": {"aws:SourceIp": "10.0.0.0/8"}},
            },
        ],
    }
    bucket = _make_bucket(policy=policy)
    out = detect_oversharing_iam(bucket, envelope=_make_envelope(), detected_at=_TS)
    assert len(out) == 1  # one finding for the bucket
    evidence = out[0].to_dict()["evidences"][0]
    assert evidence["overshare_statement_count"] == 2
    assert sorted(evidence["overshare_statement_sids"]) == ["s1", "s2"]


# ---------------------------------------------------------------------------
# Wire-shape
# ---------------------------------------------------------------------------


def test_finding_id_format() -> None:
    stmt = {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject"}
    bucket = _make_bucket(name="corp-data-lake", policy=_policy_with_statement(stmt))
    out = detect_oversharing_iam(bucket, envelope=_make_envelope(), detected_at=_TS, sequence=5)
    assert out[0].finding_id == "CSPM-AWS-OVERSHARE-005-corp-data-lake"


def test_ocsf_wire_shape() -> None:
    stmt = {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject"}
    bucket = _make_bucket(policy=_policy_with_statement(stmt))
    out = detect_oversharing_iam(bucket, envelope=_make_envelope(), detected_at=_TS)
    payload = out[0].to_dict()
    assert payload["class_uid"] == OCSF_CLASS_UID == 2003
    assert payload["compliance"]["control"] == "s3_oversharing_iam"


def test_discriminator_in_evidence() -> None:
    stmt = {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject"}
    bucket = _make_bucket(policy=_policy_with_statement(stmt))
    out = detect_oversharing_iam(bucket, envelope=_make_envelope(), detected_at=_TS)
    evidence = out[0].to_dict()["evidences"][0]
    assert (
        evidence["source_finding_type"]
        == DataSecurityFindingType.S3_OVERSHARING_IAM.value
        == "data_security_s3_oversharing_iam"
    )


# ---------------------------------------------------------------------------
# Determinism + purity
# ---------------------------------------------------------------------------


def test_same_input_produces_same_finding_id() -> None:
    stmt = {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject"}
    bucket = _make_bucket(name="alpha", policy=_policy_with_statement(stmt))
    env = _make_envelope()
    a = detect_oversharing_iam(bucket, envelope=env, detected_at=_TS, sequence=1)
    b = detect_oversharing_iam(bucket, envelope=env, detected_at=_TS, sequence=1)
    assert a[0].finding_id == b[0].finding_id


def test_detector_no_module_state() -> None:
    from data_security.detectors import oversharing as os_module

    snapshot_before = {k: id(v) for k, v in vars(os_module).items() if not k.startswith("__")}
    stmt = {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject"}
    bucket = _make_bucket(policy=_policy_with_statement(stmt))
    for _ in range(10):
        detect_oversharing_iam(bucket, envelope=_make_envelope(), detected_at=_TS)
    snapshot_after = {k: id(v) for k, v in vars(os_module).items() if not k.startswith("__")}
    assert snapshot_before == snapshot_after
