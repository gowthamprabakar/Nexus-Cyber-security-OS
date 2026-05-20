"""Tests — ``data_security.detectors.public_bucket``.

Task 5. Covers:

- ACL-grant detection (AllUsers / AuthenticatedUsers, READ/WRITE/etc).
- Block Public Access gap detection (any of the 4 flags False).
- Severity HIGH for public-only / no-PII.
- Severity CRITICAL uplift when classifier hits present.
- ``NONE`` classifier-label entries don't trigger uplift.
- Private bucket (no ACL grants, all BPA True) → no finding.
- Finding-id shape (CSPM-AWS-PUBLIC-NNN-<slug>).
- OCSF wire shape (class_uid 2003, finding_info / compliance /
  resources / evidence fields).
- Determinism: same input → same finding_id (sequence stable).
- Pure function: no module-state mutation across calls.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from data_security.detectors.public_bucket import detect_public_bucket
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
    acl_all_users: list[str] | None = None,
    acl_auth_users: list[str] | None = None,
    bpa_all_true: bool = True,
    tags: dict[str, str] | None = None,
) -> BucketInventory:
    return BucketInventory(
        name=name,
        region="us-east-1",
        account_id="123456789012",
        acl=BucketAcl(
            grants_all_users=acl_all_users or [],
            grants_authenticated_users=acl_auth_users or [],
        ),
        public_access_block=PublicAccessBlock(
            block_public_acls=bpa_all_true,
            ignore_public_acls=bpa_all_true,
            block_public_policy=bpa_all_true,
            restrict_public_buckets=bpa_all_true,
        ),
        encryption=BucketEncryption(algorithm="AES256"),
        tags=tags or {},
    )


_TS = datetime(2026, 5, 20, 12, 0, 0, tzinfo=UTC)


# ---------------------------------------------------------------------------
# Negative cases — no finding emitted
# ---------------------------------------------------------------------------


def test_fully_private_bucket_emits_nothing() -> None:
    bucket = _make_bucket()  # defaults: no public grants, all BPA True
    out = detect_public_bucket(bucket, envelope=_make_envelope(), detected_at=_TS)
    assert out == []


def test_acl_grant_to_specific_owner_not_public() -> None:
    """ACL grants to specific principals are NOT public (only AllUsers /
    AuthenticatedUsers count). The model only carries those two groups
    explicitly, so this is implicit: empty grant lists → no finding.
    """
    bucket = _make_bucket(acl_all_users=[], acl_auth_users=[])
    assert detect_public_bucket(bucket, envelope=_make_envelope(), detected_at=_TS) == []


def test_bpa_partial_gap_alone_flags_high() -> None:
    """A BPA gap alone (no ACL public grant) is still a finding because
    a future policy / ACL could expose the bucket.
    """
    bucket = _make_bucket(bpa_all_true=False)
    out = detect_public_bucket(bucket, envelope=_make_envelope(), detected_at=_TS)
    assert len(out) == 1
    assert out[0].severity == Severity.HIGH


# ---------------------------------------------------------------------------
# Positive cases — ACL grants
# ---------------------------------------------------------------------------


def test_all_users_read_grant_flags_high() -> None:
    bucket = _make_bucket(acl_all_users=["READ"])
    out = detect_public_bucket(bucket, envelope=_make_envelope(), detected_at=_TS)
    assert len(out) == 1
    assert out[0].severity == Severity.HIGH


def test_authenticated_users_write_grant_flags_high() -> None:
    bucket = _make_bucket(acl_auth_users=["WRITE"])
    out = detect_public_bucket(bucket, envelope=_make_envelope(), detected_at=_TS)
    assert len(out) == 1
    assert out[0].severity == Severity.HIGH


def test_full_control_grant_flags_high() -> None:
    bucket = _make_bucket(acl_all_users=["FULL_CONTROL"])
    out = detect_public_bucket(bucket, envelope=_make_envelope(), detected_at=_TS)
    assert len(out) == 1


def test_acl_grant_unknown_permission_ignored() -> None:
    """A permission outside the public-permission set is not a public grant."""
    bucket = _make_bucket(acl_all_users=["VOID_PERMISSION"])
    assert detect_public_bucket(bucket, envelope=_make_envelope(), detected_at=_TS) == []


# ---------------------------------------------------------------------------
# Critical uplift — classifier hits
# ---------------------------------------------------------------------------


def test_public_with_classifier_hit_uplifts_to_critical() -> None:
    bucket = _make_bucket(acl_all_users=["READ"])
    out = detect_public_bucket(
        bucket,
        classifier_hits=[ClassifierLabel.SSN],
        envelope=_make_envelope(),
        detected_at=_TS,
    )
    assert len(out) == 1
    assert out[0].severity == Severity.CRITICAL


def test_public_with_only_none_label_stays_high() -> None:
    """``ClassifierLabel.NONE`` entries don't trigger the CRITICAL uplift —
    NONE means "classifier scanned but found nothing sensitive."
    """
    bucket = _make_bucket(acl_all_users=["READ"])
    out = detect_public_bucket(
        bucket,
        classifier_hits=[ClassifierLabel.NONE, ClassifierLabel.NONE],
        envelope=_make_envelope(),
        detected_at=_TS,
    )
    assert len(out) == 1
    assert out[0].severity == Severity.HIGH


def test_private_with_classifier_hit_still_no_finding() -> None:
    """The public_bucket detector requires the public-exposure signal;
    classifier hits alone don't trigger this rule (that's
    s3_object_sensitive_in_untrusted_location, Task 7).
    """
    bucket = _make_bucket()
    out = detect_public_bucket(
        bucket,
        classifier_hits=[ClassifierLabel.SSN, ClassifierLabel.CREDIT_CARD],
        envelope=_make_envelope(),
        detected_at=_TS,
    )
    assert out == []


def test_multiple_classifier_hits_listed_in_evidence() -> None:
    bucket = _make_bucket(acl_all_users=["READ"])
    out = detect_public_bucket(
        bucket,
        classifier_hits=[
            ClassifierLabel.SSN,
            ClassifierLabel.CREDIT_CARD,
            ClassifierLabel.NONE,
        ],
        envelope=_make_envelope(),
        detected_at=_TS,
    )
    assert len(out) == 1
    evidence = out[0].to_dict()["evidences"][0]
    labels = evidence["classifier_labels_found"]
    # Sorted, de-duplicated, NONE excluded.
    assert labels == ["credit_card", "ssn"]


# ---------------------------------------------------------------------------
# Finding shape — OCSF wire conformance
# ---------------------------------------------------------------------------


def test_finding_id_format() -> None:
    bucket = _make_bucket(name="corp-data-lake", acl_all_users=["READ"])
    out = detect_public_bucket(bucket, envelope=_make_envelope(), detected_at=_TS, sequence=7)
    assert out[0].finding_id == "CSPM-AWS-PUBLIC-007-corp-data-lake"


def test_finding_id_handles_special_chars_in_bucket_name() -> None:
    """Bucket names are 3-63 chars alphanumeric / hyphen / dot per AWS spec.
    The slugifier lowercases + strips non-alphanumerics into hyphens.
    """
    bucket = _make_bucket(name="prod.corp-data_lake", acl_all_users=["READ"])
    out = detect_public_bucket(bucket, envelope=_make_envelope(), detected_at=_TS)
    # Underscores aren't actually allowed in S3 names per AWS but pydantic
    # currently doesn't reject them; the slugifier handles them anyway.
    assert out[0].finding_id.startswith("CSPM-AWS-PUBLIC-000-prod-corp-data-lake")


def test_ocsf_wire_shape() -> None:
    bucket = _make_bucket(acl_all_users=["READ"])
    out = detect_public_bucket(bucket, envelope=_make_envelope(), detected_at=_TS)
    payload = out[0].to_dict()
    assert payload["class_uid"] == OCSF_CLASS_UID == 2003
    assert payload["class_name"] == "Compliance Finding"
    assert payload["compliance"]["control"] == "s3_bucket_public"
    assert payload["resources"][0]["type"] == "s3-bucket"
    assert payload["resources"][0]["uid"] == "arn:aws:s3:::corp-data-lake"
    assert payload["nexus_envelope"]["tenant_id"] == "acme"


def test_discriminator_in_evidence() -> None:
    """Per multi-cloud-posture precedent, the discriminator goes into
    ``evidence.source_finding_type``.
    """
    bucket = _make_bucket(acl_all_users=["READ"])
    out = detect_public_bucket(bucket, envelope=_make_envelope(), detected_at=_TS)
    evidence = out[0].to_dict()["evidences"][0]
    assert (
        evidence["source_finding_type"]
        == DataSecurityFindingType.S3_BUCKET_PUBLIC.value
        == "data_security_s3_bucket_public"
    )


def test_bpa_flags_recorded_in_evidence() -> None:
    bucket = _make_bucket(acl_all_users=["READ"], bpa_all_true=False)
    out = detect_public_bucket(bucket, envelope=_make_envelope(), detected_at=_TS)
    evidence = out[0].to_dict()["evidences"][0]
    bpa = evidence["block_public_access"]
    assert bpa["block_public_acls"] is False
    assert bpa["restrict_public_buckets"] is False


def test_acl_grants_recorded_in_evidence() -> None:
    bucket = _make_bucket(acl_all_users=["READ"], acl_auth_users=["WRITE"])
    out = detect_public_bucket(bucket, envelope=_make_envelope(), detected_at=_TS)
    evidence = out[0].to_dict()["evidences"][0]
    assert evidence["acl_grants_all_users"] == ["READ"]
    assert evidence["acl_grants_authenticated_users"] == ["WRITE"]


# ---------------------------------------------------------------------------
# Determinism + purity
# ---------------------------------------------------------------------------


def test_same_input_produces_same_finding_id() -> None:
    """Pure function: deterministic finding_id for the same (bucket, seq)."""
    bucket = _make_bucket(name="alpha", acl_all_users=["READ"])
    env = _make_envelope()
    a = detect_public_bucket(bucket, envelope=env, detected_at=_TS, sequence=3)
    b = detect_public_bucket(bucket, envelope=env, detected_at=_TS, sequence=3)
    assert a[0].finding_id == b[0].finding_id


def test_sequence_drives_id_uniqueness() -> None:
    bucket = _make_bucket(name="alpha", acl_all_users=["READ"])
    env = _make_envelope()
    a = detect_public_bucket(bucket, envelope=env, detected_at=_TS, sequence=1)
    b = detect_public_bucket(bucket, envelope=env, detected_at=_TS, sequence=2)
    assert a[0].finding_id != b[0].finding_id


def test_detector_no_module_state() -> None:
    """Calling the detector multiple times must not mutate module state."""
    from data_security.detectors import public_bucket as pb_module

    snapshot_before = {k: id(v) for k, v in vars(pb_module).items() if not k.startswith("__")}
    bucket = _make_bucket(acl_all_users=["READ"])
    for _ in range(10):
        detect_public_bucket(bucket, envelope=_make_envelope(), detected_at=_TS)
    snapshot_after = {k: id(v) for k, v in vars(pb_module).items() if not k.startswith("__")}
    assert snapshot_before == snapshot_after


@pytest.mark.parametrize(
    "permissions",
    [["READ"], ["WRITE"], ["READ_ACP"], ["WRITE_ACP"], ["FULL_CONTROL"]],
)
def test_each_public_permission_triggers_finding(permissions: list[str]) -> None:
    bucket = _make_bucket(acl_all_users=permissions)
    out = detect_public_bucket(bucket, envelope=_make_envelope(), detected_at=_TS)
    assert len(out) == 1
