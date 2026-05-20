"""Tests — ``data_security.detectors.unencrypted``.

Task 6. Covers:

- ``NONE`` encryption → finding emitted.
- ``AES256`` / ``aws:kms`` / ``aws:kms:dsse`` → no finding.
- Severity MEDIUM (default) → HIGH (with classifier hit).
- ``ClassifierLabel.NONE`` entries don't uplift.
- Finding-id shape (CSPM-AWS-UNENC-NNN-<slug>).
- OCSF wire shape + discriminator location.
- Determinism + purity.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from data_security.detectors.unencrypted import detect_unencrypted
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
    algorithm: str = "AES256",
    kms_key: str | None = None,
) -> BucketInventory:
    return BucketInventory(
        name=name,
        region="us-east-1",
        account_id="123456789012",
        acl=BucketAcl(),
        public_access_block=PublicAccessBlock(),
        encryption=BucketEncryption(algorithm=algorithm, kms_master_key_id=kms_key),
    )


_TS = datetime(2026, 5, 20, 12, 0, 0, tzinfo=UTC)


# ---------------------------------------------------------------------------
# Encryption present → no finding
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("algorithm", ["AES256", "aws:kms", "aws:kms:dsse"])
def test_encryption_present_emits_no_finding(algorithm: str) -> None:
    bucket = _make_bucket(algorithm=algorithm)
    assert detect_unencrypted(bucket, envelope=_make_envelope(), detected_at=_TS) == []


def test_kms_with_key_id_no_finding() -> None:
    bucket = _make_bucket(algorithm="aws:kms", kms_key="alias/data-key")
    assert detect_unencrypted(bucket, envelope=_make_envelope(), detected_at=_TS) == []


# ---------------------------------------------------------------------------
# NONE encryption → finding
# ---------------------------------------------------------------------------


def test_none_encryption_emits_medium() -> None:
    bucket = _make_bucket(algorithm="NONE")
    out = detect_unencrypted(bucket, envelope=_make_envelope(), detected_at=_TS)
    assert len(out) == 1
    assert out[0].severity == Severity.MEDIUM


def test_none_encryption_with_classifier_hit_uplifts_to_high() -> None:
    bucket = _make_bucket(algorithm="NONE")
    out = detect_unencrypted(
        bucket,
        classifier_hits=[ClassifierLabel.SSN],
        envelope=_make_envelope(),
        detected_at=_TS,
    )
    assert len(out) == 1
    assert out[0].severity == Severity.HIGH


def test_none_encryption_with_only_none_label_stays_medium() -> None:
    bucket = _make_bucket(algorithm="NONE")
    out = detect_unencrypted(
        bucket,
        classifier_hits=[ClassifierLabel.NONE, ClassifierLabel.NONE],
        envelope=_make_envelope(),
        detected_at=_TS,
    )
    assert len(out) == 1
    assert out[0].severity == Severity.MEDIUM


def test_multiple_labels_sorted_and_deduplicated() -> None:
    bucket = _make_bucket(algorithm="NONE")
    out = detect_unencrypted(
        bucket,
        classifier_hits=[
            ClassifierLabel.SSN,
            ClassifierLabel.NONE,
            ClassifierLabel.CREDIT_CARD,
            ClassifierLabel.SSN,
        ],
        envelope=_make_envelope(),
        detected_at=_TS,
    )
    assert len(out) == 1
    evidence = out[0].to_dict()["evidences"][0]
    assert evidence["classifier_labels_found"] == ["credit_card", "ssn"]


# ---------------------------------------------------------------------------
# Wire-shape
# ---------------------------------------------------------------------------


def test_finding_id_format() -> None:
    bucket = _make_bucket(name="corp-data-lake", algorithm="NONE")
    out = detect_unencrypted(bucket, envelope=_make_envelope(), detected_at=_TS, sequence=3)
    assert out[0].finding_id == "CSPM-AWS-UNENC-003-corp-data-lake"


def test_ocsf_wire_shape() -> None:
    bucket = _make_bucket(algorithm="NONE")
    out = detect_unencrypted(bucket, envelope=_make_envelope(), detected_at=_TS)
    payload = out[0].to_dict()
    assert payload["class_uid"] == OCSF_CLASS_UID == 2003
    assert payload["compliance"]["control"] == "s3_bucket_unencrypted"
    assert payload["resources"][0]["uid"] == "arn:aws:s3:::corp-data-lake"


def test_discriminator_in_evidence() -> None:
    bucket = _make_bucket(algorithm="NONE")
    out = detect_unencrypted(bucket, envelope=_make_envelope(), detected_at=_TS)
    evidence = out[0].to_dict()["evidences"][0]
    assert (
        evidence["source_finding_type"]
        == DataSecurityFindingType.S3_BUCKET_UNENCRYPTED.value
        == "data_security_s3_bucket_unencrypted"
    )


def test_evidence_records_algorithm_value() -> None:
    """Even though only NONE triggers, the algorithm value is recorded
    for downstream introspection.
    """
    bucket = _make_bucket(algorithm="NONE")
    out = detect_unencrypted(bucket, envelope=_make_envelope(), detected_at=_TS)
    evidence = out[0].to_dict()["evidences"][0]
    assert evidence["encryption_algorithm"] == "NONE"


# ---------------------------------------------------------------------------
# Determinism + purity
# ---------------------------------------------------------------------------


def test_same_input_produces_same_finding_id() -> None:
    bucket = _make_bucket(name="alpha", algorithm="NONE")
    env = _make_envelope()
    a = detect_unencrypted(bucket, envelope=env, detected_at=_TS, sequence=3)
    b = detect_unencrypted(bucket, envelope=env, detected_at=_TS, sequence=3)
    assert a[0].finding_id == b[0].finding_id


def test_sequence_drives_id_uniqueness() -> None:
    bucket = _make_bucket(algorithm="NONE")
    env = _make_envelope()
    a = detect_unencrypted(bucket, envelope=env, detected_at=_TS, sequence=1)
    b = detect_unencrypted(bucket, envelope=env, detected_at=_TS, sequence=2)
    assert a[0].finding_id != b[0].finding_id


def test_detector_no_module_state() -> None:
    from data_security.detectors import unencrypted as un_module

    snapshot_before = {k: id(v) for k, v in vars(un_module).items() if not k.startswith("__")}
    bucket = _make_bucket(algorithm="NONE")
    for _ in range(10):
        detect_unencrypted(bucket, envelope=_make_envelope(), detected_at=_TS)
    snapshot_after = {k: id(v) for k, v in vars(un_module).items() if not k.startswith("__")}
    assert snapshot_before == snapshot_after
