"""Tests — ``data_security.detectors.sensitive_location``.

Task 7. Covers:

- Classifier hit + untrusted tag → finding (HIGH).
- Classifier hit + ``Sensitivity=Restricted`` → no finding.
- Classifier hit + missing tag → finding.
- No classifier hits → no finding (regardless of tag).
- ``ClassifierLabel.NONE`` entries don't trigger.
- Operator-override trusted_tag_value.
- Finding-id shape (CSPM-AWS-SENSLOC-NNN-<slug>).
- OCSF wire shape + discriminator location.
- Evidence carries labels + tags + actual/expected tag values.
- Determinism + purity.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from data_security.detectors.sensitive_location import (
    SENSITIVITY_TAG_KEY,
    TRUSTED_TAG_VALUE,
    detect_sensitive_location,
)
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
    tags: dict[str, str] | None = None,
) -> BucketInventory:
    return BucketInventory(
        name=name,
        region="us-east-1",
        account_id="123456789012",
        acl=BucketAcl(),
        public_access_block=PublicAccessBlock(),
        encryption=BucketEncryption(algorithm="AES256"),
        tags=tags or {},
    )


_TS = datetime(2026, 5, 20, 12, 0, 0, tzinfo=UTC)


# ---------------------------------------------------------------------------
# Trigger requires BOTH classifier hit AND untrusted location
# ---------------------------------------------------------------------------


def test_classifier_hit_in_untagged_bucket_flags_high() -> None:
    bucket = _make_bucket()
    out = detect_sensitive_location(
        bucket,
        classifier_hits=[ClassifierLabel.SSN],
        envelope=_make_envelope(),
        detected_at=_TS,
    )
    assert len(out) == 1
    assert out[0].severity == Severity.HIGH


def test_classifier_hit_in_restricted_bucket_no_finding() -> None:
    """Trusted location → no finding even with sensitive content."""
    bucket = _make_bucket(tags={"Sensitivity": "Restricted"})
    out = detect_sensitive_location(
        bucket,
        classifier_hits=[ClassifierLabel.SSN],
        envelope=_make_envelope(),
        detected_at=_TS,
    )
    assert out == []


def test_classifier_hit_in_internal_tagged_bucket_flags() -> None:
    """``Sensitivity != "Restricted"`` is still untrusted."""
    bucket = _make_bucket(tags={"Sensitivity": "Internal"})
    out = detect_sensitive_location(
        bucket,
        classifier_hits=[ClassifierLabel.SSN],
        envelope=_make_envelope(),
        detected_at=_TS,
    )
    assert len(out) == 1


def test_no_classifier_hits_no_finding_even_in_untrusted() -> None:
    """Tag-only signal is not enough — this rule requires the classifier."""
    bucket = _make_bucket(tags={"Sensitivity": "Public"})
    out = detect_sensitive_location(
        bucket,
        classifier_hits=[],
        envelope=_make_envelope(),
        detected_at=_TS,
    )
    assert out == []


def test_only_none_label_no_finding() -> None:
    bucket = _make_bucket()
    out = detect_sensitive_location(
        bucket,
        classifier_hits=[ClassifierLabel.NONE, ClassifierLabel.NONE],
        envelope=_make_envelope(),
        detected_at=_TS,
    )
    assert out == []


def test_multiple_labels_sorted_in_evidence() -> None:
    bucket = _make_bucket()
    out = detect_sensitive_location(
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
# Operator override of trusted_tag_value
# ---------------------------------------------------------------------------


def test_operator_override_trusted_value() -> None:
    """Operator can declare a different tag value as trusted."""
    bucket = _make_bucket(tags={"Sensitivity": "Confidential"})
    # Default trusted value (Restricted) → finding
    out_default = detect_sensitive_location(
        bucket,
        classifier_hits=[ClassifierLabel.SSN],
        envelope=_make_envelope(),
        detected_at=_TS,
    )
    assert len(out_default) == 1
    # Operator-overridden trusted = Confidential → no finding
    out_override = detect_sensitive_location(
        bucket,
        classifier_hits=[ClassifierLabel.SSN],
        envelope=_make_envelope(),
        detected_at=_TS,
        trusted_tag_value="Confidential",
    )
    assert out_override == []


# ---------------------------------------------------------------------------
# Wire-shape
# ---------------------------------------------------------------------------


def test_finding_id_format() -> None:
    bucket = _make_bucket(name="corp-data-lake")
    out = detect_sensitive_location(
        bucket,
        classifier_hits=[ClassifierLabel.SSN],
        envelope=_make_envelope(),
        detected_at=_TS,
        sequence=4,
    )
    assert out[0].finding_id == "CSPM-AWS-SENSLOC-004-corp-data-lake"


def test_ocsf_wire_shape() -> None:
    bucket = _make_bucket()
    out = detect_sensitive_location(
        bucket,
        classifier_hits=[ClassifierLabel.SSN],
        envelope=_make_envelope(),
        detected_at=_TS,
    )
    payload = out[0].to_dict()
    assert payload["class_uid"] == OCSF_CLASS_UID == 2003
    assert payload["compliance"]["control"] == "s3_object_sensitive_in_untrusted_location"


def test_discriminator_in_evidence() -> None:
    bucket = _make_bucket()
    out = detect_sensitive_location(
        bucket,
        classifier_hits=[ClassifierLabel.SSN],
        envelope=_make_envelope(),
        detected_at=_TS,
    )
    evidence = out[0].to_dict()["evidences"][0]
    assert (
        evidence["source_finding_type"]
        == DataSecurityFindingType.S3_OBJECT_SENSITIVE_IN_UNTRUSTED_LOCATION.value
        == "data_security_s3_object_sensitive_in_untrusted_location"
    )


def test_evidence_records_tag_values() -> None:
    bucket = _make_bucket(tags={"Sensitivity": "Internal", "Owner": "team-data"})
    out = detect_sensitive_location(
        bucket,
        classifier_hits=[ClassifierLabel.SSN],
        envelope=_make_envelope(),
        detected_at=_TS,
    )
    evidence = out[0].to_dict()["evidences"][0]
    assert evidence["sensitivity_tag_key"] == SENSITIVITY_TAG_KEY == "Sensitivity"
    assert evidence["trusted_tag_value"] == TRUSTED_TAG_VALUE == "Restricted"
    assert evidence["actual_tag_value"] == "Internal"
    assert evidence["all_tags"] == {"Sensitivity": "Internal", "Owner": "team-data"}


def test_evidence_records_missing_tag_as_none() -> None:
    bucket = _make_bucket()  # no tags
    out = detect_sensitive_location(
        bucket,
        classifier_hits=[ClassifierLabel.SSN],
        envelope=_make_envelope(),
        detected_at=_TS,
    )
    evidence = out[0].to_dict()["evidences"][0]
    assert evidence["actual_tag_value"] is None
    assert evidence["all_tags"] == {}


# ---------------------------------------------------------------------------
# Determinism + purity
# ---------------------------------------------------------------------------


def test_same_input_produces_same_finding_id() -> None:
    bucket = _make_bucket(name="alpha")
    env = _make_envelope()
    a = detect_sensitive_location(
        bucket, classifier_hits=[ClassifierLabel.SSN], envelope=env, detected_at=_TS, sequence=2
    )
    b = detect_sensitive_location(
        bucket, classifier_hits=[ClassifierLabel.SSN], envelope=env, detected_at=_TS, sequence=2
    )
    assert a[0].finding_id == b[0].finding_id


def test_detector_no_module_state() -> None:
    from data_security.detectors import sensitive_location as sl_module

    snapshot_before = {k: id(v) for k, v in vars(sl_module).items() if not k.startswith("__")}
    bucket = _make_bucket()
    for _ in range(10):
        detect_sensitive_location(
            bucket,
            classifier_hits=[ClassifierLabel.SSN],
            envelope=_make_envelope(),
            detected_at=_TS,
        )
    snapshot_after = {k: id(v) for k, v in vars(sl_module).items() if not k.startswith("__")}
    assert snapshot_before == snapshot_after


# ---------------------------------------------------------------------------
# Parametrized — every label is a valid trigger
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "label",
    [
        ClassifierLabel.SSN,
        ClassifierLabel.CREDIT_CARD,
        ClassifierLabel.AWS_ACCESS_KEY,
        ClassifierLabel.JWT,
        ClassifierLabel.EMAIL,
        ClassifierLabel.PHONE,
        ClassifierLabel.GENERIC_API_TOKEN,
    ],
)
def test_each_non_none_label_triggers(label: ClassifierLabel) -> None:
    bucket = _make_bucket()
    out = detect_sensitive_location(
        bucket,
        classifier_hits=[label],
        envelope=_make_envelope(),
        detected_at=_TS,
    )
    assert len(out) == 1
