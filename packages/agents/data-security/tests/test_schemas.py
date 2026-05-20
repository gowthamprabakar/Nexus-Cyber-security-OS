"""Schemas tests — Task 2.

Verifies the F.3 schema re-export (Q1 substrate) plus the two D.5-specific
enums that ride inside the OCSF surface:

- ``DataSecurityFindingType`` — 4 detector discriminators (Tasks 5-8).
- ``ClassifierLabel`` — privacy-contract label space (plan Q6).

Source-token helper round-trips. No build_finding integration test yet —
that lands in the detector tests (Tasks 6-9) where the detector outputs
go through build_finding for real.
"""

from __future__ import annotations

import pytest
from data_security.schemas import (
    FINDING_ID_RE,
    OCSF_CATEGORY_NAME,
    OCSF_CATEGORY_UID,
    OCSF_CLASS_NAME,
    OCSF_CLASS_UID,
    OCSF_VERSION,
    AffectedResource,
    ClassifierLabel,
    CloudPostureFinding,
    DataSecurityFindingType,
    FindingsReport,
    Severity,
    build_finding,
    severity_from_id,
    severity_to_id,
    source_token,
)

# ---------------------------------------------------------------------------
# F.3 re-export — Q1 substrate
# ---------------------------------------------------------------------------


def test_ocsf_constants_are_f3_compliance_finding() -> None:
    """D.5 emits identical wire shape to F.3 / multi-cloud-posture / k8s-posture."""
    assert OCSF_VERSION == "1.3.0"
    assert OCSF_CATEGORY_UID == 2
    assert OCSF_CATEGORY_NAME == "Findings"
    assert OCSF_CLASS_UID == 2003
    assert OCSF_CLASS_NAME == "Compliance Finding"


def test_severity_enum_round_trips_via_ocsf_id() -> None:
    for s in Severity:
        assert severity_from_id(severity_to_id(s)) is s


def test_finding_id_re_pattern() -> None:
    assert FINDING_ID_RE.pattern == r"^CSPM-[A-Z]+-[A-Z0-9]+-\d{3}-[a-z0-9_-]+$"
    # Valid examples per D.5 source-token table.
    assert FINDING_ID_RE.match("CSPM-AWS-PUBLIC-001-my-bucket")
    assert FINDING_ID_RE.match("CSPM-AWS-UNENC-042-corp-data-lake")
    assert FINDING_ID_RE.match("CSPM-AWS-SENSLOC-007-untrusted-bucket")
    assert FINDING_ID_RE.match("CSPM-AWS-OVERSHARE-013-shared-bucket")
    # Lowercase cloud token must fail.
    assert not FINDING_ID_RE.match("CSPM-aws-PUBLIC-001-bucket")
    # Missing sequence number must fail.
    assert not FINDING_ID_RE.match("CSPM-AWS-PUBLIC-my-bucket")


def test_affected_resource_round_trips_to_ocsf() -> None:
    r = AffectedResource(
        cloud="aws",
        account_id="123456789012",
        region="us-east-1",
        resource_type="s3-bucket",
        resource_id="my-bucket",
        arn="arn:aws:s3:::my-bucket",
    )
    payload = r.to_ocsf()
    assert payload["type"] == "s3-bucket"
    assert payload["uid"] == "arn:aws:s3:::my-bucket"
    assert payload["cloud_partition"] == "aws"
    assert payload["region"] == "us-east-1"
    assert payload["owner"]["account_uid"] == "123456789012"


def test_cloud_posture_finding_class_is_reexported() -> None:
    """CloudPostureFinding name preserved across the re-export boundary."""
    assert CloudPostureFinding.__name__ == "CloudPostureFinding"


def test_findings_report_class_is_reexported() -> None:
    assert FindingsReport.__name__ == "FindingsReport"


def test_build_finding_callable_is_reexported() -> None:
    assert callable(build_finding)
    assert build_finding.__name__ == "build_finding"


# ---------------------------------------------------------------------------
# DataSecurityFindingType — discriminator
# ---------------------------------------------------------------------------


def test_data_security_finding_type_has_4_values() -> None:
    """One value per detector module landing in Tasks 5-8."""
    members = set(DataSecurityFindingType)
    assert len(members) == 4
    assert DataSecurityFindingType.S3_BUCKET_PUBLIC in members
    assert DataSecurityFindingType.S3_BUCKET_UNENCRYPTED in members
    assert DataSecurityFindingType.S3_OBJECT_SENSITIVE_IN_UNTRUSTED_LOCATION in members
    assert DataSecurityFindingType.S3_OVERSHARING_IAM in members


def test_data_security_finding_type_wire_strings_have_namespace_prefix() -> None:
    """Wire strings must be prefixed with ``data_security_`` so D.7 / Meta-Harness
    can disambiguate from D.6 (k8s) / multi-cloud-posture findings on the
    same OCSF class_uid 2003.
    """
    for ft in DataSecurityFindingType:
        assert ft.value.startswith("data_security_"), (
            f"{ft.name}={ft.value!r} missing data_security_ prefix"
        )


def test_data_security_finding_type_wire_strings_are_stable() -> None:
    """Verbatim wire-format strings. **Renaming requires a coordinated OCSF
    wire-shape change** (per ADR-010 §"When this template stops applying").
    """
    assert DataSecurityFindingType.S3_BUCKET_PUBLIC.value == "data_security_s3_bucket_public"
    assert (
        DataSecurityFindingType.S3_BUCKET_UNENCRYPTED.value == "data_security_s3_bucket_unencrypted"
    )
    assert (
        DataSecurityFindingType.S3_OBJECT_SENSITIVE_IN_UNTRUSTED_LOCATION.value
        == "data_security_s3_object_sensitive_in_untrusted_location"
    )
    assert DataSecurityFindingType.S3_OVERSHARING_IAM.value == "data_security_s3_oversharing_iam"


# ---------------------------------------------------------------------------
# ClassifierLabel — privacy-contract label space (plan Q6)
# ---------------------------------------------------------------------------


def test_classifier_label_has_7_plus_none() -> None:
    """7 PII / sensitive-data labels + NONE sentinel."""
    members = set(ClassifierLabel)
    assert len(members) == 8
    assert ClassifierLabel.NONE in members
    sensitive = members - {ClassifierLabel.NONE}
    assert len(sensitive) == 7


def test_classifier_label_covers_v0_1_target_categories() -> None:
    """The 7 v0.1 labels per plan Task 3."""
    for label in (
        ClassifierLabel.SSN,
        ClassifierLabel.CREDIT_CARD,
        ClassifierLabel.AWS_ACCESS_KEY,
        ClassifierLabel.JWT,
        ClassifierLabel.EMAIL,
        ClassifierLabel.PHONE,
        ClassifierLabel.GENERIC_API_TOKEN,
    ):
        assert isinstance(label, ClassifierLabel)


def test_classifier_label_none_is_sentinel_not_a_match() -> None:
    """``NONE`` must be present so the classifier API can return a non-match
    without ever returning ``None``-as-Python-None (which would conflate
    "no match" with "value not classified yet"). The Q6 invariant is
    "label only, never substring" — this is part of how that's typed.
    """
    assert ClassifierLabel.NONE.value == "none"
    assert ClassifierLabel.NONE != ClassifierLabel.SSN


def test_classifier_label_wire_strings_are_stable() -> None:
    """Verbatim wire-format strings (lowercase snake_case). These surface in
    ``finding_info`` dicts and audit-event payloads.
    """
    assert ClassifierLabel.SSN.value == "ssn"
    assert ClassifierLabel.CREDIT_CARD.value == "credit_card"
    assert ClassifierLabel.AWS_ACCESS_KEY.value == "aws_access_key"
    assert ClassifierLabel.JWT.value == "jwt"
    assert ClassifierLabel.EMAIL.value == "email"
    assert ClassifierLabel.PHONE.value == "phone"
    assert ClassifierLabel.GENERIC_API_TOKEN.value == "generic_api_token"
    assert ClassifierLabel.NONE.value == "none"


# ---------------------------------------------------------------------------
# source_token helper
# ---------------------------------------------------------------------------


def test_source_token_returns_finding_id_safe_token_for_each_detector() -> None:
    """All source tokens must satisfy the `[A-Z0-9]+` bracket of FINDING_ID_RE."""
    import re

    bracket_re = re.compile(r"^[A-Z0-9]+$")
    for ft in DataSecurityFindingType:
        token = source_token(ft)
        assert bracket_re.match(token), (
            f"source_token({ft.name})={token!r} does not match [A-Z0-9]+"
        )


def test_source_token_round_trip_into_finding_id() -> None:
    """A finding_id built with a source token must satisfy FINDING_ID_RE."""
    for ft in DataSecurityFindingType:
        token = source_token(ft)
        finding_id = f"CSPM-AWS-{token}-001-example-bucket"
        assert FINDING_ID_RE.match(finding_id), f"finding_id {finding_id!r} does not match"


def test_source_token_values_are_stable() -> None:
    """Verbatim source tokens. Used inside FINDING_ID_RE; renaming requires a
    coordinated wire-shape change.
    """
    assert source_token(DataSecurityFindingType.S3_BUCKET_PUBLIC) == "PUBLIC"
    assert source_token(DataSecurityFindingType.S3_BUCKET_UNENCRYPTED) == "UNENC"
    assert (
        source_token(DataSecurityFindingType.S3_OBJECT_SENSITIVE_IN_UNTRUSTED_LOCATION) == "SENSLOC"
    )
    assert source_token(DataSecurityFindingType.S3_OVERSHARING_IAM) == "OVERSHARE"


def test_source_token_unmapped_raises() -> None:
    """Mapping table must cover every enum value — guards against silent drift
    if a new ``DataSecurityFindingType`` value is added without a token.
    """
    # All current values are mapped — verify by iterating.
    for ft in DataSecurityFindingType:
        try:
            source_token(ft)
        except KeyError:
            pytest.fail(f"source_token({ft.name}) missing from mapping table")
