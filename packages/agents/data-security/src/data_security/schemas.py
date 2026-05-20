"""Data Security schemas — re-export F.3's OCSF v1.3 Compliance Finding.

**Q1 resolution (per the D.5 plan).** D.5 emits the **identical wire shape**
as F.3 Cloud Posture (`class_uid 2003 Compliance Finding`) — no fork, no
duplication. The schema-as-typing-layer pattern is unchanged; D.5 adds a
`DataSecurityFindingType` enum (the 4-detector discriminator) and a
`ClassifierLabel` enum (the privacy-contract label space) that ride
inside the existing OCSF surface.

Cross-agent OCSF inventory after D.5 (Compliance Finding family):

| Agent                         | OCSF class_uid | Discriminator                  |
| ----------------------------- | -------------- | ------------------------------ |
| Cloud Posture (F.3) — AWS     | 2003           | (none — AWS only)              |
| multi-cloud-posture           | 2003           | CSPMFindingType                |
| k8s-posture                   | 2003           | K8sFindingType                 |
| **Data Security (D.5)**       | **2003**       | **DataSecurityFindingType**    |

Re-exports from `cloud_posture.schemas`:

- `OCSF_*` constants
- `Severity` enum
- `AffectedResource` model
- `CloudPostureFinding` typed wrapper
- `build_finding` constructor
- `FindingsReport` aggregate
- `FINDING_ID_RE` (validates `CSPM-<CLOUD>-<SVC>-<NNN>-<context>`)

D.5-specific additions:

- `DataSecurityFindingType` enum — 4 detector discriminators (one per
  detector rule that lands in Tasks 5-8).
- `ClassifierLabel` enum — the privacy-contract label space (Q6).
  The classifier (Task 3) returns one of these enum values for any
  match; it MUST NEVER return the matched substring itself.
- `source_token(finding_type)` — finding-id source-token helper.
"""

from __future__ import annotations

from enum import StrEnum

from cloud_posture.schemas import (
    FINDING_ID_RE,
    OCSF_CATEGORY_NAME,
    OCSF_CATEGORY_UID,
    OCSF_CLASS_NAME,
    OCSF_CLASS_UID,
    OCSF_VERSION,
    AffectedResource,
    CloudPostureFinding,
    FindingsReport,
    Severity,
    build_finding,
    severity_from_id,
    severity_to_id,
)


class DataSecurityFindingType(StrEnum):
    """The detector-rule discriminator. Drives ``finding_info.types[0]``.

    One value per detector module landing in Tasks 5-8. Discriminator
    strings are stable wire-format identifiers — downstream consumers
    (D.7 Investigation, Meta-Harness, future D.6 Compliance) may filter
    on these. **Do not rename without a coordinated OCSF wire-shape
    change** (per ADR-010 §"When this template stops applying").
    """

    S3_BUCKET_PUBLIC = "data_security_s3_bucket_public"
    S3_BUCKET_UNENCRYPTED = "data_security_s3_bucket_unencrypted"
    S3_OBJECT_SENSITIVE_IN_UNTRUSTED_LOCATION = (
        "data_security_s3_object_sensitive_in_untrusted_location"
    )
    S3_OVERSHARING_IAM = "data_security_s3_oversharing_iam"


class ClassifierLabel(StrEnum):
    """The privacy-contract label space (plan Q6).

    The classifier returns one of these enum values for any match. It
    **NEVER** returns the matched substring itself — that's the load-
    bearing Q6 invariant. Detector logs carry ``(bucket, object_key,
    label)`` triples; the matched text never appears in ``findings.json``
    or ``report.md``. The Task-13 ``no_pii_leak_in_report`` eval case
    is the acceptance probe.

    Label set is intentionally compact for v0.1 (7 labels + NONE).
    Expansion (date-of-birth, addresses, healthcare IDs) deferred to
    D.5 v0.2 per the version-roadmap.
    """

    SSN = "ssn"
    CREDIT_CARD = "credit_card"
    AWS_ACCESS_KEY = "aws_access_key"
    JWT = "jwt"
    EMAIL = "email"
    PHONE = "phone"
    GENERIC_API_TOKEN = "generic_api_token"  # noqa: S105  # enum label, not a credential
    NONE = "none"


# Maps the discriminator to the short token used in finding_id construction.
# F.3's FINDING_ID_RE is `CSPM-[A-Z]+-[A-Z0-9]+-\d{3}-[a-z0-9_-]+`; the first
# bracket is the cloud (AWS for D.5 v0.1), the second is the detector source.
_FT_SOURCE_TOKEN: dict[DataSecurityFindingType, str] = {
    DataSecurityFindingType.S3_BUCKET_PUBLIC: "PUBLIC",
    DataSecurityFindingType.S3_BUCKET_UNENCRYPTED: "UNENC",
    DataSecurityFindingType.S3_OBJECT_SENSITIVE_IN_UNTRUSTED_LOCATION: "SENSLOC",
    DataSecurityFindingType.S3_OVERSHARING_IAM: "OVERSHARE",
}


def source_token(finding_type: DataSecurityFindingType) -> str:
    """Return the finding-id source-token for a ``DataSecurityFindingType``."""
    return _FT_SOURCE_TOKEN[finding_type]


__all__ = [
    "FINDING_ID_RE",
    "OCSF_CATEGORY_NAME",
    "OCSF_CATEGORY_UID",
    "OCSF_CLASS_NAME",
    "OCSF_CLASS_UID",
    "OCSF_VERSION",
    "AffectedResource",
    "ClassifierLabel",
    "CloudPostureFinding",
    "DataSecurityFindingType",
    "FindingsReport",
    "Severity",
    "build_finding",
    "severity_from_id",
    "severity_to_id",
    "source_token",
]
