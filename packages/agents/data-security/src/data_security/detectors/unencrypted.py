"""``detect_unencrypted`` — flag S3 buckets missing default server-side encryption.

Rule
====

A bucket fails this rule when its default server-side encryption is
``NONE`` — i.e., the bucket has no encryption configuration at rest. AWS
introduced default-on SSE for new buckets in 2023, but existing buckets
predating that change can still ship without it, and operators can
explicitly disable encryption via ``put-bucket-encryption`` with no
SSE rule.

The ``BucketEncryption.algorithm`` value comes from the reader (Task 4);
expected values are ``NONE`` / ``AES256`` / ``aws:kms`` / ``aws:kms:dsse``.
Only ``NONE`` triggers this detector.

Severity
========

- **MEDIUM** — default SSE is missing.
- **HIGH** — default SSE is missing AND classifier-sensitive content
  (any ``ClassifierLabel`` other than ``NONE``) was found in this
  bucket during the CLASSIFY stage.

Discriminator
=============

``evidence["source_finding_type"] =
DataSecurityFindingType.S3_BUCKET_UNENCRYPTED.value``. Mirrors the
``s3_bucket_public`` (Task 5) discriminator pattern.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from datetime import datetime
from typing import Any

from shared.fabric.envelope import NexusEnvelope

from data_security.schemas import (
    AffectedResource,
    ClassifierLabel,
    CloudPostureFinding,
    DataSecurityFindingType,
    Severity,
    build_finding,
    source_token,
)

_SLUG_RE = re.compile(r"[^a-z0-9]+")


def detect_unencrypted(
    bucket: Any,  # data_security.tools.s3_inventory.BucketInventory
    *,
    classifier_hits: Iterable[ClassifierLabel] = (),
    envelope: NexusEnvelope,
    detected_at: datetime,
    sequence: int = 0,
) -> list[CloudPostureFinding]:
    """Return a single ``s3_bucket_unencrypted`` finding if the bucket has
    no default SSE configured; otherwise an empty list.

    Pure function: no I/O, no module state.
    """
    if bucket.encryption.algorithm != "NONE":
        return []

    sensitive_labels = sorted({lbl.value for lbl in classifier_hits if lbl != ClassifierLabel.NONE})
    severity = Severity.HIGH if sensitive_labels else Severity.MEDIUM

    finding_id = _build_finding_id(bucket.name, sequence)
    affected = AffectedResource(
        cloud="aws",
        account_id=bucket.account_id,
        region=bucket.region,
        resource_type="s3-bucket",
        resource_id=bucket.name,
        arn=bucket.arn,
    )

    description = f"S3 bucket {bucket.name} has no default server-side encryption configured."
    if sensitive_labels:
        description += (
            " Classifier flagged sensitive content (labels: "
            + ", ".join(sensitive_labels)
            + ") — HIGH escalation."
        )

    evidence: dict[str, Any] = {
        "rule": "s3_bucket_unencrypted",
        "source_finding_type": DataSecurityFindingType.S3_BUCKET_UNENCRYPTED.value,
        "encryption_algorithm": bucket.encryption.algorithm,
        "classifier_labels_found": sensitive_labels,
    }

    return [
        build_finding(
            finding_id=finding_id,
            rule_id="s3_bucket_unencrypted",
            severity=severity,
            title=f"S3 bucket {bucket.name} has no default encryption",
            description=description,
            affected=[affected],
            detected_at=detected_at,
            envelope=envelope,
            evidence=evidence,
        )
    ]


def _build_finding_id(bucket_name: str, sequence: int) -> str:
    src = source_token(DataSecurityFindingType.S3_BUCKET_UNENCRYPTED)
    context = _SLUG_RE.sub("-", bucket_name.lower()).strip("-") or "bucket"
    context = context[:40]
    return f"CSPM-AWS-{src}-{sequence:03d}-{context}"
