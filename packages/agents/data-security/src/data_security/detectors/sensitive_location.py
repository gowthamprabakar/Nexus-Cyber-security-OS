"""``detect_sensitive_location`` — flag sensitive data in untrusted buckets.

Rule
====

Classifier-sensitive content (any ``ClassifierLabel`` other than
``NONE``) was found inside this bucket, AND the bucket is not tagged
as a trusted location for sensitive data. The trust signal is the
operator-managed ``Sensitivity`` tag — if it equals
``"Restricted"``, the bucket is the right place for sensitive data
and this detector emits nothing. Any other value (or missing tag)
means the data is in an untrusted location.

This is fundamentally a **tag-drift** detector: it catches sensitive
content that ended up somewhere the operator didn't explicitly
green-light for it. Common causes: incremental copy/sync from a
restricted bucket; accidental upload to a general-purpose bucket;
forgotten dev bucket promoted to a real workload.

The trusted-tag value defaults to ``"Restricted"`` (matching common
AWS Data Classification tagging guidance). Operators can override
via the agent driver's contract config (Task 12); v0.1 ships the
hard-coded default.

Severity
========

- **HIGH** — classifier hit + untrusted location.

Note: this detector does NOT have a CRITICAL uplift via further
classifier evidence (the classifier hit is the trigger itself).
The CORRELATE stage (Task 9) may uplift to CRITICAL if F.3 also
flagged this bucket; that's out of scope here.

Output
======

Returns ``list[CloudPostureFinding]`` — empty when no hit OR
bucket is trusted; single-finding list when both conditions hold.

Discriminator
=============

``evidence["source_finding_type"] =
DataSecurityFindingType.S3_OBJECT_SENSITIVE_IN_UNTRUSTED_LOCATION.value``.
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

# Operator-managed tag name + trusted value. v0.1 hard-codes the
# defaults; Task 12 plumbs an optional override through the contract.
SENSITIVITY_TAG_KEY = "Sensitivity"
TRUSTED_TAG_VALUE = "Restricted"


def detect_sensitive_location(
    bucket: Any,  # data_security.tools.s3_inventory.BucketInventory
    *,
    classifier_hits: Iterable[ClassifierLabel] = (),
    envelope: NexusEnvelope,
    detected_at: datetime,
    sequence: int = 0,
    trusted_tag_value: str = TRUSTED_TAG_VALUE,
) -> list[CloudPostureFinding]:
    """Return a single ``s3_object_sensitive_in_untrusted_location`` finding
    if classifier-sensitive content was found in this bucket AND the
    bucket isn't tagged as a trusted location; otherwise an empty list.

    Pure function: no I/O, no module state.
    """
    sensitive_labels = sorted({lbl.value for lbl in classifier_hits if lbl != ClassifierLabel.NONE})
    if not sensitive_labels:
        # No classifier hit → no finding (this rule's trigger requires it).
        return []

    actual_tag_value = bucket.tags.get(SENSITIVITY_TAG_KEY)
    if actual_tag_value == trusted_tag_value:
        # Bucket is the right place for sensitive data.
        return []

    finding_id = _build_finding_id(bucket.name, sequence)
    affected = AffectedResource(
        cloud="aws",
        account_id=bucket.account_id,
        region=bucket.region,
        resource_type="s3-bucket",
        resource_id=bucket.name,
        arn=bucket.arn,
    )

    description = (
        f"S3 bucket {bucket.name} contains classifier-sensitive content "
        f"(labels: {', '.join(sensitive_labels)}) but is not tagged "
        f"{SENSITIVITY_TAG_KEY}={trusted_tag_value!r}. "
        f"Actual {SENSITIVITY_TAG_KEY} tag: {actual_tag_value!r}."
    )

    evidence: dict[str, Any] = {
        "rule": "s3_object_sensitive_in_untrusted_location",
        "source_finding_type": (
            DataSecurityFindingType.S3_OBJECT_SENSITIVE_IN_UNTRUSTED_LOCATION.value
        ),
        "classifier_labels_found": sensitive_labels,
        "sensitivity_tag_key": SENSITIVITY_TAG_KEY,
        "trusted_tag_value": trusted_tag_value,
        "actual_tag_value": actual_tag_value,
        "all_tags": dict(bucket.tags),
    }

    return [
        build_finding(
            finding_id=finding_id,
            rule_id="s3_object_sensitive_in_untrusted_location",
            severity=Severity.HIGH,
            title=f"Sensitive data in untrusted S3 bucket {bucket.name}",
            description=description,
            affected=[affected],
            detected_at=detected_at,
            envelope=envelope,
            evidence=evidence,
        )
    ]


def _build_finding_id(bucket_name: str, sequence: int) -> str:
    src = source_token(DataSecurityFindingType.S3_OBJECT_SENSITIVE_IN_UNTRUSTED_LOCATION)
    context = _SLUG_RE.sub("-", bucket_name.lower()).strip("-") or "bucket"
    context = context[:40]
    return f"CSPM-AWS-{src}-{sequence:03d}-{context}"
