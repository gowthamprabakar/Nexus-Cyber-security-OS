"""``detect_public_bucket`` — flag S3 buckets exposed publicly.

Rule
====

A bucket is publicly accessible if EITHER:

1. The bucket ACL grants ``READ`` (or higher) to ``AllUsers`` or
   ``AuthenticatedUsers`` — those are AWS's "anyone with an AWS
   account" / "anyone on the internet" groups.
2. Block Public Access (BPA) is NOT fully on. Any of the four BPA
   flags (``block_public_acls`` / ``ignore_public_acls`` /
   ``block_public_policy`` / ``restrict_public_buckets``) being False
   means a policy or ACL could expose the bucket even if the current
   ACL is benign.

Severity
========

- **HIGH** — any public grant exists.
- **CRITICAL** — public grant exists AND classifier-sensitive content
  (any ``ClassifierLabel`` other than ``NONE``) was found in this
  bucket during the CLASSIFY stage.

The CRITICAL uplift is the headline DSPM signal: "this bucket is
exposed AND has sensitive data in it." Tasks 9-10 (CORRELATE + SCORE)
may apply a second uplift based on sibling F.3 findings; that's
out of scope here.

Output
======

Returns ``list[CloudPostureFinding]`` — empty if the bucket is not
public, single-item if it is. The list shape allows future detectors
to emit multiple findings per bucket if needed.

Discriminator
=============

``evidence["source_finding_type"] =
DataSecurityFindingType.S3_BUCKET_PUBLIC.value`` per the multi-cloud-
posture precedent. ``finding_info.types[0]`` is not currently set
because the F.3 ``build_finding`` does not expose that field;
downstream consumers should filter on
``evidence.source_finding_type`` or ``compliance.control`` (which
this detector sets to ``"s3_bucket_public"``).
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

# The two public-grantee group URIs per AWS S3 ACL spec.
_ALL_USERS = "http://acs.amazonaws.com/groups/global/AllUsers"
_AUTH_USERS = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"

# Permissions that count as "public" exposure when granted to those groups.
_PUBLIC_PERMISSIONS = frozenset({"READ", "READ_ACP", "WRITE", "WRITE_ACP", "FULL_CONTROL"})

# Regex for finding-id `<context>` slug — lowercase alphanumerics + hyphens.
_SLUG_RE = re.compile(r"[^a-z0-9]+")


def detect_public_bucket(
    bucket: Any,  # data_security.tools.s3_inventory.BucketInventory (avoid circular import)
    *,
    classifier_hits: Iterable[ClassifierLabel] = (),
    envelope: NexusEnvelope,
    detected_at: datetime,
    sequence: int = 0,
) -> list[CloudPostureFinding]:
    """Return a single ``s3_bucket_public`` finding for ``bucket`` if it is
    publicly accessible; otherwise return an empty list.

    Pure function: no I/O, no module state. ``sequence`` is the per-run
    counter from the agent driver; it goes into the finding_id's
    ``-NNN-`` segment for stable ordering.
    """
    acl_grants = _public_acl_grants(bucket)
    bpa_gaps = _bpa_gaps(bucket)
    if not acl_grants and not bpa_gaps:
        return []

    sensitive_labels = sorted({lbl.value for lbl in classifier_hits if lbl != ClassifierLabel.NONE})
    severity = Severity.CRITICAL if sensitive_labels else Severity.HIGH

    finding_id = _build_finding_id(bucket.name, sequence)
    affected = AffectedResource(
        cloud="aws",
        account_id=bucket.account_id,
        region=bucket.region,
        resource_type="s3-bucket",
        resource_id=bucket.name,
        arn=bucket.arn,
    )

    description_parts: list[str] = []
    if acl_grants:
        description_parts.append(
            "ACL grants public access: "
            + ", ".join(f"{principal}={','.join(perms)}" for principal, perms in acl_grants)
        )
    if bpa_gaps:
        description_parts.append("Block Public Access disabled flags: " + ", ".join(bpa_gaps))
    if sensitive_labels:
        description_parts.append(
            "Classifier flagged sensitive content (labels: "
            + ", ".join(sensitive_labels)
            + ") inside this bucket — CRITICAL escalation."
        )
    description = " ".join(description_parts)

    evidence: dict[str, Any] = {
        "rule": "s3_bucket_public",
        "source_finding_type": DataSecurityFindingType.S3_BUCKET_PUBLIC.value,
        "acl_grants_all_users": list(bucket.acl.grants_all_users),
        "acl_grants_authenticated_users": list(bucket.acl.grants_authenticated_users),
        "block_public_access": {
            "block_public_acls": bucket.public_access_block.block_public_acls,
            "ignore_public_acls": bucket.public_access_block.ignore_public_acls,
            "block_public_policy": bucket.public_access_block.block_public_policy,
            "restrict_public_buckets": bucket.public_access_block.restrict_public_buckets,
        },
        "classifier_labels_found": sensitive_labels,
    }

    return [
        build_finding(
            finding_id=finding_id,
            rule_id="s3_bucket_public",
            severity=severity,
            title=f"S3 bucket {bucket.name} is publicly accessible",
            description=description,
            affected=[affected],
            detected_at=detected_at,
            envelope=envelope,
            evidence=evidence,
        )
    ]


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _public_acl_grants(bucket: Any) -> list[tuple[str, list[str]]]:
    """Return ``[(principal, [permissions...]), ...]`` for ACL grants that
    expose the bucket. Empty list if the ACL has no public grants.
    """
    grants: list[tuple[str, list[str]]] = []
    all_perms = [p for p in bucket.acl.grants_all_users if p in _PUBLIC_PERMISSIONS]
    if all_perms:
        grants.append((_ALL_USERS, all_perms))
    auth_perms = [p for p in bucket.acl.grants_authenticated_users if p in _PUBLIC_PERMISSIONS]
    if auth_perms:
        grants.append((_AUTH_USERS, auth_perms))
    return grants


def _bpa_gaps(bucket: Any) -> list[str]:
    """Return names of BPA flags that are False (i.e. NOT blocking public
    access). Empty list when all four are True.
    """
    pab = bucket.public_access_block
    gaps: list[str] = []
    if not pab.block_public_acls:
        gaps.append("block_public_acls")
    if not pab.ignore_public_acls:
        gaps.append("ignore_public_acls")
    if not pab.block_public_policy:
        gaps.append("block_public_policy")
    if not pab.restrict_public_buckets:
        gaps.append("restrict_public_buckets")
    return gaps


def _build_finding_id(bucket_name: str, sequence: int) -> str:
    """Construct F.3-shaped finding_id: ``CSPM-AWS-PUBLIC-NNN-<slug>``."""
    src = source_token(DataSecurityFindingType.S3_BUCKET_PUBLIC)
    context = _SLUG_RE.sub("-", bucket_name.lower()).strip("-") or "bucket"
    context = context[:40]
    return f"CSPM-AWS-{src}-{sequence:03d}-{context}"
