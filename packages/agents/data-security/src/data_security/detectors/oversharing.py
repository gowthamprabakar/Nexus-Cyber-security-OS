"""``detect_oversharing_iam`` — flag overly-permissive bucket policies.

Rule
====

The bucket policy contains a Statement that EITHER:

1. Grants ``s3:Get*`` / ``s3:List*`` / ``s3:GetObject`` / ``s3:ListBucket``
   (or broader: ``s3:*`` / ``*``) to a wildcard principal (``"*"`` or
   ``{"AWS": "*"}``) without an MFA or IP-source condition guard, OR
2. Grants the same to a principal in a different AWS account than the
   bucket owner without an MFA or IP-source condition guard.

This is the classic "publicly-readable via policy" surface that
sneaks past simple ACL-based public-bucket checks.

Same-account principals are NOT flagged (they're presumed to be the
operator's own IAM users / roles). Cross-account access WITH proper
condition guards (MFA, source IP, source VPCE, condition keys
like ``aws:PrincipalOrgID``) is NOT flagged either.

Severity
========

- **MEDIUM** — overshare statement exists.
- **HIGH** — overshare + classifier-sensitive content in bucket.

Discriminator
=============

``evidence["source_finding_type"] =
DataSecurityFindingType.S3_OVERSHARING_IAM.value``.

Forgiving parse
===============

Malformed JSON in ``policy_json`` does not crash the detector;
returns an empty list (no finding) and records the parse failure
in evidence-style logging (deferred — see Task 11 summarizer
warning lane).
"""

from __future__ import annotations

import json
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

# S3 actions that count as "read-like" overshare risks. Wildcards beyond
# these set are also caught via _action_is_oversharing.
_READ_S3_ACTIONS = frozenset(
    {
        "s3:GetObject",
        "s3:GetObjectAcl",
        "s3:GetObjectVersion",
        "s3:ListBucket",
        "s3:ListBucketVersions",
        "s3:GetBucketAcl",
        "s3:GetBucketPolicy",
        "s3:GetBucketLocation",
    }
)

# Condition keys that count as guards (their PRESENCE — not specific
# values — is enough to consider the statement guarded; this is the
# conservative posture, mirroring AWS Config best practices).
_GUARD_CONDITION_KEYS = frozenset(
    {
        "Bool",
        "BoolIfExists",
        "IpAddress",
        "IpAddressIfExists",
        "NotIpAddress",
        "StringEquals",
        "StringEqualsIfExists",
        "StringLike",
        "StringLikeIfExists",
    }
)

# Inner-key sub-set that specifically indicates MFA / source-IP / VPCE
# guards. Used to characterize WHICH guard is present in evidence.
_MFA_KEYS = frozenset({"aws:MultiFactorAuthPresent", "aws:MultiFactorAuthAge"})
_IP_KEYS = frozenset({"aws:SourceIp"})
_VPCE_KEYS = frozenset({"aws:SourceVpce", "aws:SourceVpc"})


def detect_oversharing_iam(
    bucket: Any,  # data_security.tools.s3_inventory.BucketInventory
    *,
    classifier_hits: Iterable[ClassifierLabel] = (),
    envelope: NexusEnvelope,
    detected_at: datetime,
    sequence: int = 0,
) -> list[CloudPostureFinding]:
    """Return a single ``s3_oversharing_iam`` finding if the bucket policy
    contains an overshare statement; otherwise empty list.

    Pure function: no I/O, no module state. Malformed policy JSON
    yields an empty list (parse failures don't escalate to findings).
    """
    if not bucket.policy_json:
        return []

    try:
        policy = json.loads(bucket.policy_json)
    except (json.JSONDecodeError, TypeError):
        return []

    if not isinstance(policy, dict):
        return []

    raw_statements = policy.get("Statement", [])
    if isinstance(raw_statements, dict):
        # Single-statement policy: wrap in list.
        raw_statements = [raw_statements]
    if not isinstance(raw_statements, list):
        return []

    overshare_statements: list[dict[str, Any]] = []
    for stmt in raw_statements:
        if not isinstance(stmt, dict):
            continue
        if _statement_is_oversharing(stmt, bucket_account_id=bucket.account_id):
            overshare_statements.append(stmt)

    if not overshare_statements:
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

    description = (
        f"S3 bucket {bucket.name} has {len(overshare_statements)} bucket-policy "
        f"statement(s) granting cross-account or wildcard read access without "
        f"MFA/IP/VPCE condition guards."
    )
    if sensitive_labels:
        description += (
            " Classifier flagged sensitive content (labels: "
            + ", ".join(sensitive_labels)
            + ") — HIGH escalation."
        )

    evidence: dict[str, Any] = {
        "rule": "s3_oversharing_iam",
        "source_finding_type": DataSecurityFindingType.S3_OVERSHARING_IAM.value,
        "overshare_statement_count": len(overshare_statements),
        "overshare_statement_sids": [
            str(s.get("Sid", f"unnamed-{i}")) for i, s in enumerate(overshare_statements)
        ],
        "classifier_labels_found": sensitive_labels,
    }

    return [
        build_finding(
            finding_id=finding_id,
            rule_id="s3_oversharing_iam",
            severity=severity,
            title=f"S3 bucket {bucket.name} has oversharing IAM policy",
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


def _statement_is_oversharing(stmt: dict[str, Any], *, bucket_account_id: str) -> bool:
    """Return True iff ``stmt`` represents an unguarded cross-account /
    wildcard read grant.
    """
    if stmt.get("Effect") != "Allow":
        return False

    actions = _normalize_to_list(stmt.get("Action"))
    if not any(_action_is_oversharing(a) for a in actions):
        return False

    if not _principal_is_cross_account(stmt.get("Principal"), bucket_account_id):
        return False

    # If any guard condition is present, statement is sufficiently guarded.
    return not _has_guard_condition(stmt.get("Condition"))


def _normalize_to_list(value: Any) -> list[str]:
    """Action / Resource can be a single string or list of strings."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [v for v in value if isinstance(v, str)]
    return []


def _action_is_oversharing(action: str) -> bool:
    """Match S3 read actions or broad wildcards.

    Catches:
    - ``*`` (any service)
    - ``s3:*`` (all S3)
    - ``s3:Get*`` / ``s3:List*`` (broad read-like wildcards)
    - Specific read actions enumerated in ``_READ_S3_ACTIONS``
    """
    if action == "*":
        return True
    if action == "s3:*":
        return True
    if action.startswith(("s3:Get", "s3:List")):
        return True
    return action in _READ_S3_ACTIONS


def _principal_is_cross_account(principal: Any, bucket_account_id: str) -> bool:
    """Return True iff the principal grants access outside the bucket's
    owning account.

    - ``"*"`` → cross-account (universal).
    - ``{"AWS": "*"}`` → cross-account (any AWS).
    - ``{"AWS": "arn:aws:iam::OTHER:root"}`` → cross-account if account != bucket.
    - ``{"AWS": "arn:aws:iam::SAME:root"}`` → same-account, OK.
    - ``{"Service": ...}`` → AWS service principal, OK in v0.1.
    - Anything else → conservative False (not flagged).
    """
    if principal == "*":
        return True
    if not isinstance(principal, dict):
        return False

    aws_principals = principal.get("AWS")
    if aws_principals is None:
        return False

    aws_list = _normalize_to_list(aws_principals)
    for p in aws_list:
        if p == "*":
            return True
        # Extract account ID from ARN: arn:aws:iam::ACCOUNT-ID:role/...
        account = _extract_account_id_from_arn(p)
        if account and account != bucket_account_id:
            return True
        # Bare account-id string (sometimes used in policies).
        if account is None and p.isdigit() and len(p) == 12 and p != bucket_account_id:
            return True
    return False


def _extract_account_id_from_arn(arn: str) -> str | None:
    """``arn:aws:iam::123456789012:...`` → ``"123456789012"``. None if not an ARN."""
    if not arn.startswith("arn:"):
        return None
    parts = arn.split(":")
    # arn:aws:iam::ACCOUNT:role/foo → ["arn", "aws", "iam", "", "ACCOUNT", "role/foo"]
    if len(parts) < 5:
        return None
    account = parts[4]
    if account.isdigit() and len(account) == 12:
        return account
    return None


def _has_guard_condition(condition: Any) -> bool:
    """Return True iff ``condition`` contains a known guard operator with
    MFA / IP / VPCE / org-scope keys.

    The presence of any guard operator is the signal — v0.1 doesn't
    evaluate the specific guard value (the conservative posture).
    """
    if not isinstance(condition, dict):
        return False
    for op_key, op_value in condition.items():
        if op_key not in _GUARD_CONDITION_KEYS:
            continue
        if not isinstance(op_value, dict):
            continue
        for inner_key in op_value:
            if (
                inner_key in _MFA_KEYS
                or inner_key in _IP_KEYS
                or inner_key in _VPCE_KEYS
                or inner_key == "aws:PrincipalOrgID"
            ):
                return True
    return False


def _build_finding_id(bucket_name: str, sequence: int) -> str:
    src = source_token(DataSecurityFindingType.S3_OVERSHARING_IAM)
    context = _SLUG_RE.sub("-", bucket_name.lower()).strip("-") or "bucket"
    context = context[:40]
    return f"CSPM-AWS-{src}-{sequence:03d}-{context}"
