"""KMS key policy exposure reader (path #21 — exposed encryption key).

A KMS key whose key policy grants use to the whole internet (``Principal: *``) or a foreign account
undermines every resource it encrypts — the encryption boundary is open. This reads customer-managed
keys and flags a wildcard-principal ``Allow`` in the key policy (the canonical CSPM signal).

Plain boto3 reader: inject the ``kms`` client, so it runs against real AWS or in-process moto.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class KmsKey:
    """A KMS key resolved to its ARN and whether its key policy is internet-open."""

    key_arn: str
    is_public: bool


def _principal_is_wildcard(principal: Any) -> bool:
    if principal == "*":
        return True
    if isinstance(principal, dict):
        aws = principal.get("AWS")
        return aws == "*" or (isinstance(aws, list) and "*" in aws)
    return False


def _policy_is_public(policy: dict) -> bool:
    """True if the key policy has an ``Allow`` statement to a wildcard principal."""
    return any(
        isinstance(stmt, dict)
        and stmt.get("Effect") == "Allow"
        and _principal_is_wildcard(stmt.get("Principal"))
        for stmt in policy.get("Statement") or []
    )


def read_kms_keys(kms: object) -> list[KmsKey]:
    """Enumerate KMS keys as ``KmsKey`` rows (exposure = wildcard-principal key policy)."""
    out: list[KmsKey] = []
    for entry in kms.list_keys().get("Keys", []):  # type: ignore[attr-defined]
        key_id = entry.get("KeyId")
        if not key_id:
            continue
        try:
            arn = kms.describe_key(KeyId=key_id)["KeyMetadata"]["Arn"]  # type: ignore[attr-defined]
            policy_raw = kms.get_key_policy(KeyId=key_id, PolicyName="default")["Policy"]  # type: ignore[attr-defined]
            policy = json.loads(policy_raw)
        except Exception:  # noqa: S112 — a key we can't read posture for is skipped, not fatal
            continue
        out.append(KmsKey(key_arn=str(arn), is_public=_policy_is_public(policy)))
    return out


__all__ = ["KmsKey", "read_kms_keys"]
