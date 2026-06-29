"""Cloud remediation actions (AWS) — the one-click fixes for the top exposure paths.

A.1 v0.1 was K8s-patch only. These add the two highest-value cloud fixes the attack-path report
points at: **S3 Block Public Access** (closes public_secret / public_unencrypted) and **RDS make
private** (closes exposed_database). They follow the same safety discipline as the kubectl executor:

- **dry-run first** — ``execute=False`` (preview) computes the change and mutates NOTHING.
- **idempotent + scoped** — one named target per call; if it's already compliant the call is a no-op
  (``already_compliant``), never a blind re-write.
- **tighten-only** — each action is hard-wired to CLOSE access (block-public / not-publicly-
  accessible); it has no code path that loosens, so a bug can't widen exposure.
- **before-state captured** — the prior config is returned so the change is auditable and reversible
  (``restore_*`` re-applies it; re-opening is itself an operator decision, never automatic).
- **verify-after** — ``execute`` re-reads the resource and only reports success when the fix is
  confirmed present.

The cloud client is injected (boto3 ``s3`` / ``rds``), so the same code runs against real AWS or
in-process moto — CI proves the logic; real-account execution stays operator-gated.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

#: Action identifiers — the ``auto_via`` values the attack-path report names.
ACTION_S3_BLOCK_PUBLIC_ACCESS = "remediation_s3_block_public_access"
ACTION_RDS_DISABLE_PUBLIC_ACCESS = "remediation_rds_disable_public_access"

_ALL_BLOCKED = {
    "BlockPublicAcls": True,
    "IgnorePublicAcls": True,
    "BlockPublicPolicy": True,
    "RestrictPublicBuckets": True,
}


@dataclass(frozen=True, slots=True)
class CloudRemediationResult:
    """Outcome of one cloud remediation on one resource. ``before`` enables audit + rollback."""

    action: str
    target: str
    mode: str  # "preview" | "execute"
    outcome: str  # already_compliant | would_change | executed_verified | execute_failed
    detail: str
    before: dict[str, Any] = field(default_factory=dict)
    after: dict[str, Any] = field(default_factory=dict)

    @property
    def changed(self) -> bool:
        return self.outcome == "executed_verified"


def _get_bpa(s3: object, bucket: str) -> dict[str, Any]:
    try:
        cfg = s3.get_public_access_block(Bucket=bucket)  # type: ignore[attr-defined]
        return dict(cfg.get("PublicAccessBlockConfiguration", {}))
    except Exception:
        return {}


def block_public_access(s3: object, bucket: str, *, execute: bool) -> CloudRemediationResult:
    """Enable S3 Block Public Access on one bucket (closes public_secret / public_unencrypted).

    Tighten-only and idempotent: a bucket already fully blocked is a no-op. ``execute=False`` previews
    the change without mutating. On execute, verifies all four flags are set before reporting success.
    """
    before = _get_bpa(s3, bucket)
    if all(before.get(k) is True for k in _ALL_BLOCKED):
        return CloudRemediationResult(
            ACTION_S3_BLOCK_PUBLIC_ACCESS,
            bucket,
            "execute" if execute else "preview",
            "already_compliant",
            "Block Public Access already fully enabled — no change.",
            before,
            before,
        )
    if not execute:
        return CloudRemediationResult(
            ACTION_S3_BLOCK_PUBLIC_ACCESS,
            bucket,
            "preview",
            "would_change",
            "Would enable all four Block Public Access flags on the bucket.",
            before,
        )
    s3.put_public_access_block(  # type: ignore[attr-defined]
        Bucket=bucket, PublicAccessBlockConfiguration=dict(_ALL_BLOCKED)
    )
    after = _get_bpa(s3, bucket)
    ok = all(after.get(k) is True for k in _ALL_BLOCKED)
    return CloudRemediationResult(
        ACTION_S3_BLOCK_PUBLIC_ACCESS,
        bucket,
        "execute",
        "executed_verified" if ok else "execute_failed",
        "Block Public Access enabled and verified." if ok else "Applied but verification failed.",
        before,
        after,
    )


def restore_public_access(s3: object, bucket: str, before: dict[str, Any]) -> None:
    """Re-apply a previously-captured BPA config (rollback). Re-opening is an operator decision."""
    if before:
        s3.put_public_access_block(  # type: ignore[attr-defined]
            Bucket=bucket, PublicAccessBlockConfiguration=before
        )
    else:
        s3.delete_public_access_block(Bucket=bucket)  # type: ignore[attr-defined]


def disable_public_access(
    rds: object, db_instance_id: str, *, execute: bool
) -> CloudRemediationResult:
    """Set an RDS instance to not publicly accessible (closes exposed_database).

    Tighten-only and idempotent: an instance already private is a no-op. ``execute=False`` previews.
    On execute, verifies ``PubliclyAccessible`` is False before reporting success.
    """
    inst = rds.describe_db_instances(DBInstanceIdentifier=db_instance_id)["DBInstances"][0]  # type: ignore[attr-defined]
    before = {"PubliclyAccessible": bool(inst.get("PubliclyAccessible"))}
    if not before["PubliclyAccessible"]:
        return CloudRemediationResult(
            ACTION_RDS_DISABLE_PUBLIC_ACCESS,
            db_instance_id,
            "execute" if execute else "preview",
            "already_compliant",
            "Instance is already not publicly accessible — no change.",
            before,
            before,
        )
    if not execute:
        return CloudRemediationResult(
            ACTION_RDS_DISABLE_PUBLIC_ACCESS,
            db_instance_id,
            "preview",
            "would_change",
            "Would set PubliclyAccessible=False on the instance.",
            before,
        )
    rds.modify_db_instance(  # type: ignore[attr-defined]
        DBInstanceIdentifier=db_instance_id, PubliclyAccessible=False, ApplyImmediately=True
    )
    inst2 = rds.describe_db_instances(DBInstanceIdentifier=db_instance_id)["DBInstances"][0]  # type: ignore[attr-defined]
    after = {"PubliclyAccessible": bool(inst2.get("PubliclyAccessible"))}
    ok = not after["PubliclyAccessible"]
    return CloudRemediationResult(
        ACTION_RDS_DISABLE_PUBLIC_ACCESS,
        db_instance_id,
        "execute",
        "executed_verified" if ok else "execute_failed",
        "Public access disabled and verified." if ok else "Applied but verification failed.",
        before,
        after,
    )


__all__ = [
    "ACTION_RDS_DISABLE_PUBLIC_ACCESS",
    "ACTION_S3_BLOCK_PUBLIC_ACCESS",
    "CloudRemediationResult",
    "block_public_access",
    "disable_public_access",
    "restore_public_access",
]
