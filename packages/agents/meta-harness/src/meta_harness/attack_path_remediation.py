"""Remediation advice per attack-path archetype — the North Star's "with a fix", honestly.

This is **advisory** guidance: precise human-readable fix steps, plus an honest flag for whether the
remediation agent (A.1) can actually *execute* the fix. Today A.1 only does K8s pod-securityContext
patches, so exactly one archetype (``privileged_vulnerable``) is auto-fixable and only for its
privilege leg — every other archetype is manual. We say so rather than implying one-click fixes that
don't exist. Pure static mapping keyed by ``path_type``; no execution, no state, no safety surface.

Automated *cloud* remediation (S3 / IAM actions in A.1) is a separate, multi-cycle safety-critical
program — not bolted on here.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class FixAdvice:
    """How to fix an archetype, and whether A.1 can execute it today."""

    steps: str
    auto_fixable: bool
    #: The real ``RemediationActionType`` value when auto-fixable (verified against A.1's schema by a
    #: cross-package drift guard); "" otherwise.
    auto_via: str = ""


#: path_type → fix advice. Must cover every path_type the ranker can emit (a coverage test enforces
#: this, so no archetype ever renders without a fix).
REMEDIATION: dict[str, FixAdvice] = {
    "crown_jewel": FixAdvice(
        "Break any leg of the chain: close the workload's internet exposure, rebuild the image on a "
        "patched base to clear the CVEs, and scope the assumed role's data access to least privilege.",
        auto_fixable=False,
    ),
    "public_secret": FixAdvice(
        "Rotate the exposed credential immediately (assume it is compromised), delete it from the "
        "object, and enable S3 Block Public Access on the bucket.",
        auto_fixable=False,
    ),
    "internet_exposed_vulnerable": FixAdvice(
        "Rebuild the image on a patched base to clear the CVEs, and restrict the security group / "
        "load balancer so the workload is not reachable from 0.0.0.0/0.",
        auto_fixable=False,
    ),
    "privileged_vulnerable": FixAdvice(
        "Set securityContext.privileged=false on the pod to remove the node-escape path, then "
        "rebuild the image on a patched base to clear the CVEs. The privilege patch is auto-fixable; "
        "the image rebuild is manual.",
        auto_fixable=True,
        auto_via="remediation_k8s_patch_disable_privileged_container",
    ),
    "public_unencrypted": FixAdvice(
        "Enable S3 Block Public Access and turn on default server-side encryption (SSE-KMS or "
        "AES256) on the bucket.",
        auto_fixable=False,
    ),
    "external_trust": FixAdvice(
        "Remove or tighten the role's trust policy so the foreign account can no longer assume it; "
        "if cross-account access is required, scope it to specific principals and add a condition.",
        auto_fixable=False,
    ),
    "exposed_ai_sensitive_data": FixAdvice(
        "Enable network isolation on the AI endpoint and lock down the training-data bucket with "
        "Block Public Access so the model and its data are not internet-reachable.",
        auto_fixable=False,
    ),
    "resource_based_data": FixAdvice(
        "Remove the bucket-policy statement granting the external principal, or restrict it to the "
        "specific principals that genuinely need access.",
        auto_fixable=False,
    ),
    "fine_grained_data": FixAdvice(
        "Scope the principal's IAM policy to least privilege — replace the broad s3:Get*/wildcard "
        "resource grant with access to only the objects it needs.",
        auto_fixable=False,
    ),
}


def advice_for(path_type: str) -> FixAdvice | None:
    """The fix advice for an archetype, or ``None`` if unknown."""
    return REMEDIATION.get(path_type)


__all__ = ["REMEDIATION", "FixAdvice", "advice_for"]
