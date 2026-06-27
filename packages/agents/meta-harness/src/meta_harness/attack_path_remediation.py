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
    "leaked_credential": FixAdvice(
        "Deactivate and rotate the leaked AWS access key immediately (assume it is compromised), "
        "purge it from the repo's git history, and scope the owning principal to least privilege.",
        auto_fixable=False,
    ),
    "runtime_exploit_vulnerable": FixAdvice(
        "Treat as an active incident: isolate the workload, investigate the runtime detection for "
        "compromise, rebuild the image on a patched base to clear the CVEs, and rotate any "
        "credentials the workload held.",
        auto_fixable=False,
    ),
    "malicious_destination": FixAdvice(
        "Treat the resource as potentially compromised: isolate it (deny egress via security group), "
        "investigate for C2/exfil, rotate its credentials, and block the malicious IP at the firewall.",
        auto_fixable=False,
    ),
    "exposed_kms_key": FixAdvice(
        "Remove the wildcard (Principal: *) statement from the KMS key policy and scope key usage to "
        "the specific roles that need it; a public key policy defeats encryption-at-rest.",
        auto_fixable=False,
    ),
    "rbac_privilege_escalation": FixAdvice(
        "Remove the cluster-admin RoleBinding from the ServiceAccount and bind a least-privilege Role "
        "scoped to only the verbs and resources the workload needs; a bound cluster-admin SA is a "
        "full-cluster-control escalation path.",
        auto_fixable=False,
    ),
    "exposed_database": FixAdvice(
        "Set the database to not publicly accessible (PubliclyAccessible=false) and restrict its "
        "security group to the application subnets; a managed database should never be internet-facing.",
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
    "privilege_escalation": FixAdvice(
        "Remove the principal from the role's trust policy (or tighten the AssumeRole condition) so "
        "it can no longer escalate, and scope the assumed role's data access to least privilege.",
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
    "iac_misconfig_deployed": FixAdvice(
        "Fix the misconfiguration in the named infrastructure-as-code file and redeploy — the live "
        "resource inherits the fix from code (the root cause), preventing the drift from recurring.",
        auto_fixable=False,
    ),
}


def advice_for(path_type: str) -> FixAdvice | None:
    """The fix advice for an archetype, or ``None`` if unknown."""
    return REMEDIATION.get(path_type)


__all__ = ["REMEDIATION", "FixAdvice", "advice_for"]
