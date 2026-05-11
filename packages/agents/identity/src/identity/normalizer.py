"""Findings normalizer — Identity Agent Task 7.

Maps the raw inventory (`IdentityListing`, `EffectiveGrant[]`,
`AccessAnalyzerFinding[]`) into OCSF Identity Detection Findings
(`class_uid 2004`). Four detection types:

- **OVERPRIVILEGE** — principals with at least one admin-equivalent
  `Allow` grant (`*:*`, `iam:*`, service-wide wildcards).
- **DORMANT** — users / roles whose `last_used_at` is older than
  `dormant_threshold_days` (default 90).
- **EXTERNAL_ACCESS** — one finding per external principal surfaced by
  Access Analyzer (cross-account or public `*`).
- **MFA_GAP** — admin-capable IAM users not present in
  `users_with_mfa` (the MFA signal is supplied by the caller; in
  Phase 1 it comes from cloud-posture's existing MFA helpers).

The function is async to mirror D.1's
[`trivy_to_findings`](../../../packages/agents/vulnerability/src/vulnerability/normalizer.py)
shape, but all inputs are pre-computed so the body is sync — no
TaskGroup needed in v0.1. The `async` keyword is the seam where future
on-demand enrichment will plug in.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta

from shared.fabric.envelope import NexusEnvelope

from identity.schemas import (
    AffectedPrincipal,
    FindingType,
    IdentityFinding,
    Severity,
    build_finding,
    short_principal_id,
)
from identity.tools.aws_access_analyzer import AccessAnalyzerFinding
from identity.tools.aws_iam import IdentityListing
from identity.tools.permission_paths import EffectiveGrant, grants_by_principal

DEFAULT_DORMANT_THRESHOLD_DAYS = 90
_CONTEXT_INVALID = re.compile(r"[^a-z0-9_-]")


async def normalize_to_findings(
    listing: IdentityListing,
    grants: Sequence[EffectiveGrant],
    access_analyzer_findings: Sequence[AccessAnalyzerFinding],
    *,
    envelope: NexusEnvelope,
    detected_at: datetime | None = None,
    dormant_threshold_days: int = DEFAULT_DORMANT_THRESHOLD_DAYS,
    users_with_mfa: frozenset[str] = frozenset(),
) -> list[IdentityFinding]:
    """Produce OCSF Identity Findings from the inventory.

    Args:
        listing: Output of `aws_iam_list_identities`.
        grants: Output of `resolve_effective_grants` (post-Task 6).
        access_analyzer_findings: Output of `aws_access_analyzer_findings`.
        envelope: NexusEnvelope to wrap every emitted finding with.
        detected_at: Timestamp on every finding (defaults to now).
        dormant_threshold_days: Last-used staleness threshold.
        users_with_mfa: Names of users (not ARNs) known to have MFA.
            Anything missing here + holding admin grants → MFA_GAP.

    Returns:
        Findings in deterministic order: overprivilege, dormant,
        external-access, mfa-gap.
    """
    when = detected_at or datetime.now(UTC)

    findings: list[IdentityFinding] = []
    findings.extend(_overprivilege_findings(grants, listing, envelope, when))
    findings.extend(_dormant_findings(listing, envelope, when, dormant_threshold_days))
    findings.extend(_external_access_findings(access_analyzer_findings, envelope, when))
    findings.extend(_mfa_gap_findings(grants, listing, envelope, when, users_with_mfa))
    return findings


# ---------------------------- per-type helpers ---------------------------


def _overprivilege_findings(
    grants: Sequence[EffectiveGrant],
    listing: IdentityListing,
    envelope: NexusEnvelope,
    when: datetime,
) -> list[IdentityFinding]:
    findings: list[IdentityFinding] = []
    by_arn = _principals_by_arn(listing)
    counter = 1
    for arn, principal_grants in grants_by_principal(grants).items():
        admin_grants = [g for g in principal_grants if g.effect == "Allow" and g.is_admin]
        if not admin_grants or arn not in by_arn:
            continue
        ptype, name, last_used = by_arn[arn]
        attached = sorted({p for g in admin_grants for p in g.source_policy_arns})
        findings.append(
            build_finding(
                finding_id=f"IDENT-OVERPRIV-{short_principal_id(arn)}-{counter:03d}-admin_grants",
                finding_type=FindingType.OVERPRIVILEGE,
                severity=Severity.HIGH,
                title=f"Overprivileged principal: {name}",
                description=(
                    f"{ptype} '{name}' has {len(admin_grants)} admin-equivalent "
                    f"grant(s) (wildcard or service-wide actions)."
                ),
                affected_principals=[_principal(arn, name, ptype, last_used)],
                evidence={
                    "admin_action_count": len(admin_grants),
                    "attached_policies": attached,
                    "inline_admin": False,
                },
                detected_at=when,
                envelope=envelope,
            )
        )
        counter += 1
    return findings


def _dormant_findings(
    listing: IdentityListing,
    envelope: NexusEnvelope,
    when: datetime,
    threshold_days: int,
) -> list[IdentityFinding]:
    findings: list[IdentityFinding] = []
    threshold = when - timedelta(days=threshold_days)
    counter = 1

    for u in listing.users:
        if _is_recently_used(u.last_used_at, threshold):
            continue
        findings.append(
            _dormant_finding(
                arn=u.arn,
                name=u.name,
                ptype="User",
                last_used=u.last_used_at,
                envelope=envelope,
                when=when,
                threshold_days=threshold_days,
                context="user_inactive",
                counter=counter,
            )
        )
        counter += 1

    for r in listing.roles:
        if _is_recently_used(r.last_used_at, threshold):
            continue
        findings.append(
            _dormant_finding(
                arn=r.arn,
                name=r.name,
                ptype="Role",
                last_used=r.last_used_at,
                envelope=envelope,
                when=when,
                threshold_days=threshold_days,
                context="role_inactive",
                counter=counter,
            )
        )
        counter += 1

    return findings


def _dormant_finding(
    *,
    arn: str,
    name: str,
    ptype: str,
    last_used: datetime | None,
    envelope: NexusEnvelope,
    when: datetime,
    threshold_days: int,
    context: str,
    counter: int,
) -> IdentityFinding:
    days = (when - last_used).days if last_used else None
    return build_finding(
        finding_id=f"IDENT-DORMANT-{short_principal_id(arn)}-{counter:03d}-{context}",
        finding_type=FindingType.DORMANT,
        severity=Severity.MEDIUM,
        title=f"Dormant {ptype.lower()}: {name}",
        description=(
            f"{ptype} '{name}' has not been used for "
            f"{'>= ' + str(threshold_days) + ' days' if days is None else f'{days} days'}."
        ),
        affected_principals=[_principal(arn, name, ptype, last_used)],
        evidence={
            "days_dormant": days,
            "last_used_at": last_used.isoformat() if last_used else None,
            "threshold_days": threshold_days,
        },
        detected_at=when,
        envelope=envelope,
    )


def _external_access_findings(
    aa_findings: Sequence[AccessAnalyzerFinding],
    envelope: NexusEnvelope,
    when: datetime,
) -> list[IdentityFinding]:
    findings: list[IdentityFinding] = []
    counter = 1
    for aaf in aa_findings:
        for external_arn in aaf.external_principals:
            is_public = external_arn == "*"
            short = "PUBLIC" if is_public else short_principal_id(external_arn)
            context = _safe_context(aaf.id)
            principal_arn = "arn:aws:iam:::*" if is_public else external_arn
            account_id = "*" if is_public else _extract_account_id(external_arn)
            principal = AffectedPrincipal(
                principal_type="Public" if is_public else "ExternalAccount",
                principal_name=external_arn or "*",
                arn=principal_arn,
                account_id=account_id or "unknown",
            )
            findings.append(
                build_finding(
                    finding_id=f"IDENT-EXTERNAL-{short}-{counter:03d}-{context}",
                    finding_type=FindingType.EXTERNAL_ACCESS,
                    severity=Severity.CRITICAL if is_public else Severity.HIGH,
                    title=(
                        f"Public access to {aaf.resource_type}: {aaf.resource_arn}"
                        if is_public
                        else f"Cross-account access to {aaf.resource_type}: {aaf.resource_arn}"
                    ),
                    description=(
                        f"Access Analyzer surfaced "
                        f"{'public' if is_public else 'cross-account'} access "
                        f"on {aaf.resource_arn} for principal {external_arn}."
                    ),
                    affected_principals=[principal],
                    evidence={
                        "trusts": [external_arn],
                        "resource_arn": aaf.resource_arn,
                        "resource_type": aaf.resource_type,
                        "actions": list(aaf.actions),
                        "access_analyzer_finding_id": aaf.id,
                    },
                    detected_at=when,
                    envelope=envelope,
                )
            )
            counter += 1
    return findings


def _mfa_gap_findings(
    grants: Sequence[EffectiveGrant],
    listing: IdentityListing,
    envelope: NexusEnvelope,
    when: datetime,
    users_with_mfa: frozenset[str],
) -> list[IdentityFinding]:
    findings: list[IdentityFinding] = []
    users_by_arn = {u.arn: u for u in listing.users}
    counter = 1
    for arn, principal_grants in grants_by_principal(grants).items():
        user = users_by_arn.get(arn)
        if user is None:
            continue
        admin_grants = [g for g in principal_grants if g.effect == "Allow" and g.is_admin]
        if not admin_grants:
            continue
        if user.name in users_with_mfa:
            continue
        actions_admin = sorted({g.action for g in admin_grants})
        findings.append(
            build_finding(
                finding_id=f"IDENT-MFA-{short_principal_id(arn)}-{counter:03d}-admin_no_mfa",
                finding_type=FindingType.MFA_GAP,
                severity=Severity.CRITICAL,
                title=f"Admin user without MFA: {user.name}",
                description=(
                    f"User '{user.name}' has admin-equivalent grants but is not "
                    "in the MFA-enabled set."
                ),
                affected_principals=[_principal(arn, user.name, "User", user.last_used_at)],
                evidence={
                    "actions_admin": actions_admin,
                    "mfa_enabled": False,
                },
                detected_at=when,
                envelope=envelope,
            )
        )
        counter += 1
    return findings


# ---------------------------- low-level helpers --------------------------


def _principal(arn: str, name: str, ptype: str, last_used: datetime | None) -> AffectedPrincipal:
    return AffectedPrincipal(
        principal_type=ptype,
        principal_name=name,
        arn=arn,
        account_id=_extract_account_id(arn) or "unknown",
        last_used_at=last_used,
    )


def _principals_by_arn(
    listing: IdentityListing,
) -> dict[str, tuple[str, str, datetime | None]]:
    """Map principal ARN → (type, name, last_used_at)."""
    out: dict[str, tuple[str, str, datetime | None]] = {}
    for u in listing.users:
        out[u.arn] = ("User", u.name, u.last_used_at)
    for r in listing.roles:
        out[r.arn] = ("Role", r.name, r.last_used_at)
    for g in listing.groups:
        out[g.arn] = ("Group", g.name, None)
    return out


def _is_recently_used(last_used: datetime | None, threshold: datetime) -> bool:
    """A principal is recently used when last_used is on or after the threshold."""
    return last_used is not None and last_used >= threshold


def _extract_account_id(arn: str) -> str:
    parts = arn.split(":")
    if len(parts) >= 5 and parts[4]:
        return parts[4]
    return ""


def _safe_context(value: str) -> str:
    """Slug a free-form value into the `[a-z0-9_-]+` shape FINDING_ID_RE requires."""
    cleaned = _CONTEXT_INVALID.sub("-", value.lower())
    cleaned = cleaned.strip("-_") or "x"
    return cleaned


__all__ = [
    "DEFAULT_DORMANT_THRESHOLD_DAYS",
    "normalize_to_findings",
]
